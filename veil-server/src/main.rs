mod community;
mod delivery;
mod store;
mod tlsframe;

use anyhow::Result;
use axum::{
	Router,
	body::Bytes,
	extract::{
		ConnectInfo, Path, State, WebSocketUpgrade,
		ws::{Message, WebSocket},
	},
	http::StatusCode,
	response::{IntoResponse, Response},
	routing,
};
use futures::{
	SinkExt, StreamExt,
	stream::{SplitSink, SplitStream},
};
use std::{
	collections::HashMap,
	io::{self, Write},
	net::{IpAddr, SocketAddr},
	sync::{Arc, LazyLock},
};
use tokio::{
	net::TcpListener,
	sync::{Mutex, RwLock},
};
use veil_protocol::{
	clock::{self, Clock, Sync},
	identity::{Device, DeviceAddress, DeviceId, UserId},
	version::VersionRange,
	*,
};
use vodozemac::olm::Account;

/// One-time keys a single identity will hand out per window. Past it we serve
/// the fallback key instead of consuming a real OTK, so someone hammering the
/// prekey endpoint degrades to fallback-key handshakes rather than stripping
/// the pool bare ahead of legitimate peers.
const OTK_BUDGET_PER_WINDOW: u32 = 5;
/// Prekey requests a single IP may make per window, whatever it asks about.
const REQUESTS_PER_IP_PER_WINDOW: u32 = 30;
const RATE_WINDOW_MS: u64 = 60_000;
/// Tunnels one user may open per window (§3.2).
const TUNNELS_PER_USER_PER_WINDOW: u32 = 20;
/// Largest blob a host will store (§10.2). Bounded because the host cannot see
/// what it is holding, so size is the only thing it can enforce.
const MAX_BLOB: usize = 16 << 20;
/// Total blob storage a host will give up before refusing more.
///
/// The only quota available to a Sealed host: it cannot tell a video from a
/// novel, and §10.2 notes that opaque sizes are sufficient. A real deployment
/// would make this per-community and configurable; a hard cap is the honest
/// starting point, because the alternative is unbounded disk use by anyone who
/// can connect.
const MAX_BLOB_STORAGE: i64 = 4 << 30;
/// Deposits one server may make per window (§3.4). Generous — a busy server
/// legitimately carries mail for many users — but bounded.
const DEPOSITS_PER_SERVER_PER_WINDOW: u32 = 600;
/// Largest frame the relay will forward. Bounds memory and stops a client
/// using the tunnel as an amplifier.
const MAX_TUNNEL_FRAME: usize = 1 << 20;

type SharedStore = Arc<Mutex<store::Store>>;

#[derive(Clone)]
struct ServerState {
	/// Key directory and mailboxes (§12.1). Was two in-memory maps, which lost
	/// every key on restart and dropped mail for anyone offline.
	store: SharedStore,
	server_account: Arc<Mutex<Account>>,
	/// Network time, not the host's (§13.4). A container inherits whatever its
	/// host's clock says, and a drifting one makes every peer unreachable.
	clock: Arc<RwLock<Clock>>,
	replay_guard: Arc<Mutex<ReplayGuard>>,
	ip_limiter: Arc<Mutex<RateLimiter<IpAddr>>>,
	otk_limiter: Arc<Mutex<RateLimiter<DeviceAddress>>>,
	tunnel_limiter: Arc<Mutex<RateLimiter<DeviceAddress>>>,
	/// Deposits one *server* may make per window (§3.4).
	///
	/// Keyed on the peer's identity key rather than its IP: an operator running
	/// several addresses is one sender, and this is the limit that makes
	/// server-to-server deposits spam-resistant where client-to-mailbox
	/// deposits would not be.
	deposit_limiter: Arc<Mutex<RateLimiter<[u8; 32]>>>,
	/// Hosts that have proved they speak Veil, so the proof is not repeated on
	/// every directory lookup (§3.4).
	verified_hosts: Arc<RwLock<std::collections::HashSet<String>>>,
	/// SHA-256 of our own TLS certificate, or zeros when serving plaintext.
	/// Signed into every challenge so a client reaching us through a relay can
	/// tell whether it is really talking to us (§3.2).
	tls_binding: [u8; 32],
}

/// Frames queued for one connection.
///
/// Routing hands a frame over and returns immediately; a per-connection task
/// does the writing. Holding the routing map's lock across a socket write —
/// which is what a map of sinks forces — means one slow recipient stalls *every*
/// message on the server (§13.3).
type Outbox = tokio::sync::mpsc::Sender<Vec<u8>>;

/// How many frames may be queued for a connection before it is considered
/// unable to keep up.
const OUTBOX_DEPTH: usize = 256;

/// Routing map, keyed by device address rather than raw key material (§5.3).
/// A user with three devices holds three entries.
static CLIENTS: LazyLock<RwLock<HashMap<DeviceAddress, Outbox>>> =
	LazyLock::new(|| RwLock::new(HashMap::new()));

/// Queues a frame for a device, if it is connected.
///
/// Never awaits while holding the map lock: the lookup clones a channel handle,
/// releases, and only then queues.
async fn route_to(recipient: &DeviceAddress, frame: Vec<u8>) -> Result<(), RouteError> {
	let outbox = {
		let clients = CLIENTS.read().await;
		clients.get(recipient).cloned()
	};

	let Some(outbox) = outbox else {
		return Err(RouteError::NotConnected);
	};

	match outbox.try_send(frame) {
		Ok(()) => Ok(()),
		Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(RouteError::NotConnected),
		Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
			// The peer has stopped reading. Dropping the connection makes that
			// visible and forces a reconnect, rather than silently discarding
			// messages or blocking everyone else behind it.
			CLIENTS.write().await.remove(recipient);
			Err(RouteError::TooSlow)
		}
	}
}

#[derive(Debug)]
enum RouteError {
	NotConnected,
	TooSlow,
}

impl std::fmt::Display for RouteError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::NotConnected => f.write_str("not connected"),
			Self::TooSlow => f.write_str("not keeping up; connection dropped"),
		}
	}
}

/// SHA-256 of the first certificate in a PEM chain.
///
/// The leaf, which is the one a peer actually negotiates with. Hashing the whole
/// DER rather than picking the public key out of it avoids an X.509 parser for
/// no loss: the binding only has to be something the server can state and the
/// client can recompute from what it was shown.
fn leaf_certificate_hash(path: &str) -> Result<[u8; 32]> {
	use sha2::{Digest, Sha256};

	let pem = std::fs::read_to_string(path)?;
	let der = pem
		.split("-----BEGIN CERTIFICATE-----")
		.nth(1)
		.and_then(|rest| rest.split("-----END CERTIFICATE-----").next())
		.ok_or_else(|| anyhow::anyhow!("{path} holds no certificate"))?;

	let der: String = der.chars().filter(|c| !c.is_whitespace()).collect();
	let der = data_encoding::BASE64.decode(der.as_bytes())?;

	Ok(Sha256::digest(&der).into())
}

fn prompt(question: &str) -> Result<String> {
	print!("{question}");
	io::stdout().flush()?;
	let mut input = String::new();
	io::stdin().read_line(&mut input)?;
	Ok(input.trim().to_owned())
}

#[tokio::main]
async fn main() -> Result<()> {
	let address = match prompt("Enter server address (empty for 0.0.0.0:9876): ")?.as_str() {
		"" => String::from("0.0.0.0:9876"),
		entered => entered.to_owned(),
	};

	let certificate_path = prompt("Enter TLS certificate chain path (empty for plaintext): ")?;
	// Hashed before anything is served, because it goes into every challenge:
	// a client behind a relay compares this against the certificate it actually
	// negotiated, and a relay terminating that session with its own certificate
	// cannot make our identity key vouch for it (§3.2).
	let tls_binding = if certificate_path.is_empty() {
		[0u8; 32]
	} else {
		leaf_certificate_hash(&certificate_path)?
	};

	// Installed unconditionally: the relay makes TLS client connections when
	// probing a destination, whether or not this server serves TLS itself.
	let _ = rustls::crypto::ring::default_provider().install_default();

	let tls = if certificate_path.is_empty() {
		eprintln!(
			"WARNING: serving without TLS. Message bodies stay end-to-end encrypted, but\n\
			 identity keys, prekey bundles and routing metadata are readable on the wire.\n\
			 Supply a certificate, or terminate TLS in front of this process, before\n\
			 exposing it to an untrusted network."
		);
		None
	} else {
		let key_path = prompt("Enter TLS private key path: ")?;
		Some(
			axum_server::tls_rustls::RustlsConfig::from_pem_file(certificate_path, key_path)
				.await?,
		)
	};

	// Ask the network what time it is before doing anything that stamps or
	// checks a timestamp.
	let clock = tokio::task::spawn_blocking(|| {
		clock::synchronise(&clock::DEFAULT_SOURCES, std::time::Duration::from_secs(3))
	})
	.await?;

	match clock {
		Sync::Network { offset_ms, sources } => {
			println!("Clock synchronised: {offset_ms:+}ms from {sources} source(s)")
		}
		Sync::SystemClockOnly => eprintln!(
			"WARNING: no time source answered. Falling back to the system clock.\n\
			 If it has drifted more than a minute, peers will be unable to talk to\n\
			 this server and the failures will look like rejected signatures."
		),
	}
	let clock = Clock::from_sync(clock);

	let db_path = match prompt("Enter database path (empty for veil-server.db): ")?.as_str() {
		"" => String::from("veil-server.db"),
		entered => entered.to_owned(),
	};

	// Checked on every start, not only after a restore: a store that has
	// silently corrupted should be found now rather than when someone needs it.
	{
		let store = store::Store::open(&db_path)?;
		store.verify_integrity()?;
		let summary = store.summary()?;
		println!(
			"Store at {db_path} — {}",
			summary
				.iter()
				.map(|(t, n)| format!("{n} {t}"))
				.collect::<Vec<_>>()
				.join(", ")
		);
	}

	let store = store::Store::open(&db_path)?;
	// Loaded, not generated. Clients pin this key and refuse a changed one
	// (invariant 6), so a fresh account at every start locked out everyone who
	// had ever connected — and another server recognises us by it too (§3.4).
	let server_account = store.load_or_create_account()?;

	let state = ServerState {
		store: Arc::new(Mutex::new(store)),
		clock: Arc::new(RwLock::new(clock)),
		server_account: Arc::new(Mutex::new(server_account)),
		replay_guard: Arc::new(Mutex::new(ReplayGuard::default())),
		ip_limiter: Arc::new(Mutex::new(RateLimiter::new(
			REQUESTS_PER_IP_PER_WINDOW,
			RATE_WINDOW_MS,
		))),
		otk_limiter: Arc::new(Mutex::new(RateLimiter::new(
			OTK_BUDGET_PER_WINDOW,
			RATE_WINDOW_MS,
		))),
		tunnel_limiter: Arc::new(Mutex::new(RateLimiter::new(
			TUNNELS_PER_USER_PER_WINDOW,
			RATE_WINDOW_MS,
		))),
		deposit_limiter: Arc::new(Mutex::new(RateLimiter::new(
			DEPOSITS_PER_SERVER_PER_WINDOW,
			RATE_WINDOW_MS,
		))),
		verified_hosts: Arc::new(RwLock::new(std::collections::HashSet::new())),
		tls_binding,
	};

	delivery::spawn_retry_loop(state.clone());

	println!(
		"My public key: {}",
		display_key(state.server_account.lock().await.ed25519_key().as_bytes())
	);

	// Drift accumulates, so re-check periodically rather than trusting a
	// startup reading for the life of the process.
	{
		let clock = state.clock.clone();
		tokio::spawn(async move {
			loop {
				tokio::time::sleep(std::time::Duration::from_secs(30 * 60)).await;
				let sync = tokio::task::spawn_blocking(|| {
					clock::synchronise(&clock::DEFAULT_SOURCES, std::time::Duration::from_secs(3))
				})
				.await;

				if let Ok(Sync::Network { offset_ms, .. }) = sync {
					let previous = clock.read().await.offset_ms();
					if (offset_ms - previous).abs() > 1_000 {
						eprintln!("clock: offset moved {previous:+}ms -> {offset_ms:+}ms");
					}
					*clock.write().await = Clock::with_offset(offset_ms);
				}
			}
		});
	}

	let router = Router::new()
		.route("/", routing::any(socket))
		.route("/clients", routing::get(list_clients))
		.route(
			"/devices/{user}/{device}/otk",
			routing::get(get_prekey_bundle),
		)
		.route("/users/{user}/devices", routing::get(get_device_list))
		.route("/aliases/{alias}", routing::get(resolve_alias))
		.route("/relay", routing::any(relay))
		.route("/s2s", routing::any(deposit_socket))
		.route(
			"/remote/{host}/users/{user}/devices",
			routing::get(remote_device_list),
		)
		.route(
			"/remote/{host}/devices/{user}/{device}/otk",
			routing::get(remote_prekey_bundle),
		)
		.with_state(state);

	let listener = TcpListener::bind(address).await?;
	println!("Listening on {}", listener.local_addr()?);

	let service = router.into_make_service_with_connect_info::<SocketAddr>();
	match tls {
		Some(config) => {
			axum_server::from_tcp_rustls(listener.into_std()?, config)
				.serve(service)
				.await?
		}
		None => axum::serve(listener, service).await?,
	}

	Ok(())
}

async fn socket(socket: WebSocketUpgrade, State(state): State<ServerState>) -> Response {
	socket.on_upgrade(|socket| handle_socket(socket, state))
}

/// Resolves a human-typed name to the identity behind it (§11.6).
///
/// **Trust on first use, and nothing more.** Anything a server says, that server
/// can lie about — so a client pins what this returns and warns loudly if the
/// same alias later resolves elsewhere. The safe path is a link or QR carrying
/// the whole `UserId`, which consults no directory and so has nothing to
/// substitute; this exists for somebody typing an address by hand.
async fn resolve_alias(State(state): State<ServerState>, Path(alias): Path<String>) -> Response {
	match state
		.store
		.lock()
		.await
		.resolve_alias(&alias.trim().to_lowercase())
	{
		Ok(Some(user)) => user.to_string().into_response(),
		Ok(None) => (StatusCode::NOT_FOUND, "no such alias").into_response(),
		Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
	}
}

/// Looks a stranger up on their own home server, so the client does not have to
/// (§3.4). The client still verifies what comes back against cross-signing, so
/// neither server is trusted for the contents.
async fn remote_device_list(
	State(state): State<ServerState>,
	Path((host, user)): Path<(String, String)>,
) -> Response {
	proxy(&state, &host, &format!("/users/{user}/devices")).await
}

async fn remote_prekey_bundle(
	State(state): State<ServerState>,
	Path((host, user, device)): Path<(String, String, String)>,
) -> Response {
	proxy(&state, &host, &format!("/devices/{user}/{device}/otk")).await
}

async fn proxy(state: &ServerState, host: &str, path: &str) -> Response {
	match delivery::fetch_remote(state, host, path).await {
		Ok((status, body)) => (
			StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
			body,
		)
			.into_response(),
		Err(e) => {
			eprintln!("Remote lookup of {host}{path} failed: {e:#}");
			(StatusCode::BAD_GATEWAY, format!("{e:#}")).into_response()
		}
	}
}

/// Where another server hands us mail for one of our users (§3.4).
async fn deposit_socket(socket: WebSocketUpgrade, State(state): State<ServerState>) -> Response {
	socket.on_upgrade(|socket| delivery::handle_deposit_socket(socket, state))
}

/// Makes the peer prove it holds the private key for the identity it claims,
/// before anything is routed to it.
///
/// The identity has to be established by signature rather than assertion: the
/// key doubles as the routing address, so accepting a bare claim would let
/// anyone connect as another user and receive that user's inbound messages.
async fn authenticate(
	sender: &mut SplitSink<WebSocket, Message>,
	receiver: &mut SplitStream<WebSocket>,
	state: &ServerState,
) -> Result<(DeviceAddress, [u8; 32], u16)> {
	let mut challenge = [0u8; 32];
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);

	let ours = VersionRange::supported();

	let framed = {
		let account = state.server_account.lock().await;
		Envelope::seal(
			&ProtocolMessage::Challenge(Challenge {
				challenge,
				versions: ours,
				tls_binding: state.tls_binding,
			}),
			&account,
		)?
	};
	sender
		.send(Message::Binary(Bytes::copy_from_slice(&framed)))
		.await?;

	let Some(Ok(Message::Binary(bytes))) = receiver.next().await else {
		anyhow::bail!("expected a binary authentication frame");
	};

	let opened = open_envelope(&bytes)?;
	let now = state.clock.read().await.now_ms();
	state
		.replay_guard
		.lock()
		.await
		.check_at(now, opened.timestamp_ms, opened.nonce)?;

	let claim = match opened.message {
		ProtocolMessage::Authenticate(claim) => claim,
		other => anyhow::bail!("expected an Authenticate message, got {other:?}"),
	};

	if claim.challenge != challenge {
		anyhow::bail!("client echoed the wrong challenge");
	}

	// Transcript binding (§3.6). Both ranges were signed, so neither could be
	// forged — but an attacker could still have swapped the challenge envelope
	// for an older, genuinely-signed one advertising a weaker range. Requiring
	// the client to echo what it saw catches that, because it will not match
	// what this connection actually advertised.
	if claim.server_versions_seen != ours {
		anyhow::bail!(
			"client saw our version range as {} but we advertised {ours} — the handshake \
			 was tampered with",
			claim.server_versions_seen
		);
	}

	let agreed = ours.agree(&claim.versions)?;

	// Walks the whole §5.4 chain:
	//
	//   device key <-signed by- SSK <-signed by- MSK ->hashes to-> user id
	//
	// and the device key checked is `opened.sender` — the key that actually
	// signed this envelope — so a peer cannot present someone else's valid
	// enrolment. Drop any link and a peer can be routed under an identity it
	// does not own.
	claim
		.keys
		.verify_device(&claim.user, &claim.device, &opened.sender, &claim.binding)?;

	// Everything needed for a device-list entry has just been verified, so
	// record it here rather than trusting a later self-report.
	let now = state.clock.read().await.now_ms();
	state.store.lock().await.upsert_device(
		&claim.user,
		&claim.keys,
		&Device {
			device_id: claim.device,
			ed25519: opened.sender,
			curve25519: [0; 32], // filled in by the key upload
			ssk_signature: claim.binding,
			display_name: String::new(),
			created_at: now,
			last_seen: now,
		},
	)?;

	Ok((
		DeviceAddress::new(claim.user, claim.device),
		opened.sender,
		agreed,
	))
}

async fn handle_socket(socket: WebSocket, state: ServerState) {
	let (mut sender, mut receiver) = socket.split();

	let (address, signing_key, version) =
		match authenticate(&mut sender, &mut receiver, &state).await {
			Ok(identity) => identity,
			Err(e) => {
				eprintln!("Handshake failed, dropping connection: {e:#}");
				return;
			}
		};

	println!("{address} connected, speaking protocol v{version}");

	// One task owns the socket's write half. Everything else queues frames, so
	// no routing path ever waits on a socket.
	let (outbox, mut outbound) = tokio::sync::mpsc::channel::<Vec<u8>>(OUTBOX_DEPTH);
	let writer = tokio::spawn(async move {
		while let Some(frame) = outbound.recv().await {
			if sender
				.send(Message::Binary(Bytes::copy_from_slice(&frame)))
				.await
				.is_err()
			{
				break;
			}
		}
	});
	CLIENTS.write().await.insert(address, outbox);

	// Anything that arrived while this device was away. Delivered before the
	// read loop starts, so it lands in order relative to live traffic.
	if let Err(e) = flush_mailbox(&state, &address).await {
		eprintln!("Could not flush mail for {address}: {e:#}");
	}

	while let Some(Ok(Message::Binary(bytes))) = receiver.next().await {
		let opened = match open_envelope(&bytes) {
			Ok(opened) => opened,
			Err(e) => {
				eprintln!("Discarding an unverifiable envelope: {e:#}");
				continue;
			}
		};

		// A valid signature proves who wrote the envelope, not who sent it.
		// Pinning it to the authenticated connection stops a client forwarding
		// envelopes it captured from someone else.
		if opened.sender != signing_key {
			eprintln!(
				"Discarding an envelope signed by {} on {address}'s connection",
				display_key(&opened.sender)
			);
			continue;
		}

		let now = state.clock.read().await.now_ms();
		if let Err(e) =
			state
				.replay_guard
				.lock()
				.await
				.check_at(now, opened.timestamp_ms, opened.nonce)
		{
			eprintln!("Discarding a replayed envelope: {e:#}");
			continue;
		}

		match opened.message {
			ProtocolMessage::EncryptedMessage(msg) => {
				eprintln!("Received an encrypted message");

				// The sender field is not taken on trust: it must match the
				// device that authenticated on this connection, or a client
				// could forge messages as any device it likes.
				if msg.sender != address {
					eprintln!("Discarding a message claiming to be from {}", msg.sender);
					continue;
				}

				// Not ours to deliver: hand it to the server that holds the
				// recipient's mailbox (§3.4 step 2). The frame forwarded is the
				// client's own envelope, so the receiving server verifies the
				// sender's signature rather than ours.
				//
				// The named host is checked, not obeyed — `deliver` completes a
				// Veil handshake before sending anything, so a client naming an
				// arbitrary address cannot use its home server as a proxy
				// (invariant 15).
				if !msg.recipient_host.is_empty() {
					let local = state
						.store
						.lock()
						.await
						.is_local_user(&msg.recipient.user)
						.unwrap_or(false);

					if !local {
						eprintln!(
							"Forwarding mail for {} to {}",
							msg.recipient, msg.recipient_host
						);
						delivery::send_onward(&state, &msg.recipient_host, &bytes).await;
						continue;
					}
				}

				match route_to(&msg.recipient, bytes.to_vec()).await {
					Ok(()) => eprintln!("Message routed from {address} to {}", msg.recipient),
					Err(e) => {
						// Undelivered is not lost. The recipient gets it when
						// they next connect (§12.2) — before this, anything for
						// an offline device was dropped on the floor.
						let queued = state.store.lock().await.enqueue(
							&msg.recipient,
							&bytes,
							opened.timestamp_ms,
						);
						match queued {
							Ok(()) => eprintln!(
								"{} is {e}; mail queued for their next connection",
								msg.recipient
							),
							Err(err) => {
								eprintln!("Could not queue mail for {}: {err:#}", msg.recipient)
							}
						}
					}
				}
			}
			ProtocolMessage::UploadKeys(upload) => {
				let mut store = state.store.lock().await;

				let accepted =
					match store_upload(&mut store, &address, &upload, opened.timestamp_ms) {
						Ok(accepted) => accepted,
						Err(e) => {
							eprintln!("Key upload from {address} failed: {e:#}");
							continue;
						}
					};

				if !accepted {
					eprintln!("Discarding a key upload that does not advance the clock.");
					continue;
				}

				eprintln!("Key upload from {address} handled properly.");
			}

			ProtocolMessage::Acknowledge(ids) => {
				let ids: Vec<i64> = ids.iter().map(|id| *id as i64).collect();
				match state.store.lock().await.acknowledge_for(&address, &ids) {
					Ok(dropped) => {
						eprintln!("{address} acknowledged {dropped} queued message(s)")
					}
					Err(e) => eprintln!("Could not clear mail for {address}: {e:#}"),
				}
			}
			ProtocolMessage::Mail(_) => {
				eprintln!("Received mail from a client. Should be impossible; ignoring.")
			}
			ProtocolMessage::Challenge(_) | ProtocolMessage::Authenticate(_) => {
				eprintln!("Received a handshake message outside the handshake. Ignoring.")
			}
			// ---- communities (§7, §8) ------------------------------------
			ProtocolMessage::CreateCommunity(root) => {
				let response = community::create(&state, &address, *root).await;
				reply(&state, &address, response.into_message()).await;
			}
			ProtocolMessage::JoinCommunity(id) => {
				let response = community::join(&state, &address, id).await;
				reply(&state, &address, response.into_message()).await;

				// Sent unprompted after a join: a client that has just been
				// admitted needs the root and the policy chain before it can
				// verify anything the host says afterwards.
				if let Ok(view) = community::view(&state, id).await {
					reply(
						&state,
						&address,
						ProtocolMessage::CommunityState(Box::new(view)),
					)
					.await;
				}
			}
			ProtocolMessage::Post(post) => {
				let response = community::post(&state, &address, post).await;
				reply(&state, &address, response.into_message()).await;
			}
			ProtocolMessage::ClaimAlias(alias) => {
				let alias = alias.trim().to_lowercase();
				let valid = !alias.is_empty()
					&& alias.len() <= 64
					&& alias
						.chars()
						.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');

				let detail = if !valid {
					"an alias is up to 64 characters of letters, digits, dot, dash or underscore"
						.to_owned()
				} else {
					let now = state.clock.read().await.now_ms();
					match state
						.store
						.lock()
						.await
						.claim_alias(&alias, &address.user, now)
					{
						Ok(true) => format!("{alias} is yours"),
						Ok(false) => format!("{alias} is already taken"),
						Err(e) => format!("could not claim it: {e}"),
					}
				};

				eprintln!("Alias claim from {address}: {detail}");
			}
			ProtocolMessage::Ephemeral(event) => {
				community::ephemeral(&state, &address, event).await;
			}
			ProtocolMessage::Report(report) => {
				let response = community::report(&state, &address, *report).await;
				reply(&state, &address, response.into_message()).await;
			}
			ProtocolMessage::FetchReports(id) => {
				let message = match community::reports(&state, &address, id).await {
					Ok(entries) => ProtocolMessage::ReportQueue {
						community: id,
						entries,
					},
					Err(e) => ProtocolMessage::CommunityResult {
						community: id,
						ok: false,
						detail: format!("{e:#}"),
					},
				};
				reply(&state, &address, message).await;
			}
			ProtocolMessage::UploadBlob(bytes) => {
				if bytes.len() > MAX_BLOB {
					eprintln!("Refusing an oversized blob from {address}");
					continue;
				}

				// The id is the hash of what arrived, computed here rather than
				// taken from the client, so a client cannot claim an id that
				// does not match its bytes — and cannot overwrite somebody
				// else's blob by claiming theirs.
				let id = veil_protocol::attachment::blob_id(&bytes);
				let size = bytes.len() as u64;
				let now = state.clock.read().await.now_ms();

				let held = state
					.store
					.lock()
					.await
					.blob_bytes_held()
					.unwrap_or(MAX_BLOB_STORAGE);
				if held.saturating_add(bytes.len() as i64) > MAX_BLOB_STORAGE {
					eprintln!("Refusing a blob from {address}: storage is full");
					continue;
				}

				match state.store.lock().await.put_blob(&id, &bytes, now) {
					Ok(()) => {
						reply(&state, &address, ProtocolMessage::BlobStored { id, size }).await
					}
					Err(e) => eprintln!("Could not store a blob for {address}: {e:#}"),
				}
			}
			ProtocolMessage::FetchBlob(id) => {
				let bytes = state.store.lock().await.blob(&id).ok().flatten();
				reply(
					&state,
					&address,
					ProtocolMessage::BlobContent {
						id,
						bytes: bytes.unwrap_or_default(),
					},
				)
				.await;
			}
			ProtocolMessage::DeleteMessage {
				community: id,
				channel,
				sequence,
			} => {
				let response = community::delete(&state, &address, id, &channel, sequence).await;
				reply(&state, &address, response.into_message()).await;
			}
			ProtocolMessage::FetchCommunity(id) => match community::view(&state, id).await {
				Ok(view) => {
					reply(
						&state,
						&address,
						ProtocolMessage::CommunityState(Box::new(view)),
					)
					.await
				}
				Err(e) => {
					reply(
						&state,
						&address,
						ProtocolMessage::CommunityResult {
							community: id,
							ok: false,
							detail: format!("{e:#}"),
						},
					)
					.await
				}
			},
			ProtocolMessage::Backfill {
				community: id,
				channel,
				after,
			} => match community::backfill(&state, &address, id, &channel, after).await {
				Ok(messages) => {
					for delivery in messages {
						reply(
							&state,
							&address,
							ProtocolMessage::Delivery(Box::new(delivery)),
						)
						.await;
					}
				}
				Err(e) => {
					eprintln!("Backfill for {address} refused: {e:#}");
					reply(
						&state,
						&address,
						ProtocolMessage::CommunityResult {
							community: id,
							ok: false,
							detail: format!("{e:#}"),
						},
					)
					.await;
				}
			},
			ProtocolMessage::SubmitPolicy(policy) => {
				let id = policy.community;
				let response = community::submit_policy(&state, *policy).await;
				let accepted = response.ok;
				reply(&state, &address, response.into_message()).await;

				// Every member's chain is now stale, not just the submitter's.
				// A client whose chain lags derives readership from it anyway
				// (§8.5), so it would keep encrypting to a device a controller
				// has just removed — which makes removal cosmetic for everyone
				// except the person who did it.
				if accepted {
					community::broadcast_state(&state, id).await;
				}
			}
			ProtocolMessage::ChannelKey(key) => {
				// Routed, not read. The payload is Olm-encrypted to the
				// recipient device, so this host carries a channel's keys
				// without ever being able to use them — which is what makes
				// Sealed mean anything on a host somebody else runs.
				if key.sender != address {
					eprintln!(
						"Discarding a channel key claiming to be from {}",
						key.sender
					);
					continue;
				}

				let recipient = key.recipient;
				if let Err(e) = route_to(&recipient, bytes.to_vec()).await {
					// Queued like any other undelivered frame: a device that
					// was offline when a key was issued must still get it, or
					// it can never read the channel.
					let queued =
						state
							.store
							.lock()
							.await
							.enqueue(&recipient, &bytes, opened.timestamp_ms);
					match queued {
						Ok(()) => eprintln!("{recipient} is {e}; channel key queued"),
						Err(err) => eprintln!("Could not queue a channel key: {err:#}"),
					}
				}
			}
			// Host -> client only; a client sending one is confused or probing.
			ProtocolMessage::CommunityState(_)
			| ProtocolMessage::Delivery(_)
			| ProtocolMessage::BlobStored { .. }
			| ProtocolMessage::ReportQueue { .. }
			| ProtocolMessage::BlobContent { .. }
			| ProtocolMessage::CommunityResult { .. } => {
				eprintln!("Received a host-to-client community frame from {address}. Ignoring.")
			}

			// Server-to-server frames never arrive on a client connection: they
			// have their own endpoint with its own handshake (§3.4). A client
			// reaching this is trying to deposit into a mailbox directly, which
			// is the unrate-limitable spam vector §3.4 exists to close.
			ProtocolMessage::ServerAuthenticate(_)
			| ProtocolMessage::Deposit(_)
			| ProtocolMessage::DepositResult(_) => {
				eprintln!("Discarding a server-to-server frame from client {address}")
			}
			ProtocolMessage::RemainingOneTimeKeys(notification) => eprintln!(
				"Received a remaining OTKs notification. Should be impossible. Client is either broken or malicious.\nNotification: {notification:?}"
			),
		}
	}

	CLIENTS.write().await.remove(&address);
	writer.abort();
	println!("{address} disconnected");
}

/// Seals a message from this host and sends it to one device.
async fn reply(state: &ServerState, address: &DeviceAddress, message: ProtocolMessage) {
	let framed = {
		let account = state.server_account.lock().await;
		match Envelope::seal(&message, &account) {
			Ok(framed) => framed.to_vec(),
			Err(e) => {
				eprintln!("Could not seal a reply for {address}: {e:#}");
				return;
			}
		}
	};

	if let Err(e) = route_to(address, framed).await {
		eprintln!("Could not reach {address}: {e}");
	}
}

/// Offers whatever was waiting for a device.
///
/// Nothing is dropped here. §12.2 makes delivery acknowledgement-based, so an
/// entry is retained until the client says it arrived — a client that dies
/// between the send and reading it gets the same mail again rather than losing
/// it. Sending is not receiving.
async fn flush_mailbox(state: &ServerState, address: &DeviceAddress) -> Result<()> {
	let pending = state.store.lock().await.pending(address)?;
	if pending.is_empty() {
		return Ok(());
	}

	eprintln!("Offering {} queued message(s) to {address}", pending.len());

	for (id, frame) in pending {
		let framed = {
			let account = state.server_account.lock().await;
			Envelope::seal(
				&ProtocolMessage::Mail(Mail {
					id: id as u64,
					frame,
				}),
				&account,
			)?
		};

		if route_to(address, framed.to_vec()).await.is_err() {
			break; // gone again; the rest stays queued
		}
	}

	Ok(())
}

// TODO: this hands the full roster to anyone who asks, which is a metadata leak
// no amount of rate limiting fixes. It wants replacing with per-user contact
// lists before this faces an untrusted network.
async fn list_clients(
	State(state): State<ServerState>,
	ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
	let now = state.clock.read().await.now_ms();

	if !state.ip_limiter.lock().await.allow(peer.ip(), now) {
		return Err((StatusCode::TOO_MANY_REQUESTS, "Too many requests".into()));
	}

	println!("List called");

	let clients = CLIENTS.read().await;
	let iter = clients.keys().map(DeviceAddress::to_string);
	Ok(itertools::Itertools::intersperse(iter, String::from("\n")).collect::<String>())
}

/// Applies a key upload, completing the device entry the handshake started.
fn store_upload(
	store: &mut store::Store,
	address: &DeviceAddress,
	upload: &UploadKeys,
	uploaded_at: u64,
) -> Result<bool> {
	// The store refuses an upload that does not advance the clock, so a captured
	// one cannot be replayed to resurrect keys already handed out.
	if !store.store_prekeys(
		address,
		&upload.encryption_key,
		&upload.fallback_key,
		&upload.one_time_keys,
		uploaded_at,
	)? {
		return Ok(false);
	}

	store.complete_device(
		address,
		&upload.encryption_key,
		&upload.display_name,
		uploaded_at,
	)?;
	Ok(true)
}

/// Prekey bundle for one device (§5.2). Addressed by `user/device` rather than
/// by key material, so a device can rotate its keys without changing where
/// peers look for it (§5.3, §5.5).
async fn get_prekey_bundle(
	State(state): State<ServerState>,
	ConnectInfo(peer): ConnectInfo<SocketAddr>,
	Path((user, device)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
	let now = state.clock.read().await.now_ms();

	if !state.ip_limiter.lock().await.allow(peer.ip(), now) {
		return Err((
			StatusCode::TOO_MANY_REQUESTS,
			"Too many prekey requests".into(),
		));
	}

	let address = parse_address(&user, &device)
		.map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid address: {e}")))?;

	// Over budget we still answer, just without burning a one-time key.
	let consume = state.otk_limiter.lock().await.allow(address, now);
	if !consume {
		eprintln!(
			"One-time key budget for {address} is spent this window; serving the fallback key."
		);
	}

	let bundle = state
		.store
		.lock()
		.await
		.take_prekey_bundle(&address, consume)
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

	match bundle {
		Some(bundle) => {
			let (signing_key, encryption_key, otk, remaining_otks) = (
				bundle.signing_key,
				bundle.encryption_key,
				bundle.one_time_key,
				bundle.remaining,
			);
			// Signing key first: a peer pins it so that whatever signs their
			// first inbound message has to match (§5.2).
			let body = format!(
				"{}\n{}\n{}",
				display_key(&signing_key),
				display_key(&encryption_key),
				display_key(&otk)
			);

			if consume {
				let framed = {
					let account = state.server_account.lock().await;
					Envelope::seal(
						&ProtocolMessage::RemainingOneTimeKeys(remaining_otks),
						&account,
					)
				};

				match framed {
					Ok(framed) => {
						// Best effort: the peer not being connected is ordinary.
						let _ = route_to(&address, framed.to_vec()).await;
					}
					Err(e) => eprintln!("Could not seal an OTK notification: {e:#}"),
				}
			}

			Ok(body)
		}
		None => Err((StatusCode::NOT_FOUND, "No such device".into())),
	}
}

fn parse_address(user: &str, device: &str) -> anyhow::Result<DeviceAddress> {
	let device = data_encoding::BASE32_NOPAD
		.decode(device.trim().to_ascii_uppercase().as_bytes())?
		.as_slice()
		.try_into()
		.map_err(|_| anyhow::anyhow!("device id must be 16 bytes"))?;

	Ok(DeviceAddress::new(
		UserId::parse(user)?,
		DeviceId::from_bytes(device),
	))
}

/// A user's cross-signing keys and enrolled devices.
///
/// Served as-is. The client verifies every entry against the keys before
/// believing any of it, so this endpoint being wrong or hostile costs
/// correctness, not security (§5.4).
async fn get_device_list(
	State(state): State<ServerState>,
	ConnectInfo(peer): ConnectInfo<SocketAddr>,
	Path(user): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
	let now = state.clock.read().await.now_ms();

	if !state.ip_limiter.lock().await.allow(peer.ip(), now) {
		return Err((StatusCode::TOO_MANY_REQUESTS, "Too many requests".into()));
	}

	let user = UserId::parse(&user)
		.map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid user id: {e}")))?;

	// Incomplete devices are withheld by the store itself: an entry recorded at
	// handshake has no Olm identity key until the upload lands, and serving it
	// would make a peer's device-list check disagree with the prekey bundle.
	let listing = state
		.store
		.lock()
		.await
		.device_list(&user)
		.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

	let (keys, devices) = listing.ok_or((StatusCode::NOT_FOUND, "No such user".to_owned()))?;

	Ok(axum::Json(serde_json::json!({
		"user": user.to_string(),
		"keys": keys,
		"devices": devices,
	})))
}

// ---------------------------------------------------------------------------
// Blind relay (§3.2)
// ---------------------------------------------------------------------------

/// Tunnels a client to another Veil host, without reading what passes through.
///
/// The point of the relay is that a community host never learns the user's IP:
/// it sees this server's address instead. The cost is that a server opening
/// connections to arbitrary destinations on a user's behalf, unable to inspect
/// the traffic, **is an open proxy** — users could route attacks through the
/// operator's IP, and the operator could neither see it nor prove innocence.
///
/// So this is not an arbitrary tunnel. Three constraints, none of which require
/// reading content:
///
/// 1. the client authenticates first, so limits are per user rather than per IP;
/// 2. the destination must prove it speaks Veil before any bytes are forwarded;
/// 3. tunnels are rate limited per user.
async fn relay(socket: WebSocketUpgrade, State(state): State<ServerState>) -> Response {
	socket.on_upgrade(|socket| handle_relay(socket, state))
}

async fn handle_relay(socket: WebSocket, state: ServerState) {
	let (mut sender, mut receiver) = socket.split();

	// Same handshake as a normal connection: a relay is a service its users
	// hold an account with, not an open service (§3.2).
	let (address, _, _) = match authenticate(&mut sender, &mut receiver, &state).await {
		Ok(identity) => identity,
		Err(e) => {
			eprintln!("Relay handshake failed: {e:#}");
			return;
		}
	};

	let Some(Ok(Message::Text(target))) = receiver.next().await else {
		eprintln!("Relay: {address} did not name a destination");
		return;
	};
	let target = target.trim().to_owned();

	let now = state.clock.read().await.now_ms();
	if !state.tunnel_limiter.lock().await.allow(address, now) {
		eprintln!("Relay: {address} is over its tunnel budget");
		let _ = sender
			.send(Message::Close(Some(axum::extract::ws::CloseFrame {
				code: 1013,
				reason: "tunnel rate limit".into(),
			})))
			.await;
		return;
	}

	eprintln!("Relay: {address} -> {target}");

	match open_verified_tunnel(&target).await {
		Ok((upstream, first_frame)) => {
			// The probe connection has done its job — it proved the destination
			// is a Veil host — and is dropped here.
			//
			// It cannot be reused as the tunnel, which an earlier version did to
			// save the destination a connection. That version forwarded parsed
			// Veil frames, so the relay could read everything passing through;
			// carrying an end-to-end TLS session instead means the tunnel has to
			// be a byte stream the relay never interprets, and a WebSocket that
			// has already spoken Veil is not one. The cost is that a destination
			// sees two connections per tunnel: one probe, one carrying.
			drop(upstream);
			let _ = first_frame;

			let stream = match tokio::time::timeout(
				std::time::Duration::from_secs(10),
				tokio::net::TcpStream::connect(strip_scheme(&target)),
			)
			.await
			{
				Ok(Ok(stream)) => stream,
				_ => {
					eprintln!("Relay: could not open a byte tunnel to {target}");
					return;
				}
			};

			pump(sender, receiver, stream, address).await;
		}
		Err(e) => {
			eprintln!("Relay: refusing {address} -> {target}: {e:#}");
			let _ = sender
				.send(Message::Close(Some(axum::extract::ws::CloseFrame {
					code: 1008,
					reason: "destination is not a veil host".into(),
				})))
				.await;
		}
	}
}

/// Connects to a destination and proves it speaks Veil before returning.
///
/// **This is the load-bearing anti-open-proxy check.** Because a Veil host
/// opens with a signed `Challenge`, a web server, game server or DNS resolver
/// cannot satisfy it — so the relay cannot be pointed at one at all. That
/// removes the general open-proxy vector rather than mitigating it.
///
/// The probe *is* the first frame of the real session, so verifying costs
/// nothing extra and the destination sees a single connection.
async fn open_verified_tunnel(
	target: &str,
) -> Result<(
	tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
	Vec<u8>,
)> {
	let url = if target.starts_with("ws://") || target.starts_with("wss://") {
		target.to_owned()
	} else {
		format!("ws://{target}")
	};

	// A permissive TLS client on purpose. The relay is not authenticating the
	// destination's certificate — it is checking that the destination can
	// produce a signed Veil challenge, which a web server cannot. Requiring a
	// CA-issued certificate here would make every self-hosted community
	// unreachable through a relay (§1.3), while proving nothing the challenge
	// does not already prove. The *client* binds the certificate to the
	// destination's identity key end-to-end (§3.2); that is where it belongs.
	let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(
		rustls::ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(std::sync::Arc::new(AnyCertificate))
			.with_no_client_auth(),
	));

	let (mut upstream, _) = tokio::time::timeout(
		std::time::Duration::from_secs(10),
		tokio_tungstenite::connect_async_tls_with_config(url, None, false, Some(connector)),
	)
	.await
	.map_err(|_| anyhow::anyhow!("destination did not answer in time"))??;

	let first = tokio::time::timeout(std::time::Duration::from_secs(10), upstream.next())
		.await
		.map_err(|_| anyhow::anyhow!("destination sent no opening frame in time"))?;

	let Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(bytes))) = first else {
		anyhow::bail!("destination did not open with a binary frame");
	};

	// A signed Veil challenge, or nothing doing.
	let opened = open_envelope(&bytes)
		.map_err(|e| anyhow::anyhow!("destination's opening frame is not a veil envelope: {e}"))?;

	if !matches!(opened.message, ProtocolMessage::Challenge(_)) {
		anyhow::bail!(
			"destination opened with {:?}, not a challenge",
			opened.message
		);
	}

	Ok((upstream, bytes.to_vec()))
}

/// Moves bytes both ways without looking at them.
/// Moves bytes both ways without looking at them.
///
/// The client runs its own TLS session with the destination through this
/// (§3.2), so what crosses is opaque: the relay sees record types, lengths and
/// timing, never content. That is what keeps a home server out of the trust set
/// for traffic to a community host — which matters most for **Open**
/// communities, whose content is not end-to-end encrypted and would otherwise
/// be readable by two operators rather than one.
///
/// Framing is validated in the client-to-destination direction only. The
/// destination has already proved it is a Veil host, so its output is not the
/// open-proxy concern; the client's input is.
async fn pump(
	mut client_out: SplitSink<WebSocket, Message>,
	mut client_in: SplitStream<WebSocket>,
	upstream: tokio::net::TcpStream,
	address: DeviceAddress,
) {
	use futures::SinkExt as _;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	let (mut up_read, mut up_write) = upstream.into_split();
	let mut records = tlsframe::RecordValidator::new();
	let mut buffer = vec![0u8; 16 * 1024];

	loop {
		tokio::select! {
			from_client = client_in.next() => match from_client {
				Some(Ok(Message::Binary(bytes))) => {
					if bytes.len() > MAX_TUNNEL_FRAME {
						eprintln!("Relay: {address} sent an oversized frame; closing");
						break;
					}
					// The one thing the relay does inspect (§3.2): that this is
					// TLS at all. A tunnel carrying anything else could be
					// pointed at a plaintext service, which is the open-proxy
					// vector the destination check alone does not close.
					if let tlsframe::Verdict::NotTls(why) = records.check(&bytes) {
						eprintln!("Relay: {address} sent something that is not TLS ({why}); closing");
						break;
					}
					if up_write.write_all(&bytes).await.is_err() {
						break;
					}
				}
				Some(Ok(Message::Close(_))) | None => break,
				// Keepalives are the transport's business, not the tunnel's;
				// tearing a tunnel down over one would break long-lived idle
				// connections, which is most of them.
				Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
				Some(Ok(_)) => break, // nothing else crosses a tunnel
				Some(Err(_)) => break,
			},
			read = up_read.read(&mut buffer) => match read {
				Ok(0) | Err(_) => break,
				Ok(n) => {
					if client_out
						.send(Message::Binary(Bytes::copy_from_slice(&buffer[..n])))
						.await
						.is_err()
					{
						break;
					}
				}
			},
		}
	}

	if !records.saw_tls() {
		eprintln!("Relay: {address} closed a tunnel that never carried TLS");
	}
	eprintln!("Relay: {address} tunnel closed");
}

/// Accepts any certificate during the relay's destination probe.
///
/// See the note at the call site: the probe's question is "does this speak
/// Veil", answered by a signature, not "is this certificate trusted".
#[derive(Debug)]
struct AnyCertificate;

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
	fn verify_server_cert(
		&self,
		_end_entity: &rustls::pki_types::CertificateDer<'_>,
		_intermediates: &[rustls::pki_types::CertificateDer<'_>],
		_server_name: &rustls::pki_types::ServerName<'_>,
		_ocsp: &[u8],
		_now: rustls::pki_types::UnixTime,
	) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &rustls::pki_types::CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(
			message,
			cert,
			dss,
			&rustls::crypto::ring::default_provider().signature_verification_algorithms,
		)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &rustls::pki_types::CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(
			message,
			cert,
			dss,
			&rustls::crypto::ring::default_provider().signature_verification_algorithms,
		)
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		rustls::crypto::ring::default_provider()
			.signature_verification_algorithms
			.supported_schemes()
	}
}

/// A bare `host:port` for `TcpStream::connect`.
fn strip_scheme(target: &str) -> String {
	target
		.trim_start_matches("wss://")
		.trim_start_matches("ws://")
		.trim_end_matches('/')
		.to_owned()
}

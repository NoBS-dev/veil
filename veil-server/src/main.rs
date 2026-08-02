mod store;

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
		rustls::crypto::ring::default_provider()
			.install_default()
			.map_err(|_| anyhow::anyhow!("failed to install the rustls crypto provider"))?;
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

	// Keys must be generated because clients won't accept anything that isn't signed.
	let state = ServerState {
		store: Arc::new(Mutex::new(store::Store::open(&db_path)?)),
		clock: Arc::new(RwLock::new(clock)),
		server_account: Arc::new(Mutex::new(Account::new())),
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
	};

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
		.route("/relay", routing::any(relay))
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
			ProtocolMessage::RemainingOneTimeKeys(notification) => eprintln!(
				"Received a remaining OTKs notification. Should be impossible. Client is either broken or malicious.\nNotification: {notification:?}"
			),
		}
	}

	CLIENTS.write().await.remove(&address);
	writer.abort();
	println!("{address} disconnected");
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
			// Hand the client the destination's challenge — the same frame the
			// probe just verified, so nothing is wasted and the destination sees
			// exactly one connection.
			if sender
				.send(Message::Binary(Bytes::copy_from_slice(&first_frame)))
				.await
				.is_err()
			{
				return;
			}
			pump(sender, receiver, upstream, address).await;
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

	let (mut upstream, _) = tokio::time::timeout(
		std::time::Duration::from_secs(10),
		tokio_tungstenite::connect_async(url),
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
async fn pump(
	mut client_out: SplitSink<WebSocket, Message>,
	mut client_in: SplitStream<WebSocket>,
	upstream: tokio_tungstenite::WebSocketStream<
		tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
	>,
	address: DeviceAddress,
) {
	use futures::SinkExt as _;
	let (mut up_out, mut up_in) = upstream.split();

	loop {
		tokio::select! {
			from_client = client_in.next() => match from_client {
				Some(Ok(Message::Binary(bytes))) => {
					if bytes.len() > MAX_TUNNEL_FRAME {
						eprintln!("Relay: {address} sent an oversized frame; closing");
						break;
					}
					if up_out
						.send(tokio_tungstenite::tungstenite::Message::Binary(bytes))
						.await
						.is_err()
					{
						break;
					}
				}
				Some(Ok(Message::Close(_))) | None => break,
				Some(Ok(_)) => break, // only binary crosses a tunnel
				Some(Err(_)) => break,
			},
			from_upstream = up_in.next() => match from_upstream {
				Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(bytes))) => {
					if client_out
						.send(Message::Binary(Bytes::copy_from_slice(&bytes)))
						.await
						.is_err()
					{
						break;
					}
				}
				Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => break,
				Some(Ok(_)) => continue,
				Some(Err(_)) => break,
			},
		}
	}

	eprintln!("Relay: {address} tunnel closed");
}

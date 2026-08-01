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
	crosssign::CrossSigningPublic,
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

type KeyMap = Arc<RwLock<HashMap<DeviceAddress, ClientStore>>>;

/// A user's published identity: their cross-signing keys plus the devices they
/// have enrolled.
///
/// The server stores and serves this but is **not trusted for it** — every
/// entry carries the owner's own signature, so a client checks the whole set
/// against the keys rather than taking the server's word (§4.3).
struct UserRecord {
	keys: CrossSigningPublic,
	devices: HashMap<DeviceId, Device>,
}

type UserMap = Arc<RwLock<HashMap<UserId, UserRecord>>>;

#[derive(Clone)]
struct ServerState {
	key_map: KeyMap,
	users: UserMap,
	server_account: Arc<Mutex<Account>>,
	replay_guard: Arc<Mutex<ReplayGuard>>,
	ip_limiter: Arc<Mutex<RateLimiter<IpAddr>>>,
	otk_limiter: Arc<Mutex<RateLimiter<DeviceAddress>>>,
}

struct ClientStore {
	/// This device's signing key. Handed out with the prekey bundle so a peer
	/// can pin it (§5.2) rather than trusting whatever signs their first
	/// inbound message.
	signing_key: [u8; 32],
	encryption_key: [u8; 32],
	fallback_key: [u8; 32],

	one_time_keys: HashMap<String, [u8; 32]>, // Key ID | Public key

	/// Timestamp of the newest key upload accepted for this device. Uploads
	/// must move forward in time, so a captured upload cannot be re-sent later
	/// to resurrect keys that have since been handed out.
	last_upload_ms: u64,
}

/// Routing map, keyed by device address rather than raw key material (§5.3).
/// A user with three devices holds three entries.
static CLIENTS: LazyLock<RwLock<HashMap<DeviceAddress, SplitSink<WebSocket, Message>>>> =
	LazyLock::new(|| RwLock::new(HashMap::new()));

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

	// Keys must be generated because clients won't accept anything that isn't signed.
	let state = ServerState {
		key_map: Arc::new(RwLock::new(HashMap::new())),
		users: Arc::new(RwLock::new(HashMap::new())),
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
	};

	println!(
		"My public key: {}",
		display_key(state.server_account.lock().await.ed25519_key().as_bytes())
	);

	let router = Router::new()
		.route("/", routing::any(socket))
		.route("/clients", routing::get(list_clients))
		.route(
			"/devices/{user}/{device}/otk",
			routing::get(get_prekey_bundle),
		)
		.route("/users/{user}/devices", routing::get(get_device_list))
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
	state
		.replay_guard
		.lock()
		.await
		.check(opened.timestamp_ms, opened.nonce)?;

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
	state.users.write().await.insert_device(
		claim.user,
		claim.keys.clone(),
		Device {
			device_id: claim.device,
			ed25519: opened.sender,
			curve25519: [0; 32], // filled in by the key upload
			ssk_signature: claim.binding,
			display_name: String::new(),
			created_at: now_ms().unwrap_or_default(),
			last_seen: now_ms().unwrap_or_default(),
		},
	);

	Ok((
		DeviceAddress::new(claim.user, claim.device),
		opened.sender,
		agreed,
	))
}

/// Small helper so the insert-or-update dance is written once.
trait UserRecords {
	fn insert_device(&mut self, user: UserId, keys: CrossSigningPublic, device: Device);
}

impl UserRecords for HashMap<UserId, UserRecord> {
	fn insert_device(&mut self, user: UserId, keys: CrossSigningPublic, device: Device) {
		match self.get_mut(&user) {
			Some(record) => {
				// Refresh rather than keep the first set ever seen. A user who
				// rotates a subkey (§5.5) would otherwise have the stale keys
				// served forever, and every device enrolled under the new key
				// would fail verification for anyone fetching the list.
				//
				// Safe to take: these keys were verified during the handshake
				// that produced this call, so they derive `user` and the master
				// key signed both subkeys.
				record.keys = keys;
				record.devices.insert(device.device_id, device);
			}
			None => {
				let mut devices = HashMap::new();
				devices.insert(device.device_id, device);
				self.insert(user, UserRecord { keys, devices });
			}
		}
	}
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
	CLIENTS.write().await.insert(address, sender);

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

		if let Err(e) = state
			.replay_guard
			.lock()
			.await
			.check(opened.timestamp_ms, opened.nonce)
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

				if let Some(sender) = CLIENTS.write().await.get_mut(&msg.recipient) {
					if let Err(e) = sender
						.send(Message::Binary(Bytes::copy_from_slice(&bytes)))
						.await
					{
						eprintln!("{e:?}");
					} else {
						eprintln!("Message routed from {address} to {}", msg.recipient);
					}
				} else {
					eprintln!("Device {} not connected", msg.recipient);
				}
			}
			ProtocolMessage::UploadKeys(upload) => {
				eprintln!("Received a key upload request.");

				let mut key_map = state.key_map.write().await;

				if let Some(existing) = key_map.get(&address)
					&& opened.timestamp_ms <= existing.last_upload_ms
				{
					eprintln!("Discarding a key upload that does not advance the clock.");
					continue;
				}

				let mut store = ClientStore {
					signing_key,
					encryption_key: upload.encryption_key,
					fallback_key: upload.fallback_key,
					one_time_keys: HashMap::new(),
					last_upload_ms: opened.timestamp_ms,
				};

				for (i, otk) in upload.one_time_keys.iter().enumerate() {
					let key_id = format!("otk_{}", i);
					store.one_time_keys.insert(key_id, *otk);
				}

				key_map.insert(address, store);
				drop(key_map);

				if let Some(record) = state.users.write().await.get_mut(&address.user)
					&& let Some(device) = record.devices.get_mut(&address.device)
				{
					device.curve25519 = upload.encryption_key;
					device.display_name = upload.display_name.clone();
					device.last_seen = opened.timestamp_ms;
				}

				eprintln!("Key upload request handled properly.");
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
	println!("{address} disconnected");
}

// TODO: this hands the full roster to anyone who asks, which is a metadata leak
// no amount of rate limiting fixes. It wants replacing with per-user contact
// lists before this faces an untrusted network.
async fn list_clients(
	State(state): State<ServerState>,
	ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
	let now = now_ms().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

	if !state.ip_limiter.lock().await.allow(peer.ip(), now) {
		return Err((StatusCode::TOO_MANY_REQUESTS, "Too many requests".into()));
	}

	println!("List called");

	let clients = CLIENTS.read().await;
	let iter = clients.keys().map(DeviceAddress::to_string);
	Ok(itertools::Itertools::intersperse(iter, String::from("\n")).collect::<String>())
}

async fn pop_otk(
	key_map: &KeyMap,
	address: &DeviceAddress,
	consume: bool,
) -> Option<([u8; 32], [u8; 32], [u8; 32], u16)> {
	let mut map_guard = key_map.write().await;

	let store = map_guard.get_mut(address)?;

	let otk = if !consume {
		None
	} else if let Some(id) = store.one_time_keys.keys().next().cloned() {
		store.one_time_keys.remove(&id)
	} else {
		None
	};

	let key = otk.unwrap_or(store.fallback_key);

	Some((
		store.signing_key,
		store.encryption_key,
		key,
		store.one_time_keys.len() as u16,
	))
}

/// Prekey bundle for one device (§5.2). Addressed by `user/device` rather than
/// by key material, so a device can rotate its keys without changing where
/// peers look for it (§5.3, §5.5).
async fn get_prekey_bundle(
	State(state): State<ServerState>,
	ConnectInfo(peer): ConnectInfo<SocketAddr>,
	Path((user, device)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
	let now = now_ms().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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

	match pop_otk(&state.key_map, &address, consume).await {
		Some((signing_key, encryption_key, otk, remaining_otks)) => {
			// Signing key first: a peer pins it so that whatever signs their
			// first inbound message has to match (§5.2).
			let body = format!(
				"{}\n{}\n{}",
				display_key(&signing_key),
				display_key(&encryption_key),
				display_key(&otk)
			);

			if consume && let Some(client) = CLIENTS.write().await.get_mut(&address) {
				let account = state.server_account.lock().await;

				match Envelope::seal(
					&ProtocolMessage::RemainingOneTimeKeys(remaining_otks),
					&account,
				) {
					Ok(framed) => {
						if let Err(e) = client
							.send(Message::Binary(Bytes::copy_from_slice(&framed)))
							.await
						{
							eprintln!("Could not notify {address}: {e:?}");
						}
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
	let now = now_ms().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

	if !state.ip_limiter.lock().await.allow(peer.ip(), now) {
		return Err((StatusCode::TOO_MANY_REQUESTS, "Too many requests".into()));
	}

	let user = UserId::parse(&user)
		.map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid user id: {e}")))?;

	let users = state.users.read().await;
	let record = users
		.get(&user)
		.ok_or((StatusCode::NOT_FOUND, "No such user".to_owned()))?;

	// A device is recorded at handshake but its Olm identity key only arrives
	// with the key upload that follows. Serving the half-built entry would make
	// a peer's device-list check disagree with the prekey bundle and refuse a
	// perfectly good device, so incomplete entries are withheld until complete.
	let devices: Vec<_> = record
		.devices
		.values()
		.filter(|d| d.curve25519 != [0; 32])
		.collect();

	Ok(axum::Json(serde_json::json!({
		"user": user.to_string(),
		"keys": record.keys,
		"devices": devices,
	})))
}

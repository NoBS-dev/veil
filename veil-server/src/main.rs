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
use veil_protocol::*;
use vodozemac::olm::Account;

/// One-time keys a single identity will hand out per window. Past it we serve
/// the fallback key instead of consuming a real OTK, so someone hammering the
/// prekey endpoint degrades to fallback-key handshakes rather than stripping
/// the pool bare ahead of legitimate peers.
const OTK_BUDGET_PER_WINDOW: u32 = 5;
/// Prekey requests a single IP may make per window, whatever it asks about.
const REQUESTS_PER_IP_PER_WINDOW: u32 = 30;
const RATE_WINDOW_MS: u64 = 60_000;

type KeyMap = Arc<RwLock<HashMap<[u8; 32], ClientStore>>>;

#[derive(Clone)]
struct ServerState {
	key_map: KeyMap,
	server_account: Arc<Mutex<Account>>,
	replay_guard: Arc<Mutex<ReplayGuard>>,
	ip_limiter: Arc<Mutex<RateLimiter<IpAddr>>>,
	otk_limiter: Arc<Mutex<RateLimiter<[u8; 32]>>>,
}

struct ClientStore {
	identity_key: [u8; 32],
	encryption_key: [u8; 32],
	fallback_key: [u8; 32],

	one_time_keys: HashMap<String, [u8; 32]>, // Key ID | Public key

	/// Timestamp of the newest key upload accepted for this identity. Uploads
	/// must move forward in time, so a captured upload cannot be re-sent later
	/// to resurrect keys that have since been handed out.
	last_upload_ms: u64,
}

static CLIENTS: LazyLock<RwLock<HashMap<[u8; 32], SplitSink<WebSocket, Message>>>> =
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
			"/clients/{id}/otk",
			routing::get(get_encryption_key_and_otk),
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
) -> Result<[u8; 32]> {
	let mut challenge = [0u8; 32];
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);

	let framed = {
		let account = state.server_account.lock().await;
		Envelope::seal(&ProtocolMessage::Challenge(challenge), &account)?
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

	match opened.message {
		ProtocolMessage::Authenticate(echoed) if echoed == challenge => Ok(opened.sender),
		ProtocolMessage::Authenticate(_) => {
			anyhow::bail!("client echoed the wrong challenge")
		}
		other => anyhow::bail!("expected an Authenticate message, got {other:?}"),
	}
}

async fn handle_socket(socket: WebSocket, state: ServerState) {
	let (mut sender, mut receiver) = socket.split();

	let public_key = match authenticate(&mut sender, &mut receiver, &state).await {
		Ok(public_key) => public_key,
		Err(e) => {
			eprintln!("Handshake failed, dropping connection: {e:#}");
			return;
		}
	};

	println!("{} connected", display_key(&public_key));
	CLIENTS.write().await.insert(public_key, sender);

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
		if opened.sender != public_key {
			eprintln!(
				"Discarding an envelope signed by {} on {}'s connection",
				display_key(&opened.sender),
				display_key(&public_key)
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

				if let Some(sender) = CLIENTS.write().await.get_mut(&msg.recipient_ed25519) {
					if let Err(e) = sender
						.send(Message::Binary(Bytes::copy_from_slice(&bytes)))
						.await
					{
						eprintln!("{e:?}");
					} else {
						eprintln!(
							"Message routed successfully from {} to {}",
							display_key(&public_key),
							display_key(&msg.recipient_ed25519)
						);
					}
				} else {
					eprintln!(
						"Client {} not connected",
						display_key(&msg.recipient_ed25519)
					);
				}
			}
			ProtocolMessage::UploadKeys(upload) => {
				eprintln!("Received a key upload request.");

				let mut key_map = state.key_map.write().await;

				if let Some(existing) = key_map.get(&public_key)
					&& opened.timestamp_ms <= existing.last_upload_ms
				{
					eprintln!("Discarding a key upload that does not advance the clock.");
					continue;
				}

				let mut store = ClientStore {
					identity_key: public_key,
					encryption_key: upload.encryption_key,
					fallback_key: upload.fallback_key,
					one_time_keys: HashMap::new(),
					last_upload_ms: opened.timestamp_ms,
				};

				for (i, otk) in upload.one_time_keys.iter().enumerate() {
					let key_id = format!("otk_{}", i);
					store.one_time_keys.insert(key_id, *otk);
				}

				key_map.insert(public_key, store);

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

	CLIENTS.write().await.remove(&public_key);
	println!("{} disconnected", display_key(&public_key));
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
	let iter = clients.keys().map(display_key);
	Ok(itertools::Itertools::intersperse(iter, String::from("\n")).collect::<String>())
}

async fn pop_otk(
	key_map: &KeyMap,
	identity_key: &[u8; 32],
	consume: bool,
) -> Option<([u8; 32], [u8; 32], [u8; 32], u16)> {
	let mut map_guard = key_map.write().await;

	let store = map_guard.get_mut(identity_key)?;

	let otk = if !consume {
		None
	} else if let Some(id) = store.one_time_keys.keys().next().cloned() {
		store.one_time_keys.remove(&id)
	} else {
		None
	};

	let key = otk.unwrap_or(store.fallback_key);

	Some((
		store.identity_key,
		store.encryption_key,
		key,
		store.one_time_keys.len() as u16,
	))
}

async fn get_encryption_key_and_otk(
	State(state): State<ServerState>,
	ConnectInfo(peer): ConnectInfo<SocketAddr>,
	Path(client_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
	let now = now_ms().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

	if !state.ip_limiter.lock().await.allow(peer.ip(), now) {
		return Err((
			StatusCode::TOO_MANY_REQUESTS,
			"Too many prekey requests".into(),
		));
	}

	let identity_key = match parse_hex_key(&client_id) {
		Ok(key) => key,
		Err(e) => return Err((StatusCode::BAD_REQUEST, format!("Invalid hex key: {}", e))),
	};

	// Over budget we still answer, just without burning a one-time key.
	let consume = state.otk_limiter.lock().await.allow(identity_key, now);
	if !consume {
		eprintln!(
			"One-time key budget for {} is spent this window; serving the fallback key.",
			display_key(&identity_key)
		);
	}

	match pop_otk(&state.key_map, &identity_key, consume).await {
		Some((_, encryption_key, otk, remaining_otks)) => {
			let encryption_key_hex = display_key(&encryption_key);
			let otk_hex = display_key(&otk);

			let body = format!("{encryption_key_hex}\n{otk_hex}");

			if consume && let Some(client) = CLIENTS.write().await.get_mut(&identity_key) {
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
							eprintln!("Could not notify {}: {e:?}", display_key(&identity_key));
						}
					}
					Err(e) => eprintln!("Could not seal an OTK notification: {e:#}"),
				}
			}

			Ok(body)
		}
		None => Err((StatusCode::NOT_FOUND, "No OTKs available".into())),
	}
}

//! Drives a real `veil-server` over a real socket.
//!
//! Every end-to-end property in this crate was originally checked by hand with
//! fifos and `grep`, which proved it worked once and protected nothing
//! afterwards. This harness speaks the actual protocol so those checks can run
//! on every build.
//!
//! It deliberately does *not* use `veil-client`: driving the server with an
//! independent implementation means a test failure points at the server, and a
//! bug the client and server happen to share cannot hide behind itself.

#![allow(dead_code)]

use futures::{SinkExt, StreamExt};
use std::{
	process::Stdio,
	time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
	io::AsyncWriteExt,
	net::TcpStream,
	process::{Child, Command},
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::Message};
use veil_protocol::{
	Authenticate, Challenge, EncryptedMessage, Envelope, Mail, ProtocolMessage, UploadKeys,
	crosssign::CrossSigningSecrets,
	identity::{DeviceAddress, DeviceId, UserId},
	message::{MessageId, random_nonce},
	open_envelope,
	version::VersionRange,
};
use vodozemac::olm::{Account, SessionConfig};

/// A server process and the scratch directory it lives in.
pub struct Server {
	child: Child,
	pub port: u16,
	pub db: String,
	dir: std::path::PathBuf,
}

impl Server {
	pub async fn start() -> Self {
		Self::start_with_db(None).await
	}

	/// Starts on a fresh port, optionally reusing an existing database so a
	/// test can prove state survived a restart.
	pub async fn start_with_db(existing: Option<String>) -> Self {
		Self::start_inner(None, existing).await
	}

	/// Starts on a *named* address, so a server can come back where another
	/// server has already queued mail for it (§3.4).
	pub async fn start_at(address: &str, existing: Option<String>) -> Self {
		let port = address
			.rsplit(':')
			.next()
			.and_then(|p| p.parse().ok())
			.expect("an address of the form host:port");
		Self::start_inner(Some(port), existing).await
	}

	/// Starts with a self-signed certificate, and reports its SHA-256.
	///
	/// A self-signed certificate rather than a CA-issued one because that is
	/// what §1.3 actually requires to work: if a home server needs a certificate
	/// authority, one person on a domestic connection cannot host a community.
	/// The nested-TLS binding (§3.2) is what makes that safe, and this is the
	/// setup it has to be safe under.
	pub async fn start_with_tls() -> (Self, [u8; 32]) {
		use sha2::{Digest, Sha256};

		let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
		let hash: [u8; 32] = Sha256::digest(certified.cert.der()).into();

		let server = Self::start_inner_tls(None, None, Some(certified)).await;
		(server, hash)
	}

	async fn start_inner(fixed_port: Option<u16>, existing: Option<String>) -> Self {
		Self::start_inner_tls(fixed_port, existing, None).await
	}

	async fn start_inner_tls(
		fixed_port: Option<u16>,
		existing: Option<String>,
		tls: Option<rcgen::CertifiedKey>,
	) -> Self {
		// Zero means "the OS picks", and the port is read back from the server
		// once it has bound. Choosing one here and handing it over cannot be
		// made safe: the harness has to release it before the server can take
		// it, and with every test binary running at once another one grabs it in
		// between often enough to matter. That was the cause of failures
		// scattered across unrelated tests, all surfacing as a refused
		// connection to a server somebody else was using.
		let requested = fixed_port.unwrap_or(0);
		// Named from the process and a counter rather than the port, which is
		// not known until the server has bound.
		static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
		let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		let dir = std::env::temp_dir().join(format!("veil-test-{}-{sequence}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let db = existing.unwrap_or_else(|| dir.join("store.db").to_string_lossy().into_owned());

		let mut child = Command::new(env!("CARGO_BIN_EXE_veil-server"))
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.kill_on_drop(true)
			.spawn()
			.expect("veil-server should start");

		// address, TLS cert (blank), database path
		let mut stdin = child.stdin.take().unwrap();
		let answers = match &tls {
			None => format!("127.0.0.1:{requested}\n\n{db}\n"),
			Some(certified) => {
				let cert_path = dir.join("cert.pem");
				let key_path = dir.join("key.pem");
				std::fs::write(&cert_path, certified.cert.pem()).unwrap();
				std::fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();
				format!(
					"127.0.0.1:{requested}\n{}\n{}\n{db}\n",
					cert_path.display(),
					key_path.display()
				)
			}
		};
		stdin.write_all(answers.as_bytes()).await.unwrap();
		stdin.flush().await.unwrap();
		drop(stdin);

		let port = read_bound_port(&mut child).await;

		let server = Self {
			child,
			port,
			db,
			dir,
		};
		server.await_ready().await;
		server
	}

	/// Waits for the port to answer rather than sleeping a guessed interval —
	/// the server queries SNTP at startup, so how long it takes varies.
	async fn await_ready(&self) {
		for _ in 0..200 {
			if TcpStream::connect(("127.0.0.1", self.port)).await.is_ok() {
				return;
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		panic!("server on port {} never became ready", self.port);
	}

	pub fn wss_url(&self) -> String {
		format!("wss://127.0.0.1:{}", self.port)
	}

	pub fn ws_url(&self) -> String {
		format!("ws://127.0.0.1:{}", self.port)
	}

	/// Bare `host:port`, which is how another server is named (§3.4).
	pub fn address(&self) -> String {
		format!("127.0.0.1:{}", self.port)
	}

	pub fn http_url(&self) -> String {
		format!("http://127.0.0.1:{}", self.port)
	}

	/// Stops the server and removes its scratch directory.
	pub async fn stop(mut self) {
		let _ = self.child.kill().await;
		let _ = std::fs::remove_dir_all(&self.dir);
	}

	/// Stops the server but leaves the database, for tests that restart onto it.
	///
	/// Separate from [`Self::stop`] deliberately: cleaning up on every stop
	/// silently deleted the store a persistence test was about to reopen, and
	/// the test failed as "server never became ready" rather than as data loss.
	pub async fn stop_keeping_data(mut self) {
		let _ = self.child.kill().await;
	}

	/// Removes a scratch directory left behind by `stop_keeping_data`.
	pub fn discard(path: &str) {
		if let Some(dir) = std::path::Path::new(path).parent() {
			let _ = std::fs::remove_dir_all(dir);
		}
	}
}

/// Reads the port the server actually bound, from its own output.
///
/// The server prints `Listening on <addr>` once it is up, which is both the
/// authoritative port and a readiness signal — so this replaces guessing at a
/// port and then polling to see whether anything took it.
async fn read_bound_port(child: &mut Child) -> u16 {
	use tokio::io::{AsyncBufReadExt, BufReader};

	let stdout = child.stdout.take().expect("server stdout should be piped");
	let mut lines = BufReader::new(stdout).lines();

	let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
	while let Ok(Ok(Some(line))) = tokio::time::timeout_at(deadline, lines.next_line()).await {
		if let Some(address) = line.strip_prefix("Listening on ")
			&& let Some(port) = address.rsplit(':').next()
			&& let Ok(port) = port.trim().parse()
		{
			// Keep reading and discarding the rest. Dropping the reader would
			// close the pipe, and the server's next `println!` would then fail
			// on it — which killed the server partway through a test and
			// surfaced as a reset connection.
			tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
			return port;
		}
	}

	panic!("server never reported a bound port");
}

#[allow(dead_code)]
async fn free_port() -> u16 {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	drop(listener);
	port
}

pub fn now_ms() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis() as u64
}

/// An independent client, built only on `veil-protocol`.
pub struct TestClient {
	pub cross_signing: CrossSigningSecrets,
	pub account: Account,
	pub device: DeviceId,
	socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl TestClient {
	/// A fresh identity, not yet connected.
	#[allow(clippy::new_ret_no_self)]
	pub fn new() -> PendingClient {
		PendingClient {
			cross_signing: CrossSigningSecrets::new(),
			account: Account::new(),
			device: DeviceId::generate(),
		}
	}

	pub fn user(&self) -> UserId {
		self.cross_signing.user_id()
	}

	pub fn address(&self) -> DeviceAddress {
		DeviceAddress::new(self.user(), self.device)
	}

	pub async fn send(&mut self, message: &ProtocolMessage) -> anyhow::Result<()> {
		let framed = Envelope::seal(message, &self.account)?;
		self.socket
			.send(Message::Binary(framed.to_vec().into()))
			.await?;
		Ok(())
	}

	/// Next protocol message, or `None` if nothing arrives in time.
	pub async fn recv(&mut self, within: Duration) -> Option<ProtocolMessage> {
		let frame = tokio::time::timeout(within, self.socket.next())
			.await
			.ok()??;
		match frame.ok()? {
			Message::Binary(bytes) => open_envelope(&bytes).ok().map(|o| o.message),
			_ => None,
		}
	}

	/// Publishes prekeys, which is what completes this device's directory entry.
	/// Builds a key upload without sending, so a test can replay it.
	pub fn compose_upload(&mut self, count: usize) -> ProtocolMessage {
		self.account.generate_one_time_keys(count);
		let one_time_keys = self
			.account
			.one_time_keys()
			.values()
			.map(|k| *k.as_bytes())
			.collect();
		self.account.generate_fallback_key();
		let (_, fallback) = self.account.fallback_key().into_iter().next().unwrap();
		self.account.mark_keys_as_published();

		ProtocolMessage::UploadKeys(UploadKeys {
			encryption_key: self.account.curve25519_key().to_bytes(),
			one_time_keys,
			fallback_key: fallback.to_bytes(),
			display_name: "test".into(),
		})
	}

	pub async fn upload_keys(&mut self, count: usize) -> anyhow::Result<()> {
		self.account.generate_one_time_keys(count);
		let one_time_keys = self
			.account
			.one_time_keys()
			.values()
			.map(|k| *k.as_bytes())
			.collect();
		self.account.generate_fallback_key();
		let (_, fallback) = self.account.fallback_key().into_iter().next().unwrap();

		self.send(&ProtocolMessage::UploadKeys(UploadKeys {
			encryption_key: self.account.curve25519_key().to_bytes(),
			one_time_keys,
			fallback_key: fallback.to_bytes(),
			display_name: "test".into(),
		}))
		.await?;
		self.account.mark_keys_as_published();
		Ok(())
	}

	/// Opens a session to a peer on this server and sends one message.
	pub async fn send_to(
		&mut self,
		recipient: DeviceAddress,
		peer_x25519: [u8; 32],
		otk: [u8; 32],
		text: &str,
	) -> anyhow::Result<()> {
		self.send_to_host(recipient, "", peer_x25519, otk, text)
			.await
	}

	/// As above, but for a recipient whose mailbox is on another server (§3.4).
	pub async fn send_to_host(
		&mut self,
		recipient: DeviceAddress,
		host: &str,
		peer_x25519: [u8; 32],
		otk: [u8; 32],
		text: &str,
	) -> anyhow::Result<()> {
		let message = self.compose_for(recipient, host, peer_x25519, otk, text)?;
		self.send(&message).await
	}

	/// Decrypts an inbound prekey message.
	pub fn decrypt(&mut self, message: &EncryptedMessage) -> anyhow::Result<String> {
		let olm = vodozemac::olm::OlmMessage::from_parts(message.message_type, &message.message)?;
		match olm {
			vodozemac::olm::OlmMessage::PreKey(prekey) => {
				let opened = self
					.account
					.create_inbound_session(prekey.identity_key(), &prekey)?;
				Ok(String::from_utf8_lossy(&opened.plaintext).into_owned())
			}
			vodozemac::olm::OlmMessage::Normal(_) => {
				anyhow::bail!("expected a prekey message to open a session")
			}
		}
	}

	pub async fn acknowledge(&mut self, id: u64) -> anyhow::Result<()> {
		self.send(&ProtocolMessage::Acknowledge(vec![id])).await
	}

	/// Sends bytes verbatim, so a test can replay or corrupt a captured frame.
	pub async fn send_raw(&mut self, bytes: Vec<u8>) -> anyhow::Result<()> {
		self.socket.send(Message::Binary(bytes.into())).await?;
		Ok(())
	}

	/// Seals a message and returns the bytes *without* sending, so a test can
	/// keep a copy to replay later.
	pub fn frame(&self, message: &ProtocolMessage) -> anyhow::Result<Vec<u8>> {
		Ok(Envelope::seal(message, &self.account)?.to_vec())
	}

	/// Builds an encrypted message without sending it.
	pub fn compose(
		&mut self,
		recipient: DeviceAddress,
		peer_x25519: [u8; 32],
		otk: [u8; 32],
		text: &str,
	) -> anyhow::Result<ProtocolMessage> {
		self.compose_for(recipient, "", peer_x25519, otk, text)
	}

	pub fn compose_for(
		&mut self,
		recipient: DeviceAddress,
		host: &str,
		peer_x25519: [u8; 32],
		otk: [u8; 32],
		text: &str,
	) -> anyhow::Result<ProtocolMessage> {
		let mut session = self.account.create_outbound_session(
			SessionConfig::version_2(),
			peer_x25519.into(),
			otk.into(),
		);
		let (message_type, ciphertext) = session.encrypt(text).to_parts();

		Ok(ProtocolMessage::EncryptedMessage(EncryptedMessage {
			sender: self.address(),
			recipient,
			recipient_host: host.to_owned(),
			sender_x25519: self.account.curve25519_key().to_bytes(),
			nonce: random_nonce(),
			origin_ts: now_ms(),
			seen_head: MessageId::ROOT,
			message_type,
			message: ciphertext,
		}))
	}

	/// Whether the peer is still willing to talk to us.
	/// Whether the peer is still willing to talk to us.
	///
	/// Sends a ping and waits for the answer. Checking only that the *send*
	/// succeeded — which is what this did — proves nothing: a write to a socket
	/// the far end has already closed lands in a local buffer and reports
	/// success, so the check passed against a server that had hung up.
	pub async fn is_connected(&mut self) -> bool {
		if self
			.socket
			.send(Message::Ping(Vec::new().into()))
			.await
			.is_err()
		{
			return false;
		}

		loop {
			match tokio::time::timeout(Duration::from_millis(1500), self.socket.next()).await {
				Ok(Some(Ok(Message::Pong(_)))) => return true,
				Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => return false,
				Ok(Some(Ok(_))) => continue, // traffic in flight; keep looking
				Err(_) => return false,      // no answer at all
			}
		}
	}

	/// Sends a text frame — the relay names its destination this way.
	pub async fn send_text(&mut self, text: &str) -> anyhow::Result<()> {
		self.socket.send(Message::Text(text.into())).await?;
		Ok(())
	}

	/// The next frame, whatever it is, so a test can judge raw behaviour.
	pub async fn recv_raw(&mut self, within: Duration) -> Option<Message> {
		tokio::time::timeout(within, self.socket.next())
			.await
			.ok()??
			.ok()
	}

	/// Drops the connection but keeps the identity, so a test can come back as
	/// the *same* device.
	pub fn disconnect(self) -> PendingClient {
		PendingClient {
			cross_signing: self.cross_signing,
			account: self.account,
			device: self.device,
		}
	}

	/// Reads what the server offers without acknowledging any of it, so a test
	/// can prove unacknowledged mail is retained.
	/// Every queued frame, whatever it holds.
	///
	/// `peek_mail` filters to messages, so it cannot see something that was
	/// queued but should not have been — which is exactly what a test about
	/// *not* queueing needs to look at.
	pub async fn mail_frames(&mut self, within: Duration) -> Vec<ProtocolMessage> {
		let mut out = Vec::new();
		while let Some(message) = self.recv(within).await {
			if let ProtocolMessage::Mail(Mail { frame, .. }) = message
				&& let Ok(inner) = open_envelope(&frame)
			{
				out.push(inner.message);
			}
		}
		out
	}

	pub async fn peek_mail(&mut self, within: Duration) -> Vec<String> {
		let mut out = Vec::new();
		while let Some(message) = self.recv(within).await {
			if let ProtocolMessage::Mail(Mail { frame, .. }) = message
				&& let Ok(inner) = open_envelope(&frame)
				&& let ProtocolMessage::EncryptedMessage(msg) = inner.message
			{
				// Recorded without decrypting: opening a prekey message twice
				// would consume the one-time key and muddy what is being tested.
				out.push(format!("{}", msg.sender));
			}
		}
		out
	}

	/// Reads mail the server offers, returning the decrypted bodies.
	pub async fn collect_mail(&mut self, within: Duration) -> Vec<String> {
		let mut out = Vec::new();
		while let Some(message) = self.recv(within).await {
			if let ProtocolMessage::Mail(Mail { id, frame }) = message
				&& let Ok(inner) = open_envelope(&frame)
				&& let ProtocolMessage::EncryptedMessage(msg) = inner.message
				&& let Ok(text) = self.decrypt(&msg)
			{
				out.push(text);
				let _ = self.acknowledge(id).await;
			}
		}
		out
	}
}

/// A client identity that has not connected yet, so a test can reconnect as
/// the *same* device later.
pub struct PendingClient {
	pub cross_signing: CrossSigningSecrets,
	pub account: Account,
	pub device: DeviceId,
}

impl PendingClient {
	pub fn user(&self) -> UserId {
		self.cross_signing.user_id()
	}

	pub fn address(&self) -> DeviceAddress {
		DeviceAddress::new(self.user(), self.device)
	}

	/// Connects and completes the handshake.
	pub async fn connect(self, url: &str) -> anyhow::Result<TestClient> {
		self.connect_with(url, |a| a).await
	}

	/// Connects to a destination *through* a relay.
	///
	/// Two handshakes, as §3.2 describes: one with the relay, which is a service
	/// the user holds an account with, and one with the destination through the
	/// tunnel — which is the session that matters.
	pub async fn connect_via_relay(
		self,
		relay_url: &str,
		destination: &str,
	) -> anyhow::Result<TestClient> {
		let (mut socket, _) =
			tokio_tungstenite::connect_async(format!("{relay_url}/relay")).await?;

		// Handshake with the relay itself.
		let Some(Ok(Message::Binary(bytes))) = socket.next().await else {
			anyhow::bail!("relay did not open with a challenge");
		};
		let opened = open_envelope(&bytes)?;
		let ProtocolMessage::Challenge(challenge) = opened.message else {
			anyhow::bail!("relay did not send a challenge");
		};
		let ours = VersionRange::supported();
		let framed = Envelope::seal(
			&ProtocolMessage::Authenticate(Box::new(Authenticate {
				challenge: challenge.challenge,
				versions: ours,
				server_versions_seen: challenge.versions,
				user: self.user(),
				device: self.device,
				keys: self.cross_signing.public(),
				binding: self
					.cross_signing
					.sign_device(&self.device, self.account.ed25519_key().as_bytes()),
			})),
			&self.account,
		)?;
		socket.send(Message::Binary(framed.to_vec().into())).await?;
		socket.send(Message::Text(destination.into())).await?;

		// From here the socket carries the destination's session.
		let Some(Ok(Message::Binary(bytes))) = socket.next().await else {
			anyhow::bail!("relay did not forward the destination's challenge");
		};
		let opened = open_envelope(&bytes)?;
		let ProtocolMessage::Challenge(challenge) = opened.message else {
			anyhow::bail!("destination did not send a challenge");
		};
		let framed = Envelope::seal(
			&ProtocolMessage::Authenticate(Box::new(Authenticate {
				challenge: challenge.challenge,
				versions: ours,
				server_versions_seen: challenge.versions,
				user: self.user(),
				device: self.device,
				keys: self.cross_signing.public(),
				binding: self
					.cross_signing
					.sign_device(&self.device, self.account.ed25519_key().as_bytes()),
			})),
			&self.account,
		)?;
		socket.send(Message::Binary(framed.to_vec().into())).await?;

		Ok(TestClient {
			cross_signing: self.cross_signing,
			account: self.account,
			device: self.device,
			socket,
		})
	}

	/// Connects, letting a test corrupt the authentication before it is sent.
	pub async fn connect_with(
		self,
		url: &str,
		tamper: impl FnOnce(Authenticate) -> Authenticate,
	) -> anyhow::Result<TestClient> {
		let (mut socket, _) = tokio_tungstenite::connect_async(url).await?;

		let Some(Ok(Message::Binary(bytes))) = socket.next().await else {
			anyhow::bail!("server did not open with a challenge");
		};
		let opened = open_envelope(&bytes)?;
		let Challenge {
			challenge,
			versions,
			tls_binding: _,
		} = match opened.message {
			ProtocolMessage::Challenge(c) => c,
			other => anyhow::bail!("expected a challenge, got {other:?}"),
		};

		let ours = VersionRange::supported();
		ours.agree(&versions)?;

		let claim = tamper(Authenticate {
			challenge,
			versions: ours,
			server_versions_seen: versions,
			user: self.user(),
			device: self.device,
			keys: self.cross_signing.public(),
			binding: self
				.cross_signing
				.sign_device(&self.device, self.account.ed25519_key().as_bytes()),
		});

		let framed = Envelope::seal(
			&ProtocolMessage::Authenticate(Box::new(claim)),
			&self.account,
		)?;
		socket.send(Message::Binary(framed.to_vec().into())).await?;

		Ok(TestClient {
			cross_signing: self.cross_signing,
			account: self.account,
			device: self.device,
			socket,
		})
	}
}

/// Devices the server currently considers connected.
///
/// Used to check that a rejected handshake really was rejected: a server that
/// merely stays silent looks identical to one that admitted you, so silence is
/// not evidence of refusal.
pub async fn connected_devices(http: &str) -> anyhow::Result<Vec<String>> {
	Ok(reqwest::get(format!("{http}/clients"))
		.await?
		.text()
		.await?
		.lines()
		.map(|l| l.trim().to_owned())
		.filter(|l| !l.is_empty())
		.collect())
}

/// Fetches a device's prekey bundle over HTTP: signing key, identity key, OTK.
pub async fn prekey_bundle(
	http: &str,
	address: &DeviceAddress,
) -> anyhow::Result<([u8; 32], [u8; 32], [u8; 32])> {
	let body = reqwest::get(format!(
		"{http}/devices/{}/{}/otk",
		address.user, address.device
	))
	.await?
	.error_for_status()?
	.text()
	.await?;

	let mut lines = body.lines();
	let mut next = || -> anyhow::Result<[u8; 32]> {
		veil_protocol::parse_hex_key(
			lines
				.next()
				.ok_or_else(|| anyhow::anyhow!("short prekey bundle"))?
				.trim(),
		)
	};
	Ok((next()?, next()?, next()?))
}

/// A signed envelope from a sender who is not connected to anything.
///
/// Enough to exercise the deposit path, which never looks inside the
/// ciphertext — only the recipient can, and that is the point. Store-and-forward
/// means the sender need not be online anywhere for this to be delivered.
pub fn compose_offline(recipient: DeviceAddress, text: &str) -> Vec<u8> {
	let sender = CrossSigningSecrets::new();
	let account = Account::new();

	Envelope::seal(
		&ProtocolMessage::EncryptedMessage(EncryptedMessage {
			sender: DeviceAddress::new(sender.user_id(), DeviceId::generate()),
			recipient,
			recipient_host: String::new(),
			sender_x25519: account.curve25519_key().to_bytes(),
			nonce: random_nonce(),
			origin_ts: now_ms(),
			seen_head: MessageId::ROOT,
			message_type: 0,
			message: text.as_bytes().to_vec(),
		}),
		&account,
	)
	.unwrap()
	.to_vec()
}

/// Re-exported so tests can build a post without importing the internals.
pub fn nonce() -> [u8; 16] {
	random_nonce()
}

/// A Megolm ciphertext, as a Sealed client would send.
///
/// Uses the real provider rather than a stand-in, so what the host is asked to
/// store is genuinely what a Sealed community produces — a test that stored
/// scrambled bytes would prove nothing about the tier.
pub fn sealed_body(plaintext: &[u8]) -> Vec<u8> {
	use veil_protocol::{
		community::Mode,
		groupkeys::{ChannelId, GroupKeyProvider, MegolmProvider, Readership},
	};

	let founder = CrossSigningSecrets::new();
	let community = veil_protocol::community::CommunityRoot::found(
		Mode::Sealed,
		vec![founder.master_public()],
		1,
		founder.master_secret(),
		now_ms(),
	)
	.unwrap()
	.id();

	let channel = ChannelId::new(community, "general");
	let mut provider = MegolmProvider::new(DeviceAddress::new(
		CrossSigningSecrets::new().user_id(),
		DeviceId::generate(),
	));
	let reader = DeviceAddress::new(CrossSigningSecrets::new().user_id(), DeviceId::generate());
	provider
		.set_readership(
			&channel,
			&Readership {
				devices: [reader].into_iter().collect(),
				policy_sequence: 1,
			},
			now_ms(),
		)
		.unwrap();

	provider.encrypt(&channel, plaintext).unwrap()
}

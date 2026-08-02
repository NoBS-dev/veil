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
		let port = free_port().await;
		let dir = std::env::temp_dir().join(format!("veil-test-{}-{port}", std::process::id()));
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
		stdin
			.write_all(format!("127.0.0.1:{port}\n\n{db}\n").as_bytes())
			.await
			.unwrap();
		stdin.flush().await.unwrap();
		drop(stdin);

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

	pub fn ws_url(&self) -> String {
		format!("ws://127.0.0.1:{}", self.port)
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

async fn free_port() -> u16 {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	drop(listener);
	port
}

fn now_ms() -> u64 {
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

	/// Opens a session to a peer and sends one message.
	pub async fn send_to(
		&mut self,
		recipient: DeviceAddress,
		peer_x25519: [u8; 32],
		otk: [u8; 32],
		text: &str,
	) -> anyhow::Result<()> {
		let mut session = self.account.create_outbound_session(
			SessionConfig::version_2(),
			peer_x25519.into(),
			otk.into(),
		);
		let (message_type, ciphertext) = session.encrypt(text).to_parts();

		self.send(&ProtocolMessage::EncryptedMessage(EncryptedMessage {
			sender: self.address(),
			recipient,
			sender_x25519: self.account.curve25519_key().to_bytes(),
			nonce: random_nonce(),
			origin_ts: now_ms(),
			seen_head: MessageId::ROOT,
			message_type,
			message: ciphertext,
		}))
		.await
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

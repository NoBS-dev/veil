//! Shared rig for the client tests: a real server, and the real client binary
//! driven the way a person drives it — commands on stdin, judgement from stdout.
//!
//! These need somewhere to keep profiles that is not the OS keyring, which is
//! what `VEIL_STATE_DIR` is for. That indirection was added to make this
//! possible and turned out to be needed for headless use anyway — a client that
//! requires a Secret Service cannot run in a container either.
//!
//! Each test file compiles this module separately, so anything only one of them
//! uses reads as dead code in the others — hence the allow, rather than trimming
//! it to whatever the current caller set happens to be.
#![allow(dead_code)]

use std::{process::Stdio, time::Duration};
use tokio::{
	io::AsyncWriteExt,
	process::{Child, Command},
};

pub struct Fixture {
	server: Child,
	pub port: u16,
	dir: std::path::PathBuf,
	/// Servers started beyond the first, killed when the fixture is dropped.
	extra: std::sync::Mutex<Vec<Child>>,
}

impl Fixture {
	pub async fn start() -> Self {
		// A counter, not a thread id: threads are reused across tests, so two
		// fixtures could land on the same directory — and the `remove_dir_all`
		// below would then wipe the other one's profiles mid-run.
		static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
		let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		let dir = std::env::temp_dir().join(format!(
			"veil-client-test-{}-{sequence}",
			std::process::id()
		));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();

		let mut server = Command::new(binary("veil-server"))
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.kill_on_drop(true)
			.spawn()
			.unwrap();

		let db = dir.join("server.db");
		let mut stdin = server.stdin.take().unwrap();
		stdin
			.write_all(format!("127.0.0.1:0\n\n{}\n", db.display()).as_bytes())
			.await
			.unwrap();
		stdin.flush().await.unwrap();
		drop(stdin);

		// The port the OS gave it, read from its own output. Picking one here
		// and handing it over cannot be made safe — the harness has to release
		// it before the server can bind, and with every test binary running at
		// once something else takes it in between often enough to matter.
		let port = read_bound_port(&mut server).await;

		Self {
			server,
			port,
			dir,
			extra: std::sync::Mutex::new(Vec::new()),
		}
	}

	/// Runs the client with the given stdin, returning everything it printed.
	///
	/// Stdin closing is what ends the session — the client treats EOF as a
	/// quit, which is also why it no longer spins when its input goes away.
	pub async fn run_client(&self, input: &str) -> String {
		self.run_client_lingering(input, Duration::ZERO).await
	}

	/// As above, but holds stdin open afterwards.
	///
	/// Sending and receiving are asynchronous — the command returns before the
	/// envelope is on the wire, and mail arrives unprompted. A client whose
	/// input closes quits immediately, so anything that has to survive a round
	/// trip needs to be given the time to make it.
	pub async fn run_client_lingering(&self, input: &str, linger: Duration) -> String {
		tokio::time::timeout(
			Duration::from_secs(45),
			Command::new(binary("veil-client"))
				.env("VEIL_STATE_DIR", self.dir.join("profiles"))
				.stdin(Stdio::piped())
				.stdout(Stdio::piped())
				.stderr(Stdio::piped())
				.kill_on_drop(true)
				.spawn()
				.unwrap()
				.wait_with_output_from(input.to_owned(), linger),
		)
		.await
		.expect("client should not hang")
	}

	/// Runs a client, feeding it input in stages with a pause between each.
	///
	/// Needed for anything that must happen *while a client is connected* —
	/// a policy change reaching a member who never reconnects, for instance.
	/// Writing the whole script at once cannot test that, because the client
	/// consumes it as fast as it can and the session is over before anything
	/// else has moved.
	pub async fn run_client_staged(&self, stages: &[(String, Duration)]) -> String {
		let stages = stages.to_vec();

		tokio::time::timeout(
			Duration::from_secs(90),
			Command::new(binary("veil-client"))
				.env("VEIL_STATE_DIR", self.dir.join("profiles"))
				.stdin(Stdio::piped())
				.stdout(Stdio::piped())
				.stderr(Stdio::piped())
				.kill_on_drop(true)
				.spawn()
				.unwrap()
				.wait_with_staged_input(stages),
		)
		.await
		.expect("client should not hang")
	}

	/// Note the `find`, not a line prefix: the client's prompts are `print!`
	/// without a newline, so the address shares a line with whatever preceded it.
	pub fn address_from(output: &str) -> String {
		let start = output
			.find("My address: ")
			.unwrap_or_else(|| panic!("client should print its address, got:\n{output}"))
			+ "My address: ".len();
		output[start..]
			.lines()
			.next()
			.expect("an address on that line")
			.trim()
			.to_owned()
	}

	/// The first server's database, for tests that check what a host holds.
	pub fn db_path(&self) -> String {
		self.dir.join("server.db").to_string_lossy().into_owned()
	}

	/// An extra plaintext server, for tests that need more than one host.
	pub async fn start_server(&self) -> String {
		self.spawn_server(None).await
	}

	/// An extra server with a **self-signed** certificate, plus its SHA-256.
	///
	/// Self-signed because that is what a self-hoster has (§1.3). The nested-TLS
	/// binding is what makes it safe, so this is the configuration it has to be
	/// safe under.
	pub async fn start_tls_server(&self) -> (String, [u8; 32]) {
		use sha2::{Digest, Sha256};

		let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
		let hash: [u8; 32] = Sha256::digest(certified.cert.der()).into();
		let address = self.spawn_server(Some(certified)).await;
		(address, hash)
	}

	async fn spawn_server(&self, tls: Option<rcgen::CertifiedKey>) -> String {
		static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
		let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		let dir = self.dir.join(format!("server-{sequence}"));
		std::fs::create_dir_all(&dir).unwrap();

		let mut child = Command::new(binary("veil-server"))
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::null())
			.kill_on_drop(true)
			.spawn()
			.unwrap();

		let db = dir.join("store.db");
		let answers = match &tls {
			None => format!("127.0.0.1:0\n\n{}\n", db.display()),
			Some(certified) => {
				let cert = dir.join("cert.pem");
				let key = dir.join("key.pem");
				std::fs::write(&cert, certified.cert.pem()).unwrap();
				std::fs::write(&key, certified.key_pair.serialize_pem()).unwrap();
				format!(
					"127.0.0.1:0\n{}\n{}\n{}\n",
					cert.display(),
					key.display(),
					db.display()
				)
			}
		};

		let mut stdin = child.stdin.take().unwrap();
		stdin.write_all(answers.as_bytes()).await.unwrap();
		stdin.flush().await.unwrap();
		drop(stdin);

		let port = read_bound_port(&mut child).await;
		self.extra.lock().unwrap().push(child);
		format!("127.0.0.1:{port}")
	}

	/// A relay that terminates the inner TLS session itself.
	///
	/// **The attack nested TLS exists to stop.** This relay behaves correctly at
	/// every layer a client can see without the binding: it authenticates the
	/// user, it forwards to the host that was actually asked for, and the Veil
	/// handshake the client completes is with the genuine destination. What it
	/// also does is decrypt everything in between — which for an Open community
	/// is the entire content of the conversation.
	///
	/// It cannot make the destination's identity key sign a hash of the
	/// certificate it presents, so the client's binding check catches it.
	pub async fn start_mitm_relay(&self, destination: &str) -> String {
		use futures_util::{SinkExt, StreamExt};
		use tungstenite::protocol::Message;

		// The fixture runs TLS itself here, so it needs a provider too.
		let _ = rustls::crypto::ring::default_provider().install_default();

		let port = free_port().await;
		let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
			.await
			.unwrap();

		// The relay's own certificate — perfectly valid, and not the one the
		// destination signed for.
		let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
		let tls_config = std::sync::Arc::new(
			rustls::ServerConfig::builder()
				.with_no_client_auth()
				.with_single_cert(
					vec![certified.cert.der().clone()],
					rustls::pki_types::PrivateKeyDer::try_from(certified.key_pair.serialize_der())
						.unwrap(),
				)
				.unwrap(),
		);

		let destination = destination.to_owned();
		tokio::spawn(async move {
			let account = vodozemac::olm::Account::new();
			while let Ok((socket, _)) = listener.accept().await {
				let destination = destination.clone();
				let tls_config = tls_config.clone();
				let pickle = account.pickle();

				tokio::spawn(async move {
					let account = vodozemac::olm::Account::from_pickle(pickle);
					let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else {
						return;
					};

					// The relay half of the handshake, played straight.
					let mut challenge = [0u8; 32];
					rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);
					let framed = veil_protocol::Envelope::seal(
						&veil_protocol::ProtocolMessage::Challenge(veil_protocol::Challenge {
							challenge,
							versions: veil_protocol::version::VersionRange::supported(),
							tls_binding: [0u8; 32],
						}),
						&account,
					)
					.unwrap();
					if ws
						.send(Message::Binary(framed.to_vec().into()))
						.await
						.is_err()
					{
						return;
					}
					let _ = ws.next().await; // Authenticate
					let _ = ws.next().await; // the destination it asked for

					// From here the client believes it is speaking TLS to the
					// destination. It is speaking TLS to us.
					let Ok(inner) = tokio_rustls::TlsAcceptor::from(tls_config)
						.accept(WsBytes::new(ws))
						.await
					else {
						return;
					};
					let Ok(mut client) = tokio_tungstenite::accept_async(inner).await else {
						return;
					};

					// And we hold the real session with the destination.
					let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(
						rustls::ClientConfig::builder()
							.dangerous()
							.with_custom_certificate_verifier(std::sync::Arc::new(AnyCert))
							.with_no_client_auth(),
					));
					let Ok((mut upstream, _)) = tokio_tungstenite::connect_async_tls_with_config(
						format!("wss://{destination}/"),
						None,
						false,
						Some(connector),
					)
					.await
					else {
						return;
					};

					loop {
						tokio::select! {
							from_client = client.next() => match from_client {
								Some(Ok(m)) => { if upstream.send(m).await.is_err() { break } }
								_ => break,
							},
							from_host = upstream.next() => match from_host {
								Some(Ok(m)) => { if client.send(m).await.is_err() { break } }
								_ => break,
							},
						}
					}
				});
			}
		});

		format!("127.0.0.1:{port}")
	}

	pub async fn stop(mut self) {
		let _ = self.server.kill().await;
		for child in self.extra.lock().unwrap().iter_mut() {
			let _ = child.start_kill();
		}
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}

/// Reads the port the server actually bound, from its own output.
///
/// Both the authoritative port and a readiness signal, so this replaces a guess
/// followed by polling to see whether anything took it.
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

/// Small helper: feed stdin, wait, collect stdout and stderr together.
trait RunWithInput {
	async fn wait_with_output_from(self, input: String, linger: Duration) -> String;
	async fn wait_with_staged_input(self, stages: Vec<(String, Duration)>) -> String;
}

impl RunWithInput for Child {
	async fn wait_with_output_from(mut self, input: String, linger: Duration) -> String {
		let mut stdin = self.stdin.take().unwrap();
		tokio::spawn(async move {
			let _ = stdin.write_all(input.as_bytes()).await;
			let _ = stdin.flush().await;
			tokio::time::sleep(linger).await;
			drop(stdin); // EOF, which the client takes as a quit
		});

		let output = self.wait_with_output().await.unwrap();
		format!(
			"{}{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		)
	}

	async fn wait_with_staged_input(mut self, stages: Vec<(String, Duration)>) -> String {
		let mut stdin = self.stdin.take().unwrap();
		tokio::spawn(async move {
			for (input, pause) in stages {
				let _ = stdin.write_all(input.as_bytes()).await;
				let _ = stdin.flush().await;
				tokio::time::sleep(pause).await;
			}
			drop(stdin);
		});

		let output = self.wait_with_output().await.unwrap();
		format!(
			"{}{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		)
	}
}

/// Locates a workspace binary.
///
/// `CARGO_BIN_EXE_*` only covers binaries belonging to the crate under test, and
/// the server belongs to another one. The test binary itself lives in
/// `target/<profile>/deps/`, so its grandparent is where both binaries are.
pub fn binary(name: &str) -> std::path::PathBuf {
	let mut path = std::env::current_exe().expect("test binary should have a path");
	path.pop(); // deps/
	path.pop(); // <profile>/
	path.push(name);
	assert!(
		path.exists(),
		"{} is not built; run `cargo build --workspace` first",
		path.display()
	);
	path
}

pub async fn free_port() -> u16 {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	drop(listener);
	port
}

/// A byte stream over a server-side WebSocket, so TLS can be run inside one.
///
/// The mirror of the client's `TunnelStream`. Lives here rather than being
/// shared because the client crate is a binary and this is a test fixture; the
/// duplication is deliberate, since a test that reuses the code under test
/// cannot disagree with it.
pub struct WsBytes {
	socket: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
	pending: Vec<u8>,
	read_from: usize,
}

impl WsBytes {
	pub fn new(socket: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) -> Self {
		Self {
			socket,
			pending: Vec::new(),
			read_from: 0,
		}
	}
}

impl tokio::io::AsyncRead for WsBytes {
	fn poll_read(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		use futures_util::StreamExt;
		use std::task::Poll;
		use tungstenite::protocol::Message;

		loop {
			let buffered = self.pending.len() - self.read_from;
			if buffered > 0 {
				let take = buffered.min(buf.remaining());
				let from = self.read_from;
				let slice = self.pending[from..from + take].to_vec();
				buf.put_slice(&slice);
				self.read_from += take;
				if self.read_from == self.pending.len() {
					self.pending.clear();
					self.read_from = 0;
				}
				return Poll::Ready(Ok(()));
			}

			match self.socket.poll_next_unpin(cx) {
				Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
					self.pending = bytes.to_vec();
					self.read_from = 0;
				}
				Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
					return Poll::Ready(Ok(()));
				}
				Poll::Ready(Some(Ok(_))) => continue,
				Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(std::io::Error::other(e))),
				Poll::Pending => return Poll::Pending,
			}
		}
	}
}

impl tokio::io::AsyncWrite for WsBytes {
	fn poll_write(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<std::io::Result<usize>> {
		use futures_util::SinkExt;
		use std::task::Poll;
		use tungstenite::protocol::Message;

		match self.socket.poll_ready_unpin(cx) {
			Poll::Ready(Ok(())) => {
				match self
					.socket
					.start_send_unpin(Message::Binary(buf.to_vec().into()))
				{
					Ok(()) => Poll::Ready(Ok(buf.len())),
					Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
				}
			}
			Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
			Poll::Pending => Poll::Pending,
		}
	}

	fn poll_flush(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		use futures_util::SinkExt;
		self.socket
			.poll_flush_unpin(cx)
			.map_err(std::io::Error::other)
	}

	fn poll_shutdown(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		use futures_util::SinkExt;
		self.socket
			.poll_close_unpin(cx)
			.map_err(std::io::Error::other)
	}
}

/// Accepts anything, so the fixture can reach a self-signed test server.
#[derive(Debug)]
pub struct AnyCert;

impl rustls::client::danger::ServerCertVerifier for AnyCert {
	fn verify_server_cert(
		&self,
		_end_entity: &rustls::pki_types::CertificateDer<'_>,
		_intermediates: &[rustls::pki_types::CertificateDer<'_>],
		_server_name: &rustls::pki_types::ServerName<'_>,
		_ocsp: &[u8],
		_now: rustls::pki_types::UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &rustls::pki_types::CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

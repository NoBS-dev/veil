//! Shared rig for the client tests: a real server, and the real client binary
//! driven the way a person drives it — commands on stdin, judgement from stdout.
//!
//! These need somewhere to keep profiles that is not the OS keyring, which is
//! what `VEIL_STATE_DIR` is for. That indirection was added to make this
//! possible and turned out to be needed for headless use anyway — a client that
//! requires a Secret Service cannot run in a container either.

use std::{process::Stdio, time::Duration};
use tokio::{
	io::AsyncWriteExt,
	process::{Child, Command},
};

pub struct Fixture {
	server: Child,
	pub port: u16,
	dir: std::path::PathBuf,
}

impl Fixture {
	pub async fn start() -> Self {
		let port = free_port().await;
		let dir =
			std::env::temp_dir().join(format!("veil-client-test-{}-{port}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();

		let mut server = Command::new(binary("veil-server"))
			.stdin(Stdio::piped())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.kill_on_drop(true)
			.spawn()
			.unwrap();

		let db = dir.join("server.db");
		let mut stdin = server.stdin.take().unwrap();
		stdin
			.write_all(format!("127.0.0.1:{port}\n\n{}\n", db.display()).as_bytes())
			.await
			.unwrap();
		stdin.flush().await.unwrap();
		drop(stdin);

		let fixture = Self { server, port, dir };
		fixture.await_ready().await;
		fixture
	}

	async fn await_ready(&self) {
		for _ in 0..200 {
			if tokio::net::TcpStream::connect(("127.0.0.1", self.port))
				.await
				.is_ok()
			{
				return;
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		panic!("server never became ready");
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

	pub async fn stop(mut self) {
		let _ = self.server.kill().await;
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}

/// Small helper: feed stdin, wait, collect stdout and stderr together.
trait RunWithInput {
	async fn wait_with_output_from(self, input: String, linger: Duration) -> String;
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

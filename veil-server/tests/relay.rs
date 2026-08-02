//! The relay's anti-open-proxy checks — `DESIGN.md` §3.2.
//!
//! A server that opens connections to arbitrary destinations on a user's behalf
//! and cannot inspect the traffic *is* an open proxy. These tests exist because
//! that is the property most likely to be quietly lost in a refactor: the tunnel
//! would keep working, and only the refusals would stop happening.
//!
//! Two independent constraints, and both are tested here because either alone
//! leaves a hole. The **destination check** proves the far end is a Veil host,
//! so the tunnel cannot be aimed at a web server. The **framing check** proves
//! what crosses is TLS, so a tunnel to a genuine Veil host cannot be used to
//! carry something else to it.
//!
//! The end-to-end round trip lives in `veil-client/tests/relay.rs`, because it
//! now requires nested TLS (§3.2) and the real client is what speaks it.

mod harness;

use futures::{SinkExt, StreamExt};
use harness::{Server, TestClient};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const BEAT: Duration = Duration::from_millis(1500);

/// Asks a relay to tunnel somewhere, and reports what it did.
///
/// A refusal is a *positive* signal — the relay closes with a stated reason —
/// which is what makes these tests meaningful. The tunnel is now a byte stream,
/// so an accepted tunnel simply says nothing until something is sent through
/// it; asserting on silence alone would pass against a relay that had stopped
/// working entirely.
async fn tunnel_outcome(relay: &Server, target: &str) -> Outcome {
	let client = TestClient::new();
	let mut client = client
		.connect(&format!("{}/relay", relay.ws_url()))
		.await
		.expect("the relay should complete a handshake");

	client.send_text(target).await.expect("send target");

	match client.recv_raw(BEAT).await {
		Some(Message::Close(frame)) => Outcome::Refused(
			frame
				.map(|f| f.reason.to_string())
				.unwrap_or_else(|| "closed".into()),
		),
		Some(_) => Outcome::Carried,
		None => Outcome::Open,
	}
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
	Refused(String),
	/// Sent something back, so the far end was reached.
	Carried,
	/// Held open, awaiting bytes. What an accepted tunnel looks like before
	/// anything is written to it.
	Open,
}

impl Outcome {
	fn refused(&self) -> bool {
		matches!(self, Outcome::Refused(_))
	}
}

/// The control for every refusal below: a genuine Veil host is *not* refused.
///
/// Without this, "the relay refused" would be satisfied by a relay that refused
/// everything, and every test in this file would pass against one that had
/// stopped tunnelling at all.
#[tokio::test]
async fn a_tunnel_to_a_veil_host_is_not_refused() {
	let destination = Server::start().await;
	let relay = Server::start().await;

	let outcome = tunnel_outcome(&relay, &format!("127.0.0.1:{}", destination.port)).await;
	assert!(
		!outcome.refused(),
		"a genuine veil host should be reachable through the relay, got {outcome:?}"
	);

	relay.stop().await;
	destination.stop().await;
}

/// The second constraint (§3.2): the tunnel carries TLS, and nothing else.
///
/// The control for this one cannot live here, and it is worth saying why. A
/// synthetic TLS record forwarded to a plaintext Veil host makes that host hang
/// up, so the tunnel closes either way and the test could not tell the relay's
/// refusal from the destination's. The honest control is a real nested TLS
/// session that works end to end, which is
/// `veil-client/tests/relay.rs::a_message_survives_a_nested_tls_tunnel`.
///
/// The destination check alone does not close this. A genuine Veil host is a
/// legitimate destination, so without framing validation the tunnel could be
/// opened to one and then used to speak whatever the client liked to it — which
/// is the open-proxy vector wearing a disguise.
#[tokio::test]
async fn a_tunnel_that_carries_something_other_than_tls_is_cut_off() {
	let destination = Server::start().await;
	let relay = Server::start().await;

	let client = TestClient::new();
	let mut client = client
		.connect(&format!("{}/relay", relay.ws_url()))
		.await
		.unwrap();
	client
		.send_text(&format!("127.0.0.1:{}", destination.port))
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	// Plain HTTP down a tunnel to a real Veil host.
	client
		.send_raw(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec())
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	assert!(
		!client.is_connected().await,
		"a tunnel carrying something that is not TLS must be closed"
	);

	relay.stop().await;
	destination.stop().await;
}

/// The load-bearing check: a relay that can be pointed at a web server is an
/// open proxy, and the operator's IP is the one that gets blocklisted.
#[tokio::test]
async fn a_tunnel_to_a_plain_http_server_is_refused() {
	let relay = Server::start().await;

	// Something that speaks HTTP but not WebSockets.
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	tokio::spawn(async move {
		while let Ok((mut socket, _)) = listener.accept().await {
			use tokio::io::AsyncWriteExt;
			let _ = socket
				.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi")
				.await;
		}
	});

	assert!(
		tunnel_outcome(&relay, &format!("127.0.0.1:{port}"))
			.await
			.refused(),
		"the relay must not forward to something that is not a veil host"
	);

	relay.stop().await;
}

/// The case the challenge check exists for: a real WebSocket server that simply
/// is not a veil host. It would satisfy any check that stopped at the transport.
#[tokio::test]
async fn a_tunnel_to_a_websocket_that_is_not_a_veil_host_is_refused() {
	let relay = Server::start().await;

	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	tokio::spawn(async move {
		while let Ok((socket, _)) = listener.accept().await {
			tokio::spawn(async move {
				if let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await {
					// A well-formed frame that is not a signed challenge.
					let _ = ws.send(Message::Binary(vec![0u8; 64].into())).await;
					while ws.next().await.is_some() {}
				}
			});
		}
	});

	assert!(
		tunnel_outcome(&relay, &format!("127.0.0.1:{port}"))
			.await
			.refused(),
		"speaking WebSocket is not the same as being a veil host"
	);

	relay.stop().await;
}

/// The narrow case the *challenge* check catches, as distinct from the envelope
/// check: a destination that produces a perfectly valid signed Veil envelope
/// which simply is not a challenge.
///
/// Worth its own test because the two refusals above both fail earlier, at
/// envelope parsing — deleting the challenge check on its own left them green.
#[tokio::test]
async fn a_tunnel_to_a_host_that_does_not_open_with_a_challenge_is_refused() {
	let relay = Server::start().await;

	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	tokio::spawn(async move {
		while let Ok((socket, _)) = listener.accept().await {
			tokio::spawn(async move {
				if let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await {
					// Genuinely signed, genuinely a veil envelope — and the
					// wrong message to open a session with.
					let account = vodozemac::olm::Account::new();
					let framed = veil_protocol::Envelope::seal(
						&veil_protocol::ProtocolMessage::RemainingOneTimeKeys(7),
						&account,
					)
					.unwrap();
					let _ = ws.send(Message::Binary(framed.to_vec().into())).await;
					while ws.next().await.is_some() {}
				}
			});
		}
	});

	assert!(
		tunnel_outcome(&relay, &format!("127.0.0.1:{port}"))
			.await
			.refused(),
		"a valid envelope is not a challenge; the relay must still refuse"
	);

	relay.stop().await;
}

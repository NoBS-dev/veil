//! The relay's anti-open-proxy checks — `DESIGN.md` §3.2.
//!
//! A server that opens connections to arbitrary destinations on a user's behalf
//! and cannot inspect the traffic *is* an open proxy. These tests exist because
//! that is the property most likely to be quietly lost in a refactor: the tunnel
//! would keep working, and only the refusals would stop happening.

mod harness;

use futures::{SinkExt, StreamExt};
use harness::{Server, TestClient};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

const BEAT: Duration = Duration::from_millis(1500);

/// Asks a relay to tunnel somewhere, returning whether it agreed.
async fn tunnel_accepted(relay: &Server, target: &str) -> bool {
	let client = TestClient::new();
	let mut client = client
		.connect(&format!("{}/relay", relay.ws_url()))
		.await
		.expect("the relay should complete a handshake");

	client.send_text(target).await.expect("send target");

	// A relay that agrees forwards the destination's opening challenge.
	matches!(
		client.recv_raw(BEAT).await,
		Some(Message::Binary(bytes)) if veil_protocol::open_envelope(&bytes).is_ok()
	)
}

#[tokio::test]
async fn a_tunnel_to_a_veil_host_is_established() {
	let destination = Server::start().await;
	let relay = Server::start().await;

	assert!(
		tunnel_accepted(&relay, &format!("127.0.0.1:{}", destination.port)).await,
		"a genuine veil host should be reachable through the relay"
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
		!tunnel_accepted(&relay, &format!("127.0.0.1:{port}")).await,
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
		!tunnel_accepted(&relay, &format!("127.0.0.1:{port}")).await,
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
		!tunnel_accepted(&relay, &format!("127.0.0.1:{port}")).await,
		"a valid envelope is not a challenge; the relay must still refuse"
	);

	relay.stop().await;
}

/// A message sent through a tunnel must arrive, or the relay is only safe
/// because it is useless.
#[tokio::test]
async fn a_message_survives_the_round_trip_through_a_relay() {
	let destination = Server::start().await;
	let relay = Server::start().await;

	// Bob is connected directly to the destination.
	let mut bob = TestClient::new()
		.connect(&destination.ws_url())
		.await
		.unwrap();
	bob.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// Alice reaches the same destination through the relay, and from the
	// destination's point of view is an ordinary client.
	let mut alice = TestClient::new()
		.connect_via_relay(&relay.ws_url(), &format!("127.0.0.1:{}", destination.port))
		.await
		.unwrap();
	alice.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let (_, bob_x25519, otk) = harness::prekey_bundle(&destination.http_url(), &bob.address())
		.await
		.unwrap();
	alice
		.send_to(bob.address(), bob_x25519, otk, "through the tunnel")
		.await
		.unwrap();

	let received = loop {
		match bob.recv(BEAT).await {
			Some(veil_protocol::ProtocolMessage::EncryptedMessage(msg)) => break Some(msg),
			Some(_) => continue,
			None => break None,
		}
	};

	let message = received.expect("bob should receive the relayed message");
	assert_eq!(bob.decrypt(&message).unwrap(), "through the tunnel");

	relay.stop().await;
	destination.stop().await;
}

//! Call signalling — `DESIGN.md` §9.
//!
//! A two-person call needs no new cryptography: WebRTC's DTLS-SRTP is already
//! end to end, and what would make it forgeable is unauthenticated signalling.
//! So the property worth testing is not the media — there is none — but that the
//! host carries setup it cannot read, cannot attribute to somebody else, and
//! does not store.
//!
//! That last one matters more than it looks. A stored offer delivered an hour
//! later is an invitation to a call nobody is on, and it would ring.

mod harness;

use harness::{Server, TestClient};
use std::time::Duration;
use veil_protocol::{CallSignal, ProtocolMessage};

const BEAT: Duration = Duration::from_millis(1500);
const PATIENCE: Duration = Duration::from_secs(20);

fn signal(
	from: &TestClient,
	to: veil_protocol::identity::DeviceAddress,
	body: &[u8],
) -> ProtocolMessage {
	ProtocolMessage::CallSignal(CallSignal {
		call: [7u8; 16],
		sender: from.address(),
		recipient: to,
		sender_x25519: from.account.curve25519_key().to_bytes(),
		message_type: 0,
		message: body.to_vec(),
	})
}

async fn next_signal(client: &mut TestClient, patience: Duration) -> Option<CallSignal> {
	let deadline = tokio::time::Instant::now() + patience;
	loop {
		match client.recv(BEAT).await {
			Some(ProtocolMessage::CallSignal(signal)) => return Some(signal),
			Some(_) => continue,
			None if tokio::time::Instant::now() < deadline => continue,
			None => return None,
		}
	}
}

#[tokio::test]
async fn a_signal_reaches_the_other_device() {
	let server = Server::start().await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	alice
		.send(&signal(&alice, bob.address(), b"an offer, encrypted"))
		.await
		.unwrap();

	let received = next_signal(&mut bob, PATIENCE)
		.await
		.expect("bob should receive the offer");
	assert_eq!(received.sender, alice.address());
	assert_eq!(received.message, b"an offer, encrypted");

	server.stop().await;
}

/// The host carries setup it cannot read. The payload is Olm ciphertext, so
/// nothing about the negotiation is visible to it — which is what lets a call
/// run through a host nobody trusts.
#[tokio::test]
async fn the_host_stores_nothing_and_reads_nothing() {
	let server = Server::start().await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let secret = b"a distinctive fingerprint value";
	alice
		.send(&signal(&alice, bob.address(), secret))
		.await
		.unwrap();
	assert!(next_signal(&mut bob, PATIENCE).await.is_some());
	tokio::time::sleep(BEAT).await;

	let mut raw = std::fs::read(&server.db).unwrap();
	if let Ok(wal) = std::fs::read(format!("{}-wal", server.db)) {
		raw.extend_from_slice(&wal);
	}
	assert!(
		!raw.windows(secret.len()).any(|w| w == secret),
		"call signalling must not be stored by the host"
	);

	server.stop().await;
}

/// Not queued for an absent device, deliberately. An offer delivered later is an
/// invitation to a call nobody is on — and it would ring.
#[tokio::test]
async fn a_signal_for_an_absent_device_is_dropped_rather_than_queued() {
	let server = Server::start().await;

	let bob_identity = TestClient::new();
	let bob_address = bob_identity.address();
	let mut bob = bob_identity.connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let bob = bob.disconnect();
	tokio::time::sleep(BEAT).await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	alice
		.send(&signal(&alice, bob_address, b"an offer nobody will answer"))
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	// A DM to the same absent device, which *is* queued. That is the control:
	// it proves the mailbox is working, so an empty one afterwards is about
	// signalling rather than about nothing being stored at all.
	let (_, bob_x25519, otk) = harness::prekey_bundle(&server.http_url(), &bob_address)
		.await
		.unwrap();
	alice
		.send_to(bob_address, bob_x25519, otk, "a message, which does wait")
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	// Bob returns to exactly one queued frame. Counting *frames* rather than
	// decrypted messages is the point: a queued call signal would not decrypt as
	// a message, so a test that looked only at messages would not notice it.
	let mut bob = bob.connect(&server.ws_url()).await.unwrap();
	let queued = bob.mail_frames(BEAT).await;
	assert_eq!(
		queued.len(),
		1,
		"exactly the message should be waiting; a call signal must not be: {queued:?}"
	);
	assert!(
		matches!(queued[0], ProtocolMessage::EncryptedMessage(_)),
		"and the one waiting should be the message: {queued:?}"
	);

	server.stop().await;
}

/// A device cannot signal as somebody else — the same rule as a message
/// (invariant 1). Without it, anyone could make a phone ring with another
/// person's name on it.
#[tokio::test]
async fn a_device_cannot_signal_as_somebody_else() {
	let server = Server::start().await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// Mallory sends, claiming to be Alice.
	mallory
		.send(&ProtocolMessage::CallSignal(CallSignal {
			call: [7u8; 16],
			sender: alice.address(),
			recipient: bob.address(),
			sender_x25519: mallory.account.curve25519_key().to_bytes(),
			message_type: 0,
			message: b"ring ring".to_vec(),
		}))
		.await
		.unwrap();

	// Then an honest one, immediately after. Asserting on *order* rather than on
	// silence is what makes this deterministic: if the forged signal were
	// forwarded it would arrive first, and waiting a moment for "nothing" would
	// pass whether or not it had been sent.
	mallory
		.send(&signal(&mallory, bob.address(), b"honestly mine"))
		.await
		.unwrap();

	let received = next_signal(&mut bob, PATIENCE)
		.await
		.expect("the honest signal should arrive");
	assert_eq!(
		received.sender,
		mallory.address(),
		"the first signal to arrive must be the honest one — a forged sender was \
		 forwarded ahead of it"
	);
	assert_eq!(received.message, b"honestly mine");

	// And nothing else follows it.
	assert!(
		next_signal(&mut bob, Duration::ZERO).await.is_none(),
		"only one signal should have been forwarded"
	);

	server.stop().await;
}

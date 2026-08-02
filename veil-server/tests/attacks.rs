//! Attacks, mounted for real against a running server.
//!
//! Each test performs the attack and asserts it fails. That is a deliberately
//! different thing from asserting that a check exists: a check can be present
//! and bypassed, and every one of these was written by first confirming it
//! *succeeds* when the corresponding defence is removed.
//!
//! Where a defence is listed as a security invariant in `CLAUDE.md`, the attack
//! it closes should be here.

mod harness;

use harness::{Server, TestClient, prekey_bundle};
use std::time::Duration;
use veil_protocol::{
	EncryptedMessage, ProtocolMessage,
	identity::{DeviceAddress, DeviceId},
	message::{MessageId, random_nonce},
	version::VersionRange,
};

const BEAT: Duration = Duration::from_millis(1500);

/// Reads until an encrypted message arrives, or gives up.
async fn next_message(client: &mut TestClient, within: Duration) -> Option<EncryptedMessage> {
	loop {
		match client.recv(within).await {
			Some(ProtocolMessage::EncryptedMessage(msg)) => return Some(msg),
			Some(_) => continue,
			None => return None,
		}
	}
}

/// Captured traffic is signed and stays signed. Only freshness stops it being
/// re-sent, which is what `ReplayGuard` is for.
#[tokio::test]
async fn a_captured_message_cannot_be_replayed() {
	let server = Server::start().await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(10).await.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let (_, bob_x25519, otk) = prekey_bundle(&server.http_url(), &bob.address())
		.await
		.unwrap();
	let message = alice
		.compose(bob.address(), bob_x25519, otk, "sent once")
		.unwrap();
	let frame = alice.frame(&message).unwrap();

	// Sent legitimately.
	alice.send_raw(frame.clone()).await.unwrap();
	assert!(
		next_message(&mut bob, BEAT).await.is_some(),
		"the genuine send should arrive"
	);

	// The very same bytes again.
	alice.send_raw(frame).await.unwrap();
	assert!(
		next_message(&mut bob, BEAT).await.is_none(),
		"a replayed frame must not be routed a second time"
	);

	server.stop().await;
}

/// Signatures cover the payload, so editing it must invalidate them.
#[tokio::test]
async fn a_tampered_frame_is_discarded() {
	let server = Server::start().await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(10).await.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let (_, bob_x25519, otk) = prekey_bundle(&server.http_url(), &bob.address())
		.await
		.unwrap();
	let message = alice
		.compose(bob.address(), bob_x25519, otk, "original")
		.unwrap();
	let mut frame = alice.frame(&message).unwrap();

	// Flip a bit somewhere in the middle of the payload.
	let middle = frame.len() / 2;
	frame[middle] ^= 0x01;

	alice.send_raw(frame).await.unwrap();
	assert!(
		next_message(&mut bob, BEAT).await.is_none(),
		"a frame whose signature no longer matches must not be routed"
	);

	server.stop().await;
}

/// A client may not put someone else's address in the sender field: the server
/// checks it against the device that authenticated on that connection.
#[tokio::test]
async fn a_client_cannot_forge_the_sender_of_a_message() {
	let server = Server::start().await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(10).await.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let (_, bob_x25519, otk) = prekey_bundle(&server.http_url(), &bob.address())
		.await
		.unwrap();

	// Mallory composes a message and claims it came from Alice. The envelope is
	// signed by Mallory's own device — she cannot forge Alice's signature — but
	// the payload names Alice.
	let mut message = mallory
		.compose(bob.address(), bob_x25519, otk, "alice would never")
		.unwrap();
	if let ProtocolMessage::EncryptedMessage(ref mut msg) = message {
		msg.sender = alice.address();
	}

	mallory
		.send_raw(mallory.frame(&message).unwrap())
		.await
		.unwrap();

	assert!(
		next_message(&mut bob, BEAT).await.is_none(),
		"a message whose sender disagrees with the authenticated connection must be dropped"
	);

	server.stop().await;
}

/// A device may not clear mail addressed to another device. Ids are row
/// numbers, so guessing them must achieve nothing.
#[tokio::test]
async fn a_client_cannot_acknowledge_another_devices_mail() {
	let server = Server::start().await;

	// Bob receives mail while away.
	let bob = TestClient::new();
	let bob_address = bob.address();
	let mut bob_session = bob.connect(&server.ws_url()).await.unwrap();
	bob_session.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let bob = bob_session.disconnect();
	tokio::time::sleep(BEAT).await;

	let (_, bob_x25519, otk) = prekey_bundle(&server.http_url(), &bob_address)
		.await
		.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	alice
		.send_to(bob_address, bob_x25519, otk, "for bob only")
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	// Mallory guesses the low row numbers.
	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	for id in 1..=20 {
		mallory.acknowledge(id).await.unwrap();
	}
	tokio::time::sleep(BEAT).await;

	// Bob's mail is untouched.
	let mut bob = bob.connect(&server.ws_url()).await.unwrap();
	assert_eq!(
		bob.collect_mail(BEAT).await,
		vec!["for bob only".to_owned()],
		"another device's acknowledgements must not clear this mailbox"
	);

	server.stop().await;
}

/// A captured key upload replayed later must not resurrect one-time keys that
/// have since been handed out.
#[tokio::test]
async fn a_replayed_key_upload_cannot_resurrect_consumed_keys() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	let upload = alice.compose_upload(2);
	let captured = alice.frame(&upload).unwrap();
	alice.send_raw(captured.clone()).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// Drain the pool.
	let first = prekey_bundle(&server.http_url(), &alice.address())
		.await
		.unwrap();
	let second = prekey_bundle(&server.http_url(), &alice.address())
		.await
		.unwrap();
	let exhausted = prekey_bundle(&server.http_url(), &alice.address())
		.await
		.unwrap();
	assert_ne!(first.2, second.2);

	// Replay the upload, which lists both consumed keys.
	alice.send_raw(captured.clone()).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let after = prekey_bundle(&server.http_url(), &alice.address())
		.await
		.unwrap();
	assert_eq!(
		after.2, exhausted.2,
		"the pool should still be exhausted; a replayed upload refilled it"
	);

	// The replay guard is per-process, so a restart wipes the memory of that
	// nonce. What stops the same replay afterwards is the store's rule that an
	// upload must advance the clock — a separate defence, and the only one left
	// standing here.
	let db = server.db.clone();
	server.stop_keeping_data().await;
	tokio::time::sleep(BEAT).await;
	let restarted = Server::start_with_db(Some(db.clone())).await;

	let mut alice = alice
		.disconnect()
		.connect(&restarted.ws_url())
		.await
		.unwrap();
	alice.send_raw(captured).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let after_restart = prekey_bundle(&restarted.http_url(), &alice.address())
		.await
		.unwrap();
	assert_eq!(
		after_restart.2, exhausted.2,
		"a captured upload replayed after a restart refilled the pool"
	);

	restarted.stop_keeping_data().await;
	harness::Server::discard(&db);
}

/// A client may not put an envelope somebody else signed on its own connection.
///
/// The signature proves who *wrote* a frame, not who *sent* it. The sender-field
/// check alone does not cover this: the frame here names Mallory as the sender,
/// so that check passes, and only comparing the envelope's signer against the
/// key that authenticated this connection catches it.
///
/// It matters because the recipient pins device keys from the envelope signer.
/// A frame that says "from Mallory" but is signed by Alice's key would have Bob
/// pin Alice's key for Mallory's address.
#[tokio::test]
async fn a_client_cannot_forward_an_envelope_signed_by_someone_else() {
	let server = Server::start().await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(10).await.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let (_, bob_x25519, otk) = prekey_bundle(&server.http_url(), &bob.address())
		.await
		.unwrap();

	// Alice signs a frame that names *Mallory* as its sender, and never sends
	// it. Fresh, so the replay guard has no reason to object.
	let mut message = alice
		.compose(
			bob.address(),
			bob_x25519,
			otk,
			"signed by alice, sent by mallory",
		)
		.unwrap();
	if let ProtocolMessage::EncryptedMessage(ref mut msg) = message {
		msg.sender = mallory.address();
	}
	let alices_frame = alice.frame(&message).unwrap();

	// Mallory puts it on her own connection. The sender field matches her, so
	// only the signer check stands between this and delivery.
	mallory.send_raw(alices_frame).await.unwrap();

	assert!(
		next_message(&mut bob, BEAT).await.is_none(),
		"an envelope signed by another device must not be accepted on this connection"
	);

	server.stop().await;
}

/// The version range is echoed back and checked, so an attacker rewriting the
/// challenge in flight cannot force both sides onto an older version.
#[tokio::test]
async fn a_downgraded_version_negotiation_is_refused() {
	let server = Server::start().await;

	// The client reports having seen a range the server never advertised, which
	// is what a rewritten challenge would look like.
	let mut liar = TestClient::new()
		.connect_with(&server.ws_url(), |mut claim| {
			claim.server_versions_seen = VersionRange::new(1, 1);
			claim.versions = VersionRange::new(1, 1);
			claim.server_versions_seen.max = 99;
			claim
		})
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	assert!(
		harness::connected_devices(&server.http_url())
			.await
			.unwrap()
			.is_empty(),
		"a handshake whose transcript does not match must not be admitted"
	);
	let _ = &mut liar;

	server.stop().await;
}

/// The prekey endpoint must not invent material for a device that was never
/// enrolled — a peer would otherwise open a session with whatever it was given.
#[tokio::test]
async fn the_server_will_not_invent_a_device() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let invented = DeviceAddress::new(alice.user(), DeviceId::generate());
	assert!(prekey_bundle(&server.http_url(), &invented).await.is_err());

	// Nor for a user that does not exist at all.
	let stranger = TestClient::new();
	assert!(
		prekey_bundle(&server.http_url(), &stranger.address())
			.await
			.is_err()
	);

	server.stop().await;
}

/// A message addressed to a device other than the recipient's own must not be
/// delivered to them, even if they are connected.
#[tokio::test]
async fn a_message_is_not_delivered_to_the_wrong_device() {
	let server = Server::start().await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(10).await.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// Addressed to a device of Bob's that does not exist.
	let phantom = DeviceAddress::new(bob.user(), DeviceId::generate());
	alice
		.send(&ProtocolMessage::EncryptedMessage(EncryptedMessage {
			sender: alice.address(),
			recipient: phantom,
			sender_x25519: [0; 32],
			nonce: random_nonce(),
			origin_ts: 0,
			seen_head: MessageId::ROOT,
			message_type: 0,
			message: vec![1, 2, 3],
		}))
		.await
		.unwrap();

	assert!(
		next_message(&mut bob, BEAT).await.is_none(),
		"a message for another device of the same user must not reach this one"
	);

	server.stop().await;
}

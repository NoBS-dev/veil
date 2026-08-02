//! End-to-end tests against a real server process.
//!
//! These replace checks that were previously done by hand: they proved the
//! behaviour once and protected nothing afterwards.

mod harness;

use harness::{Server, TestClient, prekey_bundle};
use std::time::Duration;
use veil_protocol::{
	ProtocolMessage,
	identity::{DeviceAddress, DeviceId},
};

const BEAT: Duration = Duration::from_millis(1500);

#[tokio::test]
async fn a_verified_device_is_admitted_and_published() {
	let server = Server::start().await;

	let alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	let mut alice = alice;
	alice.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// The directory now vouches for the device, and its entry chains up to the
	// user id through cross-signing.
	let body: serde_json::Value = reqwest::get(format!(
		"{}/users/{}/devices",
		server.http_url(),
		alice.user()
	))
	.await
	.unwrap()
	.json()
	.await
	.unwrap();

	assert_eq!(body["devices"].as_array().unwrap().len(), 1);
	assert_eq!(body["user"], alice.user().to_string());

	server.stop().await;
}

/// A device may not claim a user it cannot prove it belongs to. Master keys are
/// public, so quoting one is not evidence of anything (§5.4).
///
/// The assertion is that the victim keeps receiving their own mail. Two weaker
/// versions of this test passed with the chain check deleted, and both are worth
/// remembering:
///
/// - "no message arrives for the impostor" — a server says nothing after a
///   *successful* handshake either, so silence proves nothing;
/// - "the roster does not grow" — the impostor claims the victim's device id,
///   so admitting her *replaces* the victim's routing entry rather than adding
///   one, and the count is identical either way.
///
/// The attack is takeover, so the test has to look for takeover.
#[tokio::test]
async fn a_device_claiming_someone_elses_identity_cannot_take_over_their_mail() {
	let server = Server::start().await;

	let mut victim = TestClient::new().connect(&server.ws_url()).await.unwrap();
	victim.upload_keys(5).await.unwrap();
	let victim_address = victim.address();
	let victim_keys = victim.cross_signing.public();
	tokio::time::sleep(BEAT).await;

	// Mallory presents the victim's user id, device id and public key set — all
	// of which are public — but can only sign the binding with her own key.
	let mut mallory = TestClient::new()
		.connect_with(&server.ws_url(), move |mut claim| {
			claim.user = victim_address.user;
			claim.device = victim_address.device;
			claim.keys = victim_keys;
			claim
		})
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	// Someone writes to the victim.
	let (_, victim_x25519, otk) = prekey_bundle(&server.http_url(), &victim_address)
		.await
		.unwrap();
	let mut carol = TestClient::new().connect(&server.ws_url()).await.unwrap();
	carol.upload_keys(5).await.unwrap();
	carol
		.send_to(victim_address, victim_x25519, otk, "for the victim")
		.await
		.unwrap();

	// The victim must still be the one who gets it.
	let delivered = loop {
		match victim.recv(BEAT).await {
			Some(ProtocolMessage::EncryptedMessage(msg)) => break Some(msg),
			Some(_) => continue,
			None => break None,
		}
	};
	let delivered = delivered
		.expect("the victim should still hold their own routing slot; an impostor took it over");
	assert_eq!(victim.decrypt(&delivered).unwrap(), "for the victim");

	// And the impostor should have received nothing at all.
	assert!(
		mallory.recv(Duration::from_millis(500)).await.is_none(),
		"the impostor received traffic addressed to the victim"
	);

	server.stop().await;
}

#[tokio::test]
async fn a_message_reaches_a_connected_device() {
	let server = Server::start().await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(10).await.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let (_, bob_x25519, otk) = prekey_bundle(&server.http_url(), &bob.address())
		.await
		.unwrap();
	alice
		.send_to(bob.address(), bob_x25519, otk, "hello bob")
		.await
		.unwrap();

	let received = loop {
		match bob.recv(BEAT).await {
			Some(ProtocolMessage::EncryptedMessage(msg)) => break Some(msg),
			Some(_) => continue, // OTK notifications and the like
			None => break None,
		}
	};

	let message = received.expect("bob should have received something");
	assert_eq!(bob.decrypt(&message).unwrap(), "hello bob");

	server.stop().await;
}

/// The gap the mailbox exists to close: before it, this message was dropped.
#[tokio::test]
async fn a_message_for_an_offline_device_waits_for_it() {
	let server = Server::start().await;

	// Bob connects, publishes keys, then leaves.
	let bob_identity = TestClient::new();
	let bob_address = bob_identity.address();
	let mut bob = bob_identity.connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let bob = bob.disconnect();
	tokio::time::sleep(BEAT).await;

	let (_, bob_x25519, otk) = prekey_bundle(&server.http_url(), &bob_address)
		.await
		.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	alice
		.send_to(bob_address, bob_x25519, otk, "sent while you were away")
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	// Bob returns as the same device and is offered what he missed.
	let mut bob = bob.connect(&server.ws_url()).await.unwrap();

	let mail = bob.collect_mail(BEAT).await;
	assert_eq!(mail, vec!["sent while you were away".to_owned()]);

	server.stop().await;
}

/// §12.2: sending is not receiving. A client that never acknowledges must be
/// offered the same mail again rather than losing it.
#[tokio::test]
async fn unacknowledged_mail_is_offered_again() {
	let server = Server::start().await;

	let bob_identity = TestClient::new();
	let bob_address = bob_identity.address();
	let mut bob = bob_identity.connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let bob = bob.disconnect();
	tokio::time::sleep(BEAT).await;

	let (_, bob_x25519, otk) = prekey_bundle(&server.http_url(), &bob_address)
		.await
		.unwrap();
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	alice
		.send_to(bob_address, bob_x25519, otk, "never acknowledged")
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	// Bob connects and leaves without acknowledging.
	let mut session = bob.connect(&server.ws_url()).await.unwrap();
	let first = session.peek_mail(BEAT).await;
	assert_eq!(first.len(), 1, "mail should be offered on connect");
	let bob = session.disconnect();
	tokio::time::sleep(BEAT).await;

	// It is still there, because he never said he had it.
	let mut session = bob.connect(&server.ws_url()).await.unwrap();
	let second = session.peek_mail(BEAT).await;
	assert_eq!(
		second, first,
		"unacknowledged mail must be offered again, not dropped on send"
	);

	// Reconnect to be offered it again, and this time acknowledge.
	let bob = session.disconnect();
	tokio::time::sleep(BEAT).await;
	let mut session = bob.connect(&server.ws_url()).await.unwrap();
	let mail = session.collect_mail(BEAT).await;
	assert_eq!(mail, vec!["never acknowledged".to_owned()]);
	let bob = session.disconnect();
	tokio::time::sleep(BEAT).await;

	let mut session = bob.connect(&server.ws_url()).await.unwrap();
	assert!(
		session.peek_mail(BEAT).await.is_empty(),
		"acknowledged mail must not be offered again"
	);

	server.stop().await;
}

#[tokio::test]
async fn the_key_directory_survives_a_restart() {
	let server = Server::start().await;
	let db = server.db.clone();
	let db_for_cleanup = db.clone();

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	let alice_user = alice.user();
	alice.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;
	server.stop_keeping_data().await;
	tokio::time::sleep(BEAT).await;

	// Same database, cold process.
	let restarted = Server::start_with_db(Some(db)).await;
	let body: serde_json::Value = reqwest::get(format!(
		"{}/users/{alice_user}/devices",
		restarted.http_url()
	))
	.await
	.unwrap()
	.json()
	.await
	.unwrap();

	assert_eq!(
		body["devices"].as_array().unwrap().len(),
		1,
		"the device should still be published after a restart"
	);

	restarted.stop_keeping_data().await;
	harness::Server::discard(&db_for_cleanup);
}

#[tokio::test]
async fn a_prekey_bundle_is_unavailable_for_an_unknown_device() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(10).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// A device the user never enrolled.
	let invented = DeviceAddress::new(alice.user(), DeviceId::generate());
	assert!(
		prekey_bundle(&server.http_url(), &invented).await.is_err(),
		"the server must not invent a bundle for a device that does not exist"
	);

	server.stop().await;
}

/// One-time keys are consumed, then exhaustion degrades to the fallback rather
/// than failing.
#[tokio::test]
async fn one_time_keys_are_consumed_and_then_degrade() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(2).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let first = prekey_bundle(&server.http_url(), &alice.address())
		.await
		.unwrap();
	let second = prekey_bundle(&server.http_url(), &alice.address())
		.await
		.unwrap();
	assert_ne!(
		first.2, second.2,
		"each request should consume a distinct key"
	);

	// Pool exhausted: still answers, with the fallback.
	let third = prekey_bundle(&server.http_url(), &alice.address())
		.await
		.unwrap();
	let fourth = prekey_bundle(&server.http_url(), &alice.address())
		.await
		.unwrap();
	assert_eq!(
		third.2, fourth.2,
		"past exhaustion the same fallback key is served rather than failing"
	);

	server.stop().await;
}

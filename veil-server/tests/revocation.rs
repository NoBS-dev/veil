//! Device revocation — `DESIGN.md` §5.6.
//!
//! The case this exists for is a device already out of your hands, so nothing
//! here can involve asking that device to cooperate. What makes it work is that
//! the retired flag is inside the signature the owner's self-signing key makes:
//! a host can neither retire somebody's device nor refuse to believe a
//! retirement, because every client checks the same signature itself.

mod harness;

use harness::{Server, TestClient};
use std::time::Duration;
use veil_protocol::{ProtocolMessage, RevokeDevice, identity::Device};

const BEAT: Duration = Duration::from_millis(1500);

/// The devices a host is serving for a user, as anyone would fetch them.
async fn published(server: &Server, user: &veil_protocol::identity::UserId) -> Vec<Device> {
	let body: serde_json::Value =
		reqwest::get(format!("{}/users/{user}/devices", server.http_url()))
			.await
			.unwrap()
			.json()
			.await
			.unwrap();

	serde_json::from_value(body["devices"].clone()).unwrap_or_default()
}

#[tokio::test]
async fn a_retired_device_stops_being_usable() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// The control first: before retirement it verifies as an active device.
	let keys = alice.cross_signing.public();
	let before = keys
		.verify_device_list(&alice.user(), &published(&server, &alice.user()).await)
		.unwrap();
	assert_eq!(before.active.len(), 1, "the device should start usable");
	assert!(before.revoked.is_empty());

	let device = alice.address().device;
	let device_key = *alice.account.ed25519_key().as_bytes();
	alice
		.send(&ProtocolMessage::RevokeDevice(RevokeDevice {
			device,
			device_ed25519: device_key,
			signature: alice.cross_signing.revoke_device(&device, &device_key),
		}))
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	let after = keys
		.verify_device_list(&alice.user(), &published(&server, &alice.user()).await)
		.unwrap();
	assert!(
		after.active.is_empty(),
		"a retired device must not be offered as usable"
	);
	assert_eq!(
		after.revoked,
		vec![device],
		"and the retirement must be reported, so peers can remember it"
	);

	server.stop().await;
}

/// A host cannot retire somebody's device for them.
#[tokio::test]
async fn a_revocation_without_the_owners_signature_is_ignored() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let device = alice.address().device;
	let device_key = *alice.account.ed25519_key().as_bytes();

	// Signed by somebody else's self-signing key.
	let impostor = veil_protocol::crosssign::CrossSigningSecrets::new();
	alice
		.send(&ProtocolMessage::RevokeDevice(RevokeDevice {
			device,
			device_ed25519: device_key,
			signature: impostor.revoke_device(&device, &device_key),
		}))
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	let after = alice
		.cross_signing
		.public()
		.verify_device_list(&alice.user(), &published(&server, &alice.user()).await)
		.unwrap();
	assert_eq!(
		after.active.len(),
		1,
		"a revocation nobody signed must not retire a device"
	);

	server.stop().await;
}

/// Retirement is monotonic. The signature stops a host forging an un-retirement,
/// but a host replaying an older genuine entry could otherwise bring one back.
#[tokio::test]
async fn a_retired_device_cannot_be_brought_back() {
	let server = Server::start().await;

	let alice_identity = TestClient::new();
	let mut alice = alice_identity.connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let device = alice.address().device;
	let device_key = *alice.account.ed25519_key().as_bytes();
	alice
		.send(&ProtocolMessage::RevokeDevice(RevokeDevice {
			device,
			device_ed25519: device_key,
			signature: alice.cross_signing.revoke_device(&device, &device_key),
		}))
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	// The device reconnects and re-enrols, exactly as a stolen one still holding
	// its keys would.
	let alice = alice.disconnect();
	let mut alice = alice.connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let after = alice
		.cross_signing
		.public()
		.verify_device_list(&alice.user(), &published(&server, &alice.user()).await)
		.unwrap();
	assert!(
		after.active.is_empty(),
		"a retired device must not be able to re-enrol itself"
	);

	server.stop().await;
}

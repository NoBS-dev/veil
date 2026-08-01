//! Cross-signing — `DESIGN.md` §5.4.
//!
//! Three keys per user rather than one, so the master key can stay cold:
//!
//! | Key | Signed by | Signs |
//! | --- | --- | --- |
//! | **MSK** master | self | SSK, USK |
//! | **SSK** self-signing | MSK | this user's own devices |
//! | **USK** user-signing | MSK | *other users'* master keys |
//!
//! Adding a device touches only the SSK; the MSK is needed just to establish or
//! rotate the signing keys themselves.
//!
//! **The payoff is that verification is per person, not per device.** Alice
//! compares safety numbers with Bob once and signs his MSK with her USK. Every
//! device Bob owns is then trusted automatically — including ones he adds
//! later — because his SSK signs his devices and his MSK signs his SSK.
//! Per-device verification does not survive contact with real users.

use crate::identity::{DeviceId, UserId, device_binding_input};
use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as De, Deserializer, Serialize as Ser, Serializer};
use serde_with::serde_as;
use vodozemac::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

const SELF_SIGNING_DOMAIN: &[u8] = b"veil-self-signing-key-v1";
const USER_SIGNING_DOMAIN: &[u8] = b"veil-user-signing-key-v1";
const ATTESTATION_DOMAIN: &[u8] = b"veil-user-attestation-v1";

/// Bytes the master key signs to adopt one of its subkeys.
///
/// Domain-separated per subkey role and bound to the owner, so an SSK signature
/// cannot be replayed as a USK signature, and neither can be lifted onto
/// another user.
fn subkey_input(domain: &[u8], user: &UserId, subkey: &[u8; 32]) -> Vec<u8> {
	let mut buffer = Vec::with_capacity(domain.len() + 16 + 32);
	buffer.extend_from_slice(domain);
	buffer.extend_from_slice(user.as_bytes());
	buffer.extend_from_slice(subkey);
	buffer
}

/// Bytes a user-signing key signs to record "I have verified this person".
fn attestation_input(attester: &UserId, subject: &UserId, subject_master: &[u8; 32]) -> Vec<u8> {
	let mut buffer = Vec::with_capacity(ATTESTATION_DOMAIN.len() + 16 + 16 + 32);
	buffer.extend_from_slice(ATTESTATION_DOMAIN);
	buffer.extend_from_slice(attester.as_bytes());
	buffer.extend_from_slice(subject.as_bytes());
	buffer.extend_from_slice(subject_master);
	buffer
}

fn ser_key<S: Serializer>(key: &Ed25519SecretKey, s: S) -> Result<S::Ok, S::Error> {
	Ser::serialize(&key.to_base64(), s)
}
fn de_key<'a, D: Deserializer<'a>>(d: D) -> Result<Ed25519SecretKey, D::Error> {
	Ed25519SecretKey::from_base64(&String::deserialize(d)?).map_err(serde::de::Error::custom)
}

/// The secret halves. These live only on their owner's devices and never leave.
#[derive(Ser, De)]
pub struct CrossSigningSecrets {
	#[serde(serialize_with = "ser_key", deserialize_with = "de_key")]
	master: Ed25519SecretKey,
	#[serde(serialize_with = "ser_key", deserialize_with = "de_key")]
	self_signing: Ed25519SecretKey,
	#[serde(serialize_with = "ser_key", deserialize_with = "de_key")]
	user_signing: Ed25519SecretKey,
}

impl Default for CrossSigningSecrets {
	fn default() -> Self {
		Self::new()
	}
}

impl CrossSigningSecrets {
	pub fn new() -> Self {
		Self {
			master: Ed25519SecretKey::new(),
			self_signing: Ed25519SecretKey::new(),
			user_signing: Ed25519SecretKey::new(),
		}
	}

	pub fn user_id(&self) -> UserId {
		UserId::from_master_key(&self.master.public_key())
	}

	pub fn master_public(&self) -> [u8; 32] {
		*self.master.public_key().as_bytes()
	}

	/// The publishable half, with the master key's signatures over both subkeys
	/// already attached.
	pub fn public(&self) -> CrossSigningPublic {
		let user = self.user_id();
		let self_signing = *self.self_signing.public_key().as_bytes();
		let user_signing = *self.user_signing.public_key().as_bytes();

		CrossSigningPublic {
			master: self.master_public(),
			self_signing,
			self_signing_signature: self
				.master
				.sign(&subkey_input(SELF_SIGNING_DOMAIN, &user, &self_signing))
				.to_bytes(),
			user_signing,
			user_signing_signature: self
				.master
				.sign(&subkey_input(USER_SIGNING_DOMAIN, &user, &user_signing))
				.to_bytes(),
		}
	}

	/// Enrols a device. Note this uses the **self-signing** key — the master key
	/// is not touched, which is the entire reason for the split.
	pub fn sign_device(&self, device: &DeviceId, device_ed25519: &[u8; 32]) -> [u8; 64] {
		self.self_signing
			.sign(&device_binding_input(
				&self.user_id(),
				device,
				device_ed25519,
			))
			.to_bytes()
	}

	/// Records that we have verified another person, after comparing safety
	/// numbers out of band (§6.1). This is the signature that makes all of
	/// their present and future devices trusted.
	pub fn attest_user(&self, subject: &UserId, subject_master: &[u8; 32]) -> [u8; 64] {
		self.user_signing
			.sign(&attestation_input(&self.user_id(), subject, subject_master))
			.to_bytes()
	}
}

/// A user's published cross-signing keys.
#[serde_as]
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub struct CrossSigningPublic {
	pub master: [u8; 32],
	pub self_signing: [u8; 32],
	/// Master key's signature over the self-signing key.
	#[serde_as(as = "[_; 64]")]
	pub self_signing_signature: [u8; 64],
	pub user_signing: [u8; 32],
	/// Master key's signature over the user-signing key.
	#[serde_as(as = "[_; 64]")]
	pub user_signing_signature: [u8; 64],
}

impl CrossSigningPublic {
	/// Checks the key set is internally consistent and belongs to `user`:
	/// the master key derives the id, and it signed both subkeys.
	///
	/// Everything else in this module assumes this has passed. A subkey the
	/// master never signed is an attacker's subkey.
	pub fn verify(&self, user: &UserId) -> anyhow::Result<()> {
		let master = Ed25519PublicKey::from_slice(&self.master)?;

		if !user.matches(&master) {
			anyhow::bail!("master key does not derive the claimed user id {user}");
		}

		master
			.verify(
				&subkey_input(SELF_SIGNING_DOMAIN, user, &self.self_signing),
				&Ed25519Signature::from_slice(&self.self_signing_signature)?,
			)
			.map_err(|e| {
				anyhow::anyhow!("self-signing key is not signed by the master key: {e}")
			})?;

		master
			.verify(
				&subkey_input(USER_SIGNING_DOMAIN, user, &self.user_signing),
				&Ed25519Signature::from_slice(&self.user_signing_signature)?,
			)
			.map_err(|e| {
				anyhow::anyhow!("user-signing key is not signed by the master key: {e}")
			})?;

		Ok(())
	}

	/// Walks the full chain from a device up to the user id (§5.4):
	///
	/// ```text
	/// device  <-signed by-  SSK  <-signed by-  MSK  ->hashes to->  UserId
	/// ```
	///
	/// Passing means the device genuinely belongs to `user`. It does **not**
	/// mean we have verified that user — that is [`verify_attestation`], and
	/// the two are deliberately separate questions.
	pub fn verify_device(
		&self,
		user: &UserId,
		device: &DeviceId,
		device_ed25519: &[u8; 32],
		signature: &[u8; 64],
	) -> anyhow::Result<()> {
		self.verify(user)?;

		let self_signing = Ed25519PublicKey::from_slice(&self.self_signing)?;
		self_signing
			.verify(
				&device_binding_input(user, device, device_ed25519),
				&Ed25519Signature::from_slice(signature)?,
			)
			.map_err(|e| anyhow::anyhow!("device {device} is not signed by {user}'s SSK: {e}"))?;

		Ok(())
	}

	/// Have *we* verified this person? Checks our own user-signing key's
	/// signature over their master key.
	///
	/// This is the step that turns "this device really belongs to that user"
	/// into "and I know who that user is".
	pub fn verify_attestation(
		our_user_signing: &[u8; 32],
		attester: &UserId,
		subject: &UserId,
		subject_master: &[u8; 32],
		signature: &[u8; 64],
	) -> anyhow::Result<()> {
		Ed25519PublicKey::from_slice(our_user_signing)?
			.verify(
				&attestation_input(attester, subject, subject_master),
				&Ed25519Signature::from_slice(signature)?,
			)
			.map_err(|e| anyhow::anyhow!("no valid attestation for {subject}: {e}"))?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn device() -> (DeviceId, [u8; 32]) {
		(
			DeviceId::generate(),
			*Ed25519SecretKey::new().public_key().as_bytes(),
		)
	}

	#[test]
	fn a_users_own_key_set_verifies() {
		let alice = CrossSigningSecrets::new();
		assert!(alice.public().verify(&alice.user_id()).is_ok());
	}

	#[test]
	fn a_device_enrolled_by_the_ssk_verifies() {
		let alice = CrossSigningSecrets::new();
		let (id, key) = device();
		let signature = alice.sign_device(&id, &key);

		assert!(
			alice
				.public()
				.verify_device(&alice.user_id(), &id, &key, &signature)
				.is_ok()
		);
	}

	/// The point of the split: enrolling a device must not need the master key.
	/// A signature made *by* the master over a device is not a valid device
	/// signature, because verification looks at the SSK.
	#[test]
	fn the_master_key_is_not_accepted_as_a_device_signer() {
		let alice = CrossSigningSecrets::new();
		let (id, key) = device();

		let by_master = alice
			.master
			.sign(&device_binding_input(&alice.user_id(), &id, &key))
			.to_bytes();

		assert!(
			alice
				.public()
				.verify_device(&alice.user_id(), &id, &key, &by_master)
				.is_err()
		);
	}

	/// An attacker who publishes their own subkeys under a victim's user id
	/// fails, because the victim's master key never signed them.
	#[test]
	fn substituted_subkeys_are_rejected() {
		let alice = CrossSigningSecrets::new();
		let mallory = CrossSigningSecrets::new();

		let mut forged = alice.public();
		forged.self_signing = *mallory.self_signing.public_key().as_bytes();

		assert!(forged.verify(&alice.user_id()).is_err());

		// ...and therefore a device Mallory enrols does not verify either.
		let (id, key) = device();
		let signature = mallory.sign_device(&id, &key);
		assert!(
			forged
				.verify_device(&alice.user_id(), &id, &key, &signature)
				.is_err()
		);
	}

	/// Subkey signatures are domain-separated by role, so the SSK's signature
	/// cannot be presented as the USK's.
	#[test]
	fn subkey_roles_are_not_interchangeable() {
		let alice = CrossSigningSecrets::new();
		let mut swapped = alice.public();

		std::mem::swap(&mut swapped.self_signing, &mut swapped.user_signing);
		assert!(swapped.verify(&alice.user_id()).is_err());
	}

	/// A device signature is bound to (user, device, device key), so it cannot
	/// be replayed for a different device or by a different key.
	#[test]
	fn a_device_signature_cannot_be_lifted() {
		let alice = CrossSigningSecrets::new();
		let (id, key) = device();
		let signature = alice.sign_device(&id, &key);
		let public = alice.public();
		let user = alice.user_id();

		let (other_id, other_key) = device();
		assert!(
			public
				.verify_device(&user, &other_id, &key, &signature)
				.is_err()
		);
		assert!(
			public
				.verify_device(&user, &id, &other_key, &signature)
				.is_err()
		);

		// ...and not onto another user either.
		let bob = CrossSigningSecrets::new();
		assert!(
			bob.public()
				.verify_device(&bob.user_id(), &id, &key, &signature)
				.is_err()
		);
	}

	#[test]
	fn a_key_set_cannot_be_lifted_onto_another_user() {
		let alice = CrossSigningSecrets::new();
		let bob = CrossSigningSecrets::new();

		assert!(alice.public().verify(&bob.user_id()).is_err());
	}

	/// The §5.4 payoff, end to end: Alice verifies Bob once, and a device Bob
	/// adds *afterwards* is trusted with no further action from Alice.
	#[test]
	fn verifying_a_person_once_covers_devices_added_later() {
		let alice = CrossSigningSecrets::new();
		let bob = CrossSigningSecrets::new();
		let bob_public = bob.public();

		// Alice compares safety numbers with Bob, then signs his master key.
		let attestation = alice.attest_user(&bob.user_id(), &bob_public.master);
		assert!(
			CrossSigningPublic::verify_attestation(
				&alice.public().user_signing,
				&alice.user_id(),
				&bob.user_id(),
				&bob_public.master,
				&attestation,
			)
			.is_ok()
		);

		// Later — after that verification — Bob enrols a brand new device.
		let (laptop, laptop_key) = device();
		let signature = bob.sign_device(&laptop, &laptop_key);

		// Alice trusts it without re-verifying Bob.
		assert!(
			bob_public
				.verify_device(&bob.user_id(), &laptop, &laptop_key, &signature)
				.is_ok()
		);
	}

	#[test]
	fn an_attestation_does_not_transfer_to_another_person() {
		let alice = CrossSigningSecrets::new();
		let bob = CrossSigningSecrets::new();
		let mallory = CrossSigningSecrets::new();

		let for_bob = alice.attest_user(&bob.user_id(), &bob.public().master);

		// Mallory cannot present Alice's attestation of Bob as one of herself.
		assert!(
			CrossSigningPublic::verify_attestation(
				&alice.public().user_signing,
				&alice.user_id(),
				&mallory.user_id(),
				&mallory.public().master,
				&for_bob,
			)
			.is_err()
		);
	}

	#[test]
	fn secrets_survive_a_keyring_round_trip() {
		let alice = CrossSigningSecrets::new();
		let json = serde_json::to_string(&alice).unwrap();
		let restored: CrossSigningSecrets = serde_json::from_str(&json).unwrap();

		assert_eq!(restored.user_id(), alice.user_id());
		// A device signed before the round trip still verifies after it.
		let (id, key) = device();
		let signature = alice.sign_device(&id, &key);
		assert!(
			restored
				.public()
				.verify_device(&restored.user_id(), &id, &key, &signature)
				.is_ok()
		);
	}
}

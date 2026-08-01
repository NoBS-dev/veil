//! User and device identity — `DESIGN.md` §5.1–5.3.
//!
//! The property this module exists to provide is that **identity is
//! self-certifying**. A `UserId` is derived from its owner's master key, so
//! anyone holding the pair can check they belong together without asking a
//! server. No server can map a `UserId` to key material its owner did not
//! publish, which is what stops a malicious home server or community host from
//! substituting itself for a peer.
//!
//! It also contains no hostname. A user is not welded to the server their
//! account lives on and can move without becoming a different person — the
//! structural problem with Matrix's `@user:server`.

use data_encoding::BASE32_NOPAD;
use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as De, Serialize as Ser};
use sha2::{Digest, Sha256};
use vodozemac::Ed25519PublicKey;

const USER_ID_DOMAIN: &[u8] = b"veil-user-id-v1";
const DEVICE_BINDING_DOMAIN: &[u8] = b"veil-device-binding-v1";

/// Bytes of the truncated digest. 128 bits is far beyond what a collision
/// search could reach, while keeping the rendered form short enough to paste.
const USER_ID_LEN: usize = 16;

/// A user's stable, server-independent identifier.
///
/// Derived from the master key rather than assigned, so it cannot be reassigned
/// by anyone and cannot disagree with the key it names.
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[rkyv(attr(derive(Debug)))]
#[derive(Ser, De)]
pub struct UserId([u8; USER_ID_LEN]);

impl UserId {
	/// `UserId = base32( SHA-256( "veil-user-id-v1" || MSK_public ) )[..16]`
	pub fn from_master_key(master_key: &Ed25519PublicKey) -> Self {
		let mut hasher = Sha256::new();
		hasher.update(USER_ID_DOMAIN);
		hasher.update(master_key.as_bytes());
		let digest = hasher.finalize();

		let mut id = [0u8; USER_ID_LEN];
		id.copy_from_slice(&digest[..USER_ID_LEN]);
		Self(id)
	}

	/// The self-certifying check: does this master key hash to this `UserId`?
	///
	/// Every path that learns a peer's master key from a server must run this
	/// against the `UserId` it already trusted, or the derivation buys nothing.
	pub fn matches(&self, master_key: &Ed25519PublicKey) -> bool {
		// Not constant-time on purpose: both inputs are public values, and an
		// attacker able to supply candidate keys learns nothing from timing that
		// they could not learn by hashing locally.
		*self == Self::from_master_key(master_key)
	}

	pub fn as_bytes(&self) -> &[u8; USER_ID_LEN] {
		&self.0
	}

	pub fn from_bytes(bytes: [u8; USER_ID_LEN]) -> Self {
		Self(bytes)
	}

	pub fn parse(text: &str) -> anyhow::Result<Self> {
		// Uppercase so a hand-typed id is accepted; the alphabet has no
		// lowercase forms to be ambiguous with.
		let bytes = BASE32_NOPAD.decode(text.trim().to_ascii_uppercase().as_bytes())?;
		let bytes: [u8; USER_ID_LEN] = bytes.as_slice().try_into().map_err(|_| {
			anyhow::anyhow!(
				"expected a {}-byte user id, got {} bytes",
				USER_ID_LEN,
				bytes.len()
			)
		})?;
		Ok(Self(bytes))
	}
}

impl std::fmt::Display for UserId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&BASE32_NOPAD.encode(&self.0))
	}
}

/// Identifies one device belonging to a user. Random rather than derived: a
/// device's keys rotate (§5.5) and the id must survive that.
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[rkyv(attr(derive(Debug)))]
#[derive(Ser, De)]
pub struct DeviceId([u8; 16]);

impl DeviceId {
	pub fn generate() -> Self {
		let mut id = [0u8; 16];
		rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
		Self(id)
	}

	pub fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}

	pub fn from_bytes(bytes: [u8; 16]) -> Self {
		Self(bytes)
	}
}

impl std::fmt::Display for DeviceId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&BASE32_NOPAD.encode(&self.0))
	}
}

/// Where a message goes. Sessions are established **device to device**, never
/// user to user, so a message addressed to a user fans out to one of these per
/// active device (§5.2).
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[rkyv(attr(derive(Debug)))]
#[derive(Ser, De)]
pub struct DeviceAddress {
	pub user: UserId,
	pub device: DeviceId,
}

impl DeviceAddress {
	pub fn new(user: UserId, device: DeviceId) -> Self {
		Self { user, device }
	}
}

impl std::fmt::Display for DeviceAddress {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}/{}", self.user, self.device)
	}
}

/// A device as published in its owner's device list.
///
/// **Not yet verifiable.** §5.2 gives this an `ssk_signature` proving the device
/// belongs to the user, and that field arrives with cross-signing (§5.4, Tier 1
/// item 2). Until then, presence in a list is an assertion by whoever served the
/// list — treat it as routing information, never as proof of ownership.
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(attr(derive(Debug)))]
#[derive(Ser, De)]
pub struct Device {
	pub device_id: DeviceId,
	/// Signing key — the device's Olm identity for signature purposes.
	pub ed25519: [u8; 32],
	/// Olm identity key used to establish sessions.
	pub curve25519: [u8; 32],
	pub display_name: String,
	pub created_at: u64,
	pub last_seen: u64,
}

impl Device {
	pub fn address(&self, user: UserId) -> DeviceAddress {
		DeviceAddress::new(user, self.device_id)
	}
}

/// Bytes signed to bind a device to its owner.
///
/// Domain-separated and covering all three of user, device and device key, so a
/// signature cannot be lifted onto a different device or a different user.
///
/// Signed by the user's **self-signing key** (§5.4), not the master key — see
/// `crosssign`. This lives here because it names identity types, not because
/// identity owns the signing policy.
pub fn device_binding_input(
	user: &UserId,
	device: &DeviceId,
	device_ed25519: &[u8; 32],
) -> Vec<u8> {
	let mut buffer = Vec::with_capacity(DEVICE_BINDING_DOMAIN.len() + USER_ID_LEN + 16 + 32);
	buffer.extend_from_slice(DEVICE_BINDING_DOMAIN);
	buffer.extend_from_slice(user.as_bytes());
	buffer.extend_from_slice(device.as_bytes());
	buffer.extend_from_slice(device_ed25519);
	buffer
}

/// A user's published set of devices.
///
/// Held separately from the user's identity so that adding or removing a device
/// never disturbs the `UserId`, which is the whole point of §5.5's split
/// between routine device rotation and disruptive master-key rotation.
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(attr(derive(Debug)))]
#[derive(Ser, De)]
pub struct DeviceList {
	pub user: UserId,
	pub devices: Vec<Device>,
	/// Advanced on every publish so a captured older list cannot be replayed to
	/// resurrect a device its owner has since removed.
	pub updated_at: u64,
}

impl DeviceList {
	pub fn new(user: UserId, updated_at: u64) -> Self {
		Self {
			user,
			devices: Vec::new(),
			updated_at,
		}
	}

	pub fn get(&self, device: &DeviceId) -> Option<&Device> {
		self.devices.iter().find(|d| d.device_id == *device)
	}

	pub fn contains(&self, device: &DeviceId) -> bool {
		self.get(device).is_some()
	}

	/// Adds a device, or replaces an existing entry with the same id so that a
	/// device rotating its keys (§5.5) does not appear twice.
	pub fn upsert(&mut self, device: Device, updated_at: u64) {
		match self
			.devices
			.iter_mut()
			.find(|d| d.device_id == device.device_id)
		{
			Some(existing) => *existing = device,
			None => self.devices.push(device),
		}
		self.updated_at = updated_at;
	}

	pub fn remove(&mut self, device: &DeviceId, updated_at: u64) -> bool {
		let before = self.devices.len();
		self.devices.retain(|d| d.device_id != *device);
		let removed = self.devices.len() != before;
		if removed {
			self.updated_at = updated_at;
		}
		removed
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use vodozemac::Ed25519SecretKey;

	fn master_key() -> Ed25519PublicKey {
		Ed25519SecretKey::new().public_key()
	}

	#[test]
	fn user_id_is_derived_not_assigned() {
		let key = master_key();
		// Deriving twice must agree, or nothing downstream can rely on it.
		assert_eq!(UserId::from_master_key(&key), UserId::from_master_key(&key));
		assert_ne!(
			UserId::from_master_key(&key),
			UserId::from_master_key(&master_key())
		);
	}

	/// The property the whole identity model rests on: a server cannot hand you
	/// a different key for an id you already trust.
	#[test]
	fn a_substituted_master_key_is_detected() {
		let real = master_key();
		let impostor = master_key();
		let id = UserId::from_master_key(&real);

		assert!(id.matches(&real));
		assert!(!id.matches(&impostor));
	}

	#[test]
	fn user_id_survives_a_text_round_trip() {
		let id = UserId::from_master_key(&master_key());
		assert_eq!(UserId::parse(&id.to_string()).unwrap(), id);
		// Hand-typed ids should not fail on case alone.
		assert_eq!(UserId::parse(&id.to_string().to_lowercase()).unwrap(), id);
		assert_eq!(UserId::parse(&format!("  {id}  ")).unwrap(), id);
	}

	#[test]
	fn user_id_rejects_wrong_length() {
		assert!(UserId::parse("AAAA").is_err());
		assert!(UserId::parse("").is_err());
		assert!(UserId::parse("not valid base32 !!").is_err());
	}

	#[test]
	fn device_ids_are_unique() {
		let ids: std::collections::HashSet<_> = (0..64).map(|_| DeviceId::generate()).collect();
		assert_eq!(ids.len(), 64);
	}

	/// §5.5: rotating a device key is routine and must not disturb the user's
	/// identity. This is what makes device compromise recoverable without
	/// forcing every peer to re-verify.
	#[test]
	fn device_changes_never_touch_the_user_id() {
		let key = master_key();
		let user = UserId::from_master_key(&key);

		let mut list = DeviceList::new(user, 1);
		let phone = DeviceId::generate();
		list.upsert(
			Device {
				device_id: phone,
				ed25519: [1; 32],
				curve25519: [2; 32],
				display_name: "phone".into(),
				created_at: 1,
				last_seen: 1,
			},
			1,
		);
		list.upsert(
			Device {
				device_id: DeviceId::generate(),
				ed25519: [3; 32],
				curve25519: [4; 32],
				display_name: "laptop".into(),
				created_at: 2,
				last_seen: 2,
			},
			2,
		);
		assert_eq!(list.devices.len(), 2);

		// Rotating the phone's keys replaces it rather than duplicating it.
		list.upsert(
			Device {
				device_id: phone,
				ed25519: [9; 32],
				curve25519: [9; 32],
				display_name: "phone".into(),
				created_at: 1,
				last_seen: 3,
			},
			3,
		);
		assert_eq!(list.devices.len(), 2);
		assert_eq!(list.get(&phone).unwrap().ed25519, [9; 32]);

		assert!(list.remove(&phone, 4));
		assert!(!list.contains(&phone));
		assert!(
			!list.remove(&phone, 5),
			"removing twice should report nothing"
		);

		// Through all of that, the identity is untouched.
		assert_eq!(list.user, user);
		assert!(user.matches(&key));
	}

	#[test]
	fn device_list_updated_at_advances_on_change() {
		let user = UserId::from_master_key(&master_key());
		let mut list = DeviceList::new(user, 10);
		let id = DeviceId::generate();

		list.upsert(
			Device {
				device_id: id,
				ed25519: [1; 32],
				curve25519: [2; 32],
				display_name: "d".into(),
				created_at: 0,
				last_seen: 0,
			},
			11,
		);
		assert_eq!(list.updated_at, 11);

		// A no-op removal must not advance the clock, or a replayed list could
		// be made to look newer than it is.
		assert!(!list.remove(&DeviceId::generate(), 99));
		assert_eq!(list.updated_at, 11);
	}
}

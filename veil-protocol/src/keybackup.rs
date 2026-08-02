//! Key backup and device enrolment — `DESIGN.md` §12.5.
//!
//! Sealed history depends on member key material, and the server must never
//! hold Megolm keys in usable form — it could otherwise read everything, which
//! is the whole point of the tier. Two mechanisms, in order of how often they
//! are used:
//!
//! **Cross-device handover** is the common path. An existing device approves a
//! new one and hands over what it holds. Anyone with two devices never touches
//! recovery at all.
//!
//! **The encrypted blob** is for losing every device at once. The client
//! encrypts locally and gives the server ciphertext, so the server stores
//! something it cannot read — the same logic as member-restorable backups
//! (§12.3), applied to keys rather than messages.
//!
//! One recovery key covers identity *and* history: the blob holds the
//! cross-signing secrets as well as the Megolm sessions. Splitting them would
//! only give the user two things to lose.

use crate::{
	crosssign::CrossSigningSecrets,
	groupkeys::ChannelId,
	identity::{DeviceAddress, DeviceId},
};
use chacha20poly1305::{
	XChaCha20Poly1305, XNonce,
	aead::{Aead, KeyInit},
};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

/// The secret that unlocks a backup.
///
/// **Randomly generated, never derived from a passphrase.** A user-chosen
/// passphrase lets whoever holds the blob brute-force it offline at their
/// leisure, which turns the whole mechanism into theatre. The cost is one string
/// the user has to keep, for something touched once.
#[derive(Clone)]
pub struct RecoveryKey([u8; 32]);

impl RecoveryKey {
	pub fn generate() -> Self {
		let mut key = [0u8; 32];
		rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
		Self(key)
	}

	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Rendered in groups, because it is meant to be written down.
	pub fn display(&self) -> String {
		BASE32_NOPAD
			.encode(&self.0)
			.as_bytes()
			.chunks(5)
			.map(|c| String::from_utf8_lossy(c).into_owned())
			.collect::<Vec<_>>()
			.join("-")
	}

	pub fn parse(text: &str) -> anyhow::Result<Self> {
		let cleaned: String = text
			.chars()
			.filter(|c| c.is_ascii_alphanumeric())
			.collect::<String>()
			.to_ascii_uppercase();

		let bytes = BASE32_NOPAD.decode(cleaned.as_bytes())?;
		Ok(Self(bytes.as_slice().try_into().map_err(|_| {
			anyhow::anyhow!("a recovery key is 32 bytes; got {}", bytes.len())
		})?))
	}
}

impl std::fmt::Debug for RecoveryKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// Never print the key itself, including by accident through a Debug
		// derive somewhere upstream.
		f.write_str("RecoveryKey(<redacted>)")
	}
}

/// One Megolm session, exported at the point it was received.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionExport {
	pub channel: String,
	pub sender: DeviceAddress,
	/// vodozemac's exported session key, base64.
	pub session_key: String,
	/// Whether this session may be handed to a device other than our own.
	///
	/// MSC4268 carries the same flag, and it exists so that keys from a period
	/// a user was not entitled to read can never be included in a handover.
	pub shared_history: bool,
}

/// What a backup contains.
#[derive(Serialize, Deserialize)]
pub struct BackupPayload {
	pub cross_signing: CrossSigningSecrets,
	pub sessions: Vec<SessionExport>,
}

/// A backup as stored: ciphertext the holder cannot read.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedBackup {
	pub nonce: Vec<u8>,
	pub ciphertext: Vec<u8>,
}

pub fn seal(key: &RecoveryKey, payload: &BackupPayload) -> anyhow::Result<EncryptedBackup> {
	let plaintext = serde_json::to_vec(payload)?;

	let mut nonce = [0u8; 24];
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

	let cipher = XChaCha20Poly1305::new((&key.0).into());
	let ciphertext = cipher
		.encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
		.map_err(|e| anyhow::anyhow!("could not seal backup: {e}"))?;

	Ok(EncryptedBackup {
		nonce: nonce.to_vec(),
		ciphertext,
	})
}

pub fn open(key: &RecoveryKey, backup: &EncryptedBackup) -> anyhow::Result<BackupPayload> {
	if backup.nonce.len() != 24 {
		anyhow::bail!("backup nonce is {} bytes, expected 24", backup.nonce.len());
	}

	let cipher = XChaCha20Poly1305::new((&key.0).into());
	let plaintext = cipher
		.decrypt(
			XNonce::from_slice(&backup.nonce),
			backup.ciphertext.as_slice(),
		)
		.map_err(|_| anyhow::anyhow!("wrong recovery key, or the backup is corrupt"))?;

	Ok(serde_json::from_slice(&plaintext)?)
}

/// Everything handed to a newly enrolled device.
///
/// **One bundle, not one message per session.** Matrix's first attempt
/// (MSC3061) sent a to-device message per Megolm session per recipient device,
/// and its own successor calls that "prohibitive" — a room accumulates sessions
/// forever, so the cost grows without bound. MSC4268 replaced it with exactly
/// this shape.
#[derive(Serialize, Deserialize)]
pub struct EnrolmentBundle {
	pub for_device: DeviceId,
	pub sessions: Vec<SessionExport>,
}

/// Selects what may be handed to one of *our own* newly-enrolled devices.
///
/// The rules here are deliberately **not** the rules for sharing a new session
/// key with a channel's members, and the two must not share code. Applying the
/// new-key rules to historical keys is precisely the defect Matrix shipped
/// (disclosed October 2024, matrix-js-sdk 9.11.0–34.7.x): historical keys
/// reached unverified devices and users.
///
/// Two conditions, both required:
///
/// 1. the destination is a device we have verified as **our own** — never a
///    peer's, however well verified that peer is;
/// 2. the session is flagged shareable, so keys from a period the user was not
///    entitled to read are not eligible in the first place.
pub fn bundle_for_own_device(
	sessions: &[SessionExport],
	destination: DeviceId,
	our_verified_devices: &[DeviceId],
) -> anyhow::Result<EnrolmentBundle> {
	if !our_verified_devices.contains(&destination) {
		anyhow::bail!(
			"{destination} is not a verified device of ours; historical keys are never \
			 shared outside our own device set"
		);
	}

	Ok(EnrolmentBundle {
		for_device: destination,
		sessions: sessions
			.iter()
			.filter(|s| s.shared_history)
			.cloned()
			.collect(),
	})
}

/// Selects who receives a *newly created* session key.
///
/// Separate function, separate rules: a new key goes to every current member
/// device of the channel, verified or not, because they are entitled to read
/// what is sent from now on. Kept apart from [`bundle_for_own_device`] so the
/// two cannot be confused at a call site.
pub fn recipients_for_new_session(
	channel: &ChannelId,
	member_devices: &[DeviceAddress],
) -> Vec<DeviceAddress> {
	let _ = channel;
	member_devices.to_vec()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::identity::UserId;
	use vodozemac::Ed25519SecretKey;

	fn address() -> DeviceAddress {
		DeviceAddress::new(
			UserId::from_master_key(&Ed25519SecretKey::new().public_key()),
			DeviceId::generate(),
		)
	}

	fn session(shared: bool) -> SessionExport {
		SessionExport {
			channel: "general".into(),
			sender: address(),
			session_key: "AAAA".into(),
			shared_history: shared,
		}
	}

	fn payload() -> BackupPayload {
		BackupPayload {
			cross_signing: CrossSigningSecrets::new(),
			sessions: vec![session(true), session(false)],
		}
	}

	#[test]
	fn a_backup_round_trips_under_its_recovery_key() {
		let key = RecoveryKey::generate();
		let original = payload();
		let user = original.cross_signing.user_id();

		let sealed = seal(&key, &original).unwrap();
		let restored = open(&key, &sealed).unwrap();

		// The identity comes back with the history, from one secret (§12.5).
		assert_eq!(restored.cross_signing.user_id(), user);
		assert_eq!(restored.sessions.len(), 2);
	}

	#[test]
	fn the_wrong_recovery_key_does_not_open_it() {
		let sealed = seal(&RecoveryKey::generate(), &payload()).unwrap();
		assert!(open(&RecoveryKey::generate(), &sealed).is_err());
	}

	#[test]
	fn a_tampered_backup_is_rejected() {
		let key = RecoveryKey::generate();
		let mut sealed = seal(&key, &payload()).unwrap();
		sealed.ciphertext[0] ^= 1;

		assert!(
			open(&key, &sealed).is_err(),
			"the AEAD tag must catch modification"
		);
	}

	#[test]
	fn a_recovery_key_survives_being_written_down() {
		let key = RecoveryKey::generate();
		let written = key.display();

		assert!(written.contains('-'), "should be grouped for transcription");
		assert_eq!(RecoveryKey::parse(&written).unwrap().0, key.0);
		// Typed back in with the wrong case and stray spaces.
		assert_eq!(
			RecoveryKey::parse(&format!("  {}  ", written.to_lowercase()))
				.unwrap()
				.0,
			key.0
		);
	}

	#[test]
	fn a_recovery_key_is_never_printed_by_accident() {
		let key = RecoveryKey::generate();
		let debug = format!("{key:?}");
		assert!(debug.contains("redacted"));
		assert!(!debug.contains(&key.display()[..5]));
	}

	/// The defect Matrix shipped: historical keys must not reach a device
	/// outside our own verified set, however the caller asks.
	#[test]
	fn historical_keys_never_leave_our_own_device_set() {
		let sessions = vec![session(true), session(true)];
		let ours = DeviceId::generate();
		let theirs = DeviceId::generate();

		assert!(bundle_for_own_device(&sessions, ours, &[ours]).is_ok());
		assert!(
			bundle_for_own_device(&sessions, theirs, &[ours]).is_err(),
			"a peer's device must never receive historical keys"
		);
	}

	/// Sessions from a period the user was not entitled to read are not
	/// eligible for handover at all.
	#[test]
	fn unshareable_sessions_are_excluded_from_a_bundle() {
		let sessions = vec![session(true), session(false), session(true)];
		let ours = DeviceId::generate();

		let bundle = bundle_for_own_device(&sessions, ours, &[ours]).unwrap();
		assert_eq!(bundle.sessions.len(), 2);
		assert!(bundle.sessions.iter().all(|s| s.shared_history));
	}
}

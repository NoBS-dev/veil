//! Group key agreement, behind an interface — `DESIGN.md` §8.4, §8.5.
//!
//! Megolm is an *implementation* here, not an assumption. Its cost is
//! `Σ(devices per member)` per rotation, and rotation is mandatory whenever
//! someone is removed (§8.3), so the binding constraint is churn × devices. If
//! that ever bites, **MLS replaces one module rather than the stack** — adopting
//! the boundary now is nearly free and retrofitting it is not.
//!
//! The boundary is drawn so both fit: callers hand over *who may read* and get
//! back opaque key material addressed to devices. Megolm returns a session key
//! per recipient device; MLS would return a commit for the group. Neither shape
//! leaks into the caller.

use crate::{community::CommunityId, identity::DeviceAddress};
use std::collections::{BTreeSet, HashMap};
use vodozemac::megolm::{
	GroupSession, InboundGroupSession, MegolmMessage, SessionConfig, SessionKey,
};

/// A channel within a community.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId {
	pub community: CommunityId,
	pub name: String,
}

impl ChannelId {
	pub fn new(community: CommunityId, name: impl Into<String>) -> Self {
		Self {
			community,
			name: name.into(),
		}
	}
}

impl std::fmt::Display for ChannelId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}#{}", self.community, self.name)
	}
}

/// Who may read a channel.
///
/// **This must come from verified policy (§8.5), never from a host
/// notification.** In Sealed, read access *is* key possession — senders consult
/// this to decide who receives keys — so a host able to supply it could add a
/// reader and have every sender dutifully encrypt to them.
///
/// `policy_sequence` is carried so that constraint is structural rather than a
/// comment: readership cannot be driven backwards, which is what stops a stale
/// policy record reinstating a removed member.
#[derive(Debug, Clone)]
pub struct Readership {
	/// Devices, not users — keys go to devices (§5.2).
	pub devices: BTreeSet<DeviceAddress>,
	/// Sequence of the policy record this was derived from (§7.4).
	pub policy_sequence: u64,
}

/// Key material to deliver, addressed to the devices that need it.
///
/// Deliberately opaque: Megolm puts a session key here and addresses every
/// member device; MLS would put a commit here and address the group. The
/// caller's job is delivery, not interpretation.
#[derive(Debug, Clone)]
pub struct KeyDelivery {
	pub channel: ChannelId,
	pub payload: Vec<u8>,
	pub recipients: Vec<DeviceAddress>,
}

/// Why a channel's keys changed, for callers that want to explain it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationCause {
	/// First key for this channel.
	Established,
	/// Someone lost read access. Mandatory — without it they keep decrypting.
	MemberRemoved,
	/// Only additions; the existing key is handed to the newcomers. Joiners
	/// cannot read history from before they joined, by construction (§8.3).
	MembersAdded,
}

pub trait GroupKeyProvider {
	fn encrypt(&mut self, channel: &ChannelId, plaintext: &[u8]) -> anyhow::Result<Vec<u8>>;

	fn decrypt(
		&mut self,
		channel: &ChannelId,
		sender: &DeviceAddress,
		ciphertext: &[u8],
	) -> anyhow::Result<Vec<u8>>;

	/// Applies a readership decided by verified policy, returning whatever key
	/// material now needs delivering.
	fn set_readership(
		&mut self,
		channel: &ChannelId,
		readership: &Readership,
	) -> anyhow::Result<Option<(RotationCause, KeyDelivery)>>;

	/// Accepts key material a peer sent us.
	fn accept_key(
		&mut self,
		channel: &ChannelId,
		sender: &DeviceAddress,
		payload: &[u8],
	) -> anyhow::Result<()>;
}

struct Outbound {
	session: GroupSession,
	readers: BTreeSet<DeviceAddress>,
	policy_sequence: u64,
}

/// Megolm behind the boundary.
#[derive(Default)]
pub struct MegolmProvider {
	outbound: HashMap<ChannelId, Outbound>,
	inbound: HashMap<(ChannelId, DeviceAddress), InboundGroupSession>,
}

impl MegolmProvider {
	pub fn new() -> Self {
		Self::default()
	}

	/// Cost of the next rotation, in pairwise Olm encryptions. Exposed because
	/// it is the number that decides whether Megolm remains viable for a given
	/// channel (§8.3).
	pub fn rotation_cost(&self, channel: &ChannelId) -> usize {
		self.outbound
			.get(channel)
			.map(|o| o.readers.len())
			.unwrap_or(0)
	}

	fn establish(
		&mut self,
		channel: &ChannelId,
		readership: &Readership,
		cause: RotationCause,
		recipients: Vec<DeviceAddress>,
	) -> (RotationCause, KeyDelivery) {
		let session = GroupSession::new(SessionConfig::version_2());
		let payload = session.session_key().to_base64().into_bytes();

		self.outbound.insert(
			channel.clone(),
			Outbound {
				session,
				readers: readership.devices.clone(),
				policy_sequence: readership.policy_sequence,
			},
		);

		(
			cause,
			KeyDelivery {
				channel: channel.clone(),
				payload,
				recipients,
			},
		)
	}
}

impl GroupKeyProvider for MegolmProvider {
	fn encrypt(&mut self, channel: &ChannelId, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
		let outbound = self.outbound.get_mut(channel).ok_or_else(|| {
			anyhow::anyhow!("no group session for {channel}; set a readership first")
		})?;

		Ok(outbound.session.encrypt(plaintext).to_base64().into_bytes())
	}

	fn decrypt(
		&mut self,
		channel: &ChannelId,
		sender: &DeviceAddress,
		ciphertext: &[u8],
	) -> anyhow::Result<Vec<u8>> {
		let session = self
			.inbound
			.get_mut(&(channel.clone(), *sender))
			.ok_or_else(|| anyhow::anyhow!("no inbound session for {sender} in {channel}"))?;

		let message = MegolmMessage::from_base64(std::str::from_utf8(ciphertext)?)?;
		Ok(session.decrypt(&message)?.plaintext)
	}

	fn set_readership(
		&mut self,
		channel: &ChannelId,
		readership: &Readership,
	) -> anyhow::Result<Option<(RotationCause, KeyDelivery)>> {
		let Some(existing) = self.outbound.get(channel) else {
			let recipients = readership.devices.iter().copied().collect();
			return Ok(Some(self.establish(
				channel,
				readership,
				RotationCause::Established,
				recipients,
			)));
		};

		// A stale policy record must not be able to reinstate a removed reader
		// (§7.4). Equal sequences are a no-op rather than an error: replaying
		// the current state is harmless.
		if readership.policy_sequence < existing.policy_sequence {
			anyhow::bail!(
				"readership for {channel} is from policy sequence {} but {} is already applied",
				readership.policy_sequence,
				existing.policy_sequence
			);
		}

		let removed: Vec<_> = existing.readers.difference(&readership.devices).collect();
		let added: Vec<_> = readership
			.devices
			.difference(&existing.readers)
			.copied()
			.collect();

		if !removed.is_empty() {
			// Mandatory (§8.3): without a new session the removed devices keep
			// decrypting everything sent afterwards. Everyone still present
			// needs the replacement.
			let recipients = readership.devices.iter().copied().collect();
			return Ok(Some(self.establish(
				channel,
				readership,
				RotationCause::MemberRemoved,
				recipients,
			)));
		}

		if added.is_empty() {
			return Ok(None);
		}

		// Additions alone need no rotation — the joiner gets the current key and
		// by construction cannot read anything sent before they had it.
		let outbound = self.outbound.get_mut(channel).expect("checked above");
		let payload = outbound.session.session_key().to_base64().into_bytes();
		outbound.readers = readership.devices.clone();
		outbound.policy_sequence = readership.policy_sequence;

		Ok(Some((
			RotationCause::MembersAdded,
			KeyDelivery {
				channel: channel.clone(),
				payload,
				recipients: added,
			},
		)))
	}

	fn accept_key(
		&mut self,
		channel: &ChannelId,
		sender: &DeviceAddress,
		payload: &[u8],
	) -> anyhow::Result<()> {
		let key = SessionKey::from_base64(std::str::from_utf8(payload)?)?;
		self.inbound.insert(
			(channel.clone(), *sender),
			InboundGroupSession::new(&key, SessionConfig::version_2()),
		);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		community::{CommunityRoot, Mode},
		identity::{DeviceId, UserId},
	};
	use vodozemac::Ed25519SecretKey;

	fn channel() -> ChannelId {
		let founder = Ed25519SecretKey::new();
		let root = CommunityRoot::found(
			Mode::Sealed,
			vec![*Ed25519SecretKey::new().public_key().as_bytes()],
			1,
			&founder,
			0,
		)
		.unwrap();
		ChannelId::new(root.id(), "general")
	}

	fn device() -> DeviceAddress {
		DeviceAddress::new(
			UserId::from_master_key(&Ed25519SecretKey::new().public_key()),
			DeviceId::generate(),
		)
	}

	fn readership(devices: &[DeviceAddress], sequence: u64) -> Readership {
		Readership {
			devices: devices.iter().copied().collect(),
			policy_sequence: sequence,
		}
	}

	#[test]
	fn a_reader_with_the_key_can_decrypt() {
		let channel = channel();
		let (alice, bob) = (device(), device());

		let mut sender = MegolmProvider::new();
		let (cause, delivery) = sender
			.set_readership(&channel, &readership(&[alice, bob], 1))
			.unwrap()
			.unwrap();
		assert_eq!(cause, RotationCause::Established);
		assert!(delivery.recipients.contains(&bob));

		let mut receiver = MegolmProvider::new();
		receiver
			.accept_key(&channel, &alice, &delivery.payload)
			.unwrap();

		let ciphertext = sender.encrypt(&channel, b"for the channel").unwrap();
		assert_eq!(
			receiver.decrypt(&channel, &alice, &ciphertext).unwrap(),
			b"for the channel"
		);
	}

	/// §8.3: removal *must* rotate, or the removed device keeps decrypting
	/// everything sent afterwards.
	#[test]
	fn removal_rotates_and_locks_the_removed_device_out() {
		let channel = channel();
		let (alice, bob, carol) = (device(), device(), device());

		let mut sender = MegolmProvider::new();
		let (_, first) = sender
			.set_readership(&channel, &readership(&[alice, bob, carol], 1))
			.unwrap()
			.unwrap();

		// Carol holds the original key.
		let mut carols = MegolmProvider::new();
		carols.accept_key(&channel, &alice, &first.payload).unwrap();

		let before = sender.encrypt(&channel, b"carol may read this").unwrap();
		assert_eq!(
			carols.decrypt(&channel, &alice, &before).unwrap(),
			b"carol may read this"
		);

		// Carol loses access.
		let (cause, second) = sender
			.set_readership(&channel, &readership(&[alice, bob], 2))
			.unwrap()
			.unwrap();
		assert_eq!(cause, RotationCause::MemberRemoved);
		assert!(
			!second.recipients.contains(&carol),
			"the new key must not be sent to the removed device"
		);
		assert_ne!(first.payload, second.payload, "removal must rotate the key");

		// Anything sent now is unreadable with the key she has.
		let after = sender
			.encrypt(&channel, b"carol must not read this")
			.unwrap();
		assert!(carols.decrypt(&channel, &alice, &after).is_err());
	}

	/// Joins need no rotation, and the joiner cannot read what came before —
	/// which falls out of Megolm ratcheting rather than being enforced.
	#[test]
	fn a_join_does_not_rotate() {
		let channel = channel();
		let (alice, bob, dave) = (device(), device(), device());

		let mut sender = MegolmProvider::new();
		let (_, first) = sender
			.set_readership(&channel, &readership(&[alice, bob], 1))
			.unwrap()
			.unwrap();

		let (cause, second) = sender
			.set_readership(&channel, &readership(&[alice, bob, dave], 2))
			.unwrap()
			.unwrap();

		assert_eq!(cause, RotationCause::MembersAdded);
		assert_eq!(
			second.recipients,
			vec![dave],
			"only the joiner needs the key"
		);
		assert_eq!(first.payload, second.payload, "a join must not rotate");
	}

	#[test]
	fn an_unchanged_readership_is_a_no_op() {
		let channel = channel();
		let (alice, bob) = (device(), device());

		let mut sender = MegolmProvider::new();
		sender
			.set_readership(&channel, &readership(&[alice, bob], 1))
			.unwrap();

		assert!(
			sender
				.set_readership(&channel, &readership(&[alice, bob], 2))
				.unwrap()
				.is_none()
		);
	}

	/// §7.4/§8.5: a stale policy record must not reinstate a removed reader.
	#[test]
	fn readership_cannot_be_driven_backwards() {
		let channel = channel();
		let (alice, bob, carol) = (device(), device(), device());

		let mut sender = MegolmProvider::new();
		sender
			.set_readership(&channel, &readership(&[alice, bob, carol], 5))
			.unwrap();
		sender
			.set_readership(&channel, &readership(&[alice, bob], 6))
			.unwrap();

		// Replaying the older record, which still lists Carol.
		assert!(
			sender
				.set_readership(&channel, &readership(&[alice, bob, carol], 5))
				.is_err()
		);
	}

	/// The number that decides whether Megolm stays viable for a channel: the
	/// pairwise Olm encryptions a rotation costs (§8.3).
	#[test]
	fn rotation_cost_tracks_the_reader_count() {
		let channel = channel();
		let devices: Vec<_> = (0..50).map(|_| device()).collect();

		let mut sender = MegolmProvider::new();
		assert_eq!(sender.rotation_cost(&channel), 0);

		sender
			.set_readership(&channel, &readership(&devices, 1))
			.unwrap();
		assert_eq!(sender.rotation_cost(&channel), 50);
	}

	#[test]
	fn encrypting_without_a_readership_fails_rather_than_sending_in_the_clear() {
		let mut sender = MegolmProvider::new();
		assert!(sender.encrypt(&channel(), b"oops").is_err());
	}
}

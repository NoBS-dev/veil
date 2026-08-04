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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use vodozemac::megolm::{
	GroupSession, InboundGroupSession, MegolmMessage, SessionConfig, SessionKey,
};

/// Messages one session will carry before it is replaced.
///
/// Matrix's value. A busy channel reaches this in an afternoon, which is the
/// point — it bounds how much one stolen key is worth in traffic rather than in
/// time.
const MESSAGES_PER_SESSION: u64 = 100;
/// How long one session lives, however quiet the channel.
///
/// The other half of the bound: without it a channel with little traffic keeps
/// one session indefinitely, and a key taken from it is worth everything ever
/// said there.
const SESSION_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// A channel within a community.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
	/// The session has run long enough. See [`MegolmProvider::rotation_due`].
	Aged,
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
	/// `now` is supplied rather than read, for the same reason `ReplayGuard`
	/// takes it: a provider that read the clock itself could not be told about
	/// an SNTP offset (§13.4) and could not be driven by a test.
	fn set_readership(
		&mut self,
		channel: &ChannelId,
		readership: &Readership,
		now: u64,
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
	/// Messages sent under this session, and when it was established.
	///
	/// Both bound how much one stolen key is worth — see
	/// [`MegolmProvider::rotation_due`].
	messages: u64,
	established_at: u64,
}

/// Megolm behind the boundary.
pub struct MegolmProvider {
	/// The device this provider speaks as.
	///
	/// Needed because a sender has to be able to read its own channel. Megolm
	/// is one-way — an outbound session encrypts and never decrypts — so
	/// without registering an inbound session against ourselves at the moment we
	/// establish one, every message we sent would come back unreadable to us.
	own: DeviceAddress,
	outbound: HashMap<ChannelId, Outbound>,
	inbound: HashMap<(ChannelId, DeviceAddress), InboundGroupSession>,
}

/// The provider's state, in a form that can be written to disk.
///
/// **Sessions have to survive a restart.** A Megolm session is the only thing
/// that can read what was sent under it, so a client that regenerated on every
/// start would lose every Sealed channel it had ever read — and a *sender* that
/// did so would rotate on every start, which is `Σ(devices)` pairwise
/// encryptions each time (§8.3). Neither is a security failure; both make
/// Sealed unusable, which comes to the same thing.
///
/// Kept separate from the provider rather than derived on it, because vodozemac's
/// session types are not themselves serialisable — pickling is the supported
/// route, and going through it explicitly keeps the conversion in one place.
#[derive(Serialize, Deserialize, Clone)]
pub struct ProviderState {
	outbound: Vec<(ChannelId, OutboundState)>,
	inbound: Vec<(ChannelId, DeviceAddress, String)>,
}

#[derive(Serialize, Deserialize, Clone)]
struct OutboundState {
	session: String,
	readers: BTreeSet<DeviceAddress>,
	policy_sequence: u64,
	/// Carried across a restart. Without these a client that restarted daily
	/// would never rotate, which is the failure the limits exist to prevent.
	#[serde(default)]
	messages: u64,
	#[serde(default)]
	established_at: u64,
}

impl MegolmProvider {
	/// Captures everything worth keeping.
	pub fn save(&self) -> anyhow::Result<ProviderState> {
		Ok(ProviderState {
			outbound: self
				.outbound
				.iter()
				.map(|(channel, out)| {
					Ok((
						channel.clone(),
						OutboundState {
							session: serde_json::to_string(&out.session.pickle())?,
							readers: out.readers.clone(),
							policy_sequence: out.policy_sequence,
							messages: out.messages,
							established_at: out.established_at,
						},
					))
				})
				.collect::<anyhow::Result<Vec<_>>>()?,
			inbound: self
				.inbound
				.iter()
				.map(|((channel, sender), session)| {
					Ok((
						channel.clone(),
						*sender,
						serde_json::to_string(&session.pickle())?,
					))
				})
				.collect::<anyhow::Result<Vec<_>>>()?,
		})
	}

	/// The device address is supplied rather than stored: it is a property of
	/// this device, not of the sessions, and reading it back from a file would
	/// let a tampered profile change who we think we are.
	pub fn restore(state: ProviderState, own: DeviceAddress) -> anyhow::Result<Self> {
		let mut provider = Self::new(own);

		for (channel, out) in state.outbound {
			provider.outbound.insert(
				channel,
				Outbound {
					session: GroupSession::from_pickle(serde_json::from_str(&out.session)?),
					readers: out.readers,
					policy_sequence: out.policy_sequence,
					messages: out.messages,
					established_at: out.established_at,
				},
			);
		}

		for (channel, sender, pickle) in state.inbound {
			provider.inbound.insert(
				(channel, sender),
				InboundGroupSession::from_pickle(serde_json::from_str(&pickle)?),
			);
		}

		Ok(provider)
	}
}

impl MegolmProvider {
	pub fn new(own: DeviceAddress) -> Self {
		Self {
			own,
			outbound: HashMap::new(),
			inbound: HashMap::new(),
		}
	}

	/// Cost of the next rotation, in pairwise Olm encryptions. Exposed because
	/// it is the number that decides whether Megolm remains viable for a given
	/// channel (§8.3).
	/// Whether a channel's session has run long enough to be replaced.
	///
	/// **Megolm has no backward secrecy within a session.** A key taken from a
	/// device today decrypts every message sent under that session, including
	/// ones from before the theft, and goes on decrypting until the session
	/// ends. Rotating on nothing but membership change means a session
	/// established a year ago is still the session — so one stolen device is
	/// worth a year of a channel.
	///
	/// Rotation bounds that. Both limits matter and neither substitutes for the
	/// other: a busy channel reaches the message count in an afternoon, and a
	/// quiet one would otherwise keep one session indefinitely. The values match
	/// Matrix's, which is not laziness — they are what a decade of running this
	/// in practice settled on, and departing from them needs a reason.
	pub fn rotation_due(&self, channel: &ChannelId, now: u64) -> bool {
		self.outbound.get(channel).is_some_and(|out| {
			out.messages >= MESSAGES_PER_SESSION
				|| now.saturating_sub(out.established_at) >= SESSION_LIFETIME_MS
		})
	}

	/// Replaces a channel's session if it is due, returning what to distribute.
	///
	/// Separate from `encrypt` so the caller decides when to pay the cost — it
	/// is `Σ(devices)` pairwise encryptions — and so encryption itself stays a
	/// function that cannot fail for a reason the caller has to handle.
	pub fn rotate_if_due(
		&mut self,
		channel: &ChannelId,
		now: u64,
	) -> Option<(RotationCause, KeyDelivery)> {
		if !self.rotation_due(channel, now) {
			return None;
		}

		let existing = self.outbound.get(channel)?;
		let readership = Readership {
			devices: existing.readers.clone(),
			policy_sequence: existing.policy_sequence,
		};
		let recipients = readership.devices.iter().copied().collect();

		Some(self.establish(channel, &readership, RotationCause::Aged, recipients, now))
	}

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
		now: u64,
	) -> (RotationCause, KeyDelivery) {
		let session = GroupSession::new(SessionConfig::version_2());
		let payload = session.session_key().to_base64().into_bytes();

		// Our own inbound copy, so what we send comes back readable. The host
		// fans a message out to every member including the sender, and a sender
		// that could not read its own channel would be plainly broken.
		self.inbound.insert(
			(channel.clone(), self.own),
			InboundGroupSession::new(&session.session_key(), SessionConfig::version_2()),
		);

		self.outbound.insert(
			channel.clone(),
			Outbound {
				session,
				readers: readership.devices.clone(),
				policy_sequence: readership.policy_sequence,
				messages: 0,
				established_at: now,
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

		// Counted here rather than by the caller, so a caller that forgets does
		// not silently disable the volume limit.
		outbound.messages = outbound.messages.saturating_add(1);

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
		now: u64,
	) -> anyhow::Result<Option<(RotationCause, KeyDelivery)>> {
		let Some(existing) = self.outbound.get(channel) else {
			let recipients = readership.devices.iter().copied().collect();
			return Ok(Some(self.establish(
				channel,
				readership,
				RotationCause::Established,
				recipients,
				now,
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
				now,
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

		let mut sender = MegolmProvider::new(device());
		let (cause, delivery) = sender
			.set_readership(&channel, &readership(&[alice, bob], 1), 0)
			.unwrap()
			.unwrap();
		assert_eq!(cause, RotationCause::Established);
		assert!(delivery.recipients.contains(&bob));

		let mut receiver = MegolmProvider::new(device());
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

		let mut sender = MegolmProvider::new(device());
		let (_, first) = sender
			.set_readership(&channel, &readership(&[alice, bob, carol], 1), 0)
			.unwrap()
			.unwrap();

		// Carol holds the original key.
		let mut carols = MegolmProvider::new(device());
		carols.accept_key(&channel, &alice, &first.payload).unwrap();

		let before = sender.encrypt(&channel, b"carol may read this").unwrap();
		assert_eq!(
			carols.decrypt(&channel, &alice, &before).unwrap(),
			b"carol may read this"
		);

		// Carol loses access.
		let (cause, second) = sender
			.set_readership(&channel, &readership(&[alice, bob], 2), 0)
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

		let mut sender = MegolmProvider::new(device());
		let (_, first) = sender
			.set_readership(&channel, &readership(&[alice, bob], 1), 0)
			.unwrap()
			.unwrap();

		let (cause, second) = sender
			.set_readership(&channel, &readership(&[alice, bob, dave], 2), 0)
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

		let mut sender = MegolmProvider::new(device());
		sender
			.set_readership(&channel, &readership(&[alice, bob], 1), 0)
			.unwrap();

		assert!(
			sender
				.set_readership(&channel, &readership(&[alice, bob], 2), 0)
				.unwrap()
				.is_none()
		);
	}

	/// §7.4/§8.5: a stale policy record must not reinstate a removed reader.
	#[test]
	fn readership_cannot_be_driven_backwards() {
		let channel = channel();
		let (alice, bob, carol) = (device(), device(), device());

		let mut sender = MegolmProvider::new(device());
		sender
			.set_readership(&channel, &readership(&[alice, bob, carol], 5), 0)
			.unwrap();
		sender
			.set_readership(&channel, &readership(&[alice, bob], 6), 0)
			.unwrap();

		// Replaying the older record, which still lists Carol.
		assert!(
			sender
				.set_readership(&channel, &readership(&[alice, bob, carol], 5), 0)
				.is_err()
		);
	}

	/// The number that decides whether Megolm stays viable for a channel: the
	/// pairwise Olm encryptions a rotation costs (§8.3).
	#[test]
	fn rotation_cost_tracks_the_reader_count() {
		let channel = channel();
		let devices: Vec<_> = (0..50).map(|_| device()).collect();

		let mut sender = MegolmProvider::new(device());
		assert_eq!(sender.rotation_cost(&channel), 0);

		sender
			.set_readership(&channel, &readership(&devices, 1), 0)
			.unwrap();
		assert_eq!(sender.rotation_cost(&channel), 50);
	}

	#[test]
	fn encrypting_without_a_readership_fails_rather_than_sending_in_the_clear() {
		let mut sender = MegolmProvider::new(device());
		assert!(sender.encrypt(&channel(), b"oops").is_err());
	}

	/// A restart must not cost a channel's history.
	///
	/// The session is the only thing that can read what was sent under it, so a
	/// provider that came back empty would leave every Sealed message
	/// permanently unreadable — and would rotate on every start, which is
	/// `Σ(devices)` pairwise encryptions each time (§8.3).
	#[test]
	fn sessions_survive_being_saved_and_restored() {
		let channel = channel();
		let (reader, sender_address) = (device(), device());

		let mut sender = MegolmProvider::new(sender_address);
		let delivery = sender
			.set_readership(&channel, &readership(&[reader], 1), 0)
			.unwrap()
			.expect("establishing a channel produces a key")
			.1;
		let ciphertext = sender.encrypt(&channel, b"before the restart").unwrap();

		// The reader takes the key, then is restarted.
		let mut reader_provider = MegolmProvider::new(reader);
		reader_provider
			.accept_key(&channel, &sender_address, &delivery.payload)
			.unwrap();

		let restored = MegolmProvider::restore(reader_provider.save().unwrap(), reader).unwrap();
		let mut restored = restored;

		assert_eq!(
			restored
				.decrypt(&channel, &sender_address, &ciphertext)
				.unwrap(),
			b"before the restart",
			"a restored provider must still read what it could before"
		);
	}

	/// And the sender's side: after a restart it keeps sending on the same
	/// session rather than silently establishing a new one nobody has the key
	/// for.
	#[test]
	fn a_restored_sender_keeps_its_session() {
		let channel = channel();
		let (reader, sender_address) = (device(), device());

		let mut sender = MegolmProvider::new(sender_address);
		let delivery = sender
			.set_readership(&channel, &readership(&[reader], 1), 0)
			.unwrap()
			.unwrap()
			.1;

		let mut reader_provider = MegolmProvider::new(reader);
		reader_provider
			.accept_key(&channel, &sender_address, &delivery.payload)
			.unwrap();

		let mut sender = MegolmProvider::restore(sender.save().unwrap(), sender_address).unwrap();
		let after = sender.encrypt(&channel, b"after the restart").unwrap();

		assert_eq!(
			reader_provider
				.decrypt(&channel, &sender_address, &after)
				.unwrap(),
			b"after the restart",
			"a restored sender must keep the session its readers already hold"
		);
	}

	/// A sender must be able to read its own channel.
	///
	/// Megolm is one-way: an outbound session encrypts and never decrypts. The
	/// host fans every message out to all members including the sender, so
	/// without an inbound copy registered against ourselves at establishment,
	/// everything we sent would come back unreadable to us.
	#[test]
	fn a_sender_can_read_its_own_messages() {
		let channel = channel();
		let me = device();

		let mut provider = MegolmProvider::new(me);
		provider
			.set_readership(&channel, &readership(&[me, device()], 1), 0)
			.unwrap();

		let ciphertext = provider.encrypt(&channel, b"my own message").unwrap();
		assert_eq!(
			provider.decrypt(&channel, &me, &ciphertext).unwrap(),
			b"my own message"
		);
	}

	/// And still can after a restart, which is the combination that actually
	/// matters — the inbound copy has to be persisted like any other.
	#[test]
	fn a_sender_can_read_its_own_messages_after_a_restart() {
		let channel = channel();
		let me = device();

		let mut provider = MegolmProvider::new(me);
		provider
			.set_readership(&channel, &readership(&[me], 1), 0)
			.unwrap();
		let ciphertext = provider.encrypt(&channel, b"before").unwrap();

		let mut restored = MegolmProvider::restore(provider.save().unwrap(), me).unwrap();
		assert_eq!(
			restored.decrypt(&channel, &me, &ciphertext).unwrap(),
			b"before"
		);
	}
	/// §8.3: a session that never ends means one stolen key is worth the whole
	/// channel, for as long as the channel has existed.
	#[test]
	fn a_session_rotates_once_it_has_carried_enough_messages() {
		let channel = channel();
		let me = device();
		let mut provider = MegolmProvider::new(me);

		provider
			.set_readership(&channel, &readership(&[me, device()], 1), 0)
			.unwrap();

		assert!(!provider.rotation_due(&channel, 0));

		for _ in 0..MESSAGES_PER_SESSION {
			provider.encrypt(&channel, b"chatter").unwrap();
		}

		assert!(
			provider.rotation_due(&channel, 0),
			"a session must not carry unbounded traffic"
		);

		let (cause, delivery) = provider
			.rotate_if_due(&channel, 0)
			.expect("a due session should rotate");
		assert_eq!(cause, RotationCause::Aged);
		assert_eq!(
			delivery.recipients.len(),
			2,
			"everyone still reading needs the replacement"
		);

		// And the replacement starts its own budget.
		assert!(!provider.rotation_due(&channel, 0));
	}

	/// The other half of the bound: a quiet channel would otherwise keep one
	/// session forever.
	#[test]
	fn a_session_rotates_once_it_is_old_enough() {
		let channel = channel();
		let me = device();
		let mut provider = MegolmProvider::new(me);

		provider
			.set_readership(&channel, &readership(&[me], 1), 1_000)
			.unwrap();

		provider.encrypt(&channel, b"one message all week").unwrap();
		assert!(
			!provider.rotation_due(&channel, 1_000 + SESSION_LIFETIME_MS - 1),
			"it should not rotate early"
		);
		assert!(
			provider.rotation_due(&channel, 1_000 + SESSION_LIFETIME_MS),
			"a week-old session must be replaced however quiet the channel"
		);
	}

	/// A client that restarted daily would otherwise never rotate, which is
	/// exactly the case the limits exist for.
	#[test]
	fn the_rotation_budget_survives_a_restart() {
		let channel = channel();
		let me = device();
		let mut provider = MegolmProvider::new(me);

		provider
			.set_readership(&channel, &readership(&[me], 1), 1_000)
			.unwrap();
		for _ in 0..MESSAGES_PER_SESSION {
			provider.encrypt(&channel, b"chatter").unwrap();
		}

		let restored = MegolmProvider::restore(provider.save().unwrap(), me).unwrap();
		assert!(
			restored.rotation_due(&channel, 1_000),
			"the message count must survive a restart, or restarting resets the budget"
		);
	}
}

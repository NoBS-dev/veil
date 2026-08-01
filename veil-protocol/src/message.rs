//! Message identity and ordering — `DESIGN.md` §10.
//!
//! Two halves with different owners. The sender authors and signs identity,
//! timing, and causal position; the **host** alone assigns order and builds the
//! chain. A member can never write, reorder, or rewrite — their only power over
//! history is read-side: holding a copy and proving what it says.
//!
//! Note what is *not* here: `seq`, `prev_hash` and `server_ts` exist only where
//! there is a host to assign them, which means community channels. DMs have no
//! shared log to sequence — a conversation lives in two mailboxes and no single
//! server sees both sides — so they carry the sender-authored half only and are
//! ordered client-side.

use crate::identity::DeviceAddress;
use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as De, Serialize as Ser};
use sha2::{Digest, Sha256};

const MESSAGE_ID_DOMAIN: &[u8] = b"veil-message-id-v1";

/// A message's identity, which **is** a hash of its content.
///
/// Content-addressed as Matrix event IDs are from room version 4 onward: any
/// change to the message changes its id, so a message cannot be altered while
/// keeping its identity. The `nonce` keeps two identical messages distinct, and
/// a retry reuses it so idempotency and dedup still work.
///
/// **Derived, never transmitted.** Carrying it on the wire would only let a
/// sender claim an id that does not match its content, and every receiver has
/// to recompute it to check anyway. Computing it is strictly less to go wrong.
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub struct MessageId([u8; 32]);

impl MessageId {
	/// `H(domain || sender || origin_ts || nonce || content)`
	pub fn derive(
		sender: &DeviceAddress,
		origin_ts: u64,
		nonce: &[u8; 16],
		content: &[u8],
	) -> Self {
		let mut hasher = Sha256::new();
		hasher.update(MESSAGE_ID_DOMAIN);
		hasher.update(sender.user.as_bytes());
		hasher.update(sender.device.as_bytes());
		hasher.update(origin_ts.to_le_bytes());
		hasher.update(nonce);
		// Length-prefixed so that content cannot be shifted against whatever
		// might follow it in a future version of this input.
		hasher.update((content.len() as u64).to_le_bytes());
		hasher.update(content);

		let mut id = [0u8; 32];
		id.copy_from_slice(&hasher.finalize());
		Self(id)
	}

	/// The identity of "nothing seen yet", used as `seen_head` on the first
	/// message of a conversation.
	pub const ROOT: Self = Self([0u8; 32]);

	/// Serde default helper — `ROOT` as a function, for `#[serde(default = ..)]`.
	pub fn root() -> Self {
		Self::ROOT
	}

	pub fn is_root(&self) -> bool {
		*self == Self::ROOT
	}

	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	pub fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}
}

impl std::fmt::Display for MessageId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// Short form — enough to compare by eye in a log without dominating it.
		for byte in &self.0[..8] {
			write!(f, "{byte:02x}")?;
		}
		f.write_str("…")
	}
}

pub fn random_nonce() -> [u8; 16] {
	let mut nonce = [0u8; 16];
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
	nonce
}

/// What a host assigns when it accepts a message into a channel.
///
/// Unused until communities exist (Tier 3), but defined and tested now because
/// retrofitting order onto stored history means migrating every message and
/// every reference to one.
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub struct Placement {
	pub seq: u64,
	/// `MessageId` of `seq - 1` in this channel, or `ROOT` for the first.
	pub prev: MessageId,
	pub server_ts: u64,
}

/// Builds and checks a channel's chain.
///
/// The chain links **message ids**, and an id is a hash of the original
/// content, so blanking a message's stored content (§10.5 tombstoning) leaves
/// its identity and position untouched and the chain still verifies. That
/// property falls out of content-addressing for free and would have been
/// expensive to add later — it is the reason not to chain over stored rows.
#[derive(Debug)]
pub struct Chain {
	head: MessageId,
	next_seq: u64,
}

impl Default for Chain {
	fn default() -> Self {
		Self::new()
	}
}

impl Chain {
	pub fn new() -> Self {
		Self {
			head: MessageId::ROOT,
			next_seq: 1,
		}
	}

	/// Resumes an existing chain, as a host would on restart.
	pub fn resume(head: MessageId, next_seq: u64) -> Self {
		Self { head, next_seq }
	}

	pub fn head(&self) -> MessageId {
		self.head
	}

	pub fn next_seq(&self) -> u64 {
		self.next_seq
	}

	/// Places a message at the end of the chain.
	pub fn append(&mut self, id: MessageId, server_ts: u64) -> Placement {
		let placement = Placement {
			seq: self.next_seq,
			prev: self.head,
			server_ts,
		};

		self.head = id;
		self.next_seq += 1;
		placement
	}

	/// Walks a run of messages and reports where it first breaks.
	///
	/// This is what a member does with a copy of history, and what makes a
	/// rewrite detectable: change any message and its id changes, so every
	/// later `prev` stops matching.
	pub fn verify(
		from: MessageId,
		first_seq: u64,
		messages: &[(MessageId, Placement)],
	) -> Result<(), ChainBreak> {
		let mut expected_prev = from;

		for (offset, (id, placement)) in messages.iter().enumerate() {
			let expected_seq = first_seq + offset as u64;

			if placement.seq != expected_seq {
				return Err(ChainBreak::Sequence {
					expected: expected_seq,
					found: placement.seq,
				});
			}
			if placement.prev != expected_prev {
				return Err(ChainBreak::Link {
					seq: placement.seq,
					expected: expected_prev,
					found: placement.prev,
				});
			}
			expected_prev = *id;
		}

		Ok(())
	}
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainBreak {
	/// A gap or a repeat — messages are missing or duplicated.
	Sequence { expected: u64, found: u64 },
	/// The chain does not join up: something was altered or substituted.
	Link {
		seq: u64,
		expected: MessageId,
		found: MessageId,
	},
}

impl std::fmt::Display for ChainBreak {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Sequence { expected, found } => {
				write!(f, "expected seq {expected}, found {found}")
			}
			Self::Link {
				seq,
				expected,
				found,
			} => write!(
				f,
				"seq {seq} links to {found} but should link to {expected}"
			),
		}
	}
}

impl std::error::Error for ChainBreak {}

/// Bounded record of message ids, for duplicate suppression.
///
/// Sits alongside [`crate::ReplayGuard`], which stops a captured *envelope*
/// being re-sent. This stops the same *message* being processed twice — which
/// matters because decrypting twice would advance an Olm ratchet for something
/// already handled. Retries cause this far more often than attacks do.
///
/// Bounded because a client cache is not the authoritative log: catching
/// duplicates within a useful window is enough.
#[derive(Debug, Clone, Ser, De)]
pub struct SeenWindow {
	ids: std::collections::VecDeque<MessageId>,
	capacity: usize,
}

impl Default for SeenWindow {
	fn default() -> Self {
		Self::new(256)
	}
}

impl SeenWindow {
	pub fn new(capacity: usize) -> Self {
		Self {
			ids: std::collections::VecDeque::new(),
			capacity: capacity.max(1),
		}
	}

	pub fn contains(&self, id: &MessageId) -> bool {
		self.ids.contains(id)
	}

	/// Records an id, reporting whether it was new.
	pub fn observe(&mut self, id: MessageId) -> bool {
		if self.contains(&id) {
			return false;
		}

		self.ids.push_back(id);
		if self.ids.len() > self.capacity {
			self.ids.pop_front();
		}
		true
	}

	pub fn len(&self) -> usize {
		self.ids.len()
	}

	pub fn is_empty(&self) -> bool {
		self.ids.is_empty()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::identity::{DeviceId, UserId};
	use vodozemac::Ed25519SecretKey;

	fn address() -> DeviceAddress {
		DeviceAddress::new(
			UserId::from_master_key(&Ed25519SecretKey::new().public_key()),
			DeviceId::generate(),
		)
	}

	#[test]
	fn an_id_is_a_hash_of_the_message() {
		let sender = address();
		let nonce = random_nonce();

		let id = MessageId::derive(&sender, 100, &nonce, b"hello");
		assert_eq!(id, MessageId::derive(&sender, 100, &nonce, b"hello"));

		// Every input is bound: change any one and the identity changes.
		assert_ne!(id, MessageId::derive(&sender, 100, &nonce, b"hello!"));
		assert_ne!(id, MessageId::derive(&sender, 101, &nonce, b"hello"));
		assert_ne!(
			id,
			MessageId::derive(&sender, 100, &random_nonce(), b"hello")
		);
		assert_ne!(id, MessageId::derive(&address(), 100, &nonce, b"hello"));
	}

	/// A retry reuses its nonce, so it lands on the same id and dedups. Two
	/// deliberately identical messages use different nonces and stay distinct.
	#[test]
	fn retries_dedup_but_repeats_do_not_collide() {
		let sender = address();
		let nonce = random_nonce();

		let sent = MessageId::derive(&sender, 100, &nonce, b"ok");
		let retried = MessageId::derive(&sender, 100, &nonce, b"ok");
		assert_eq!(sent, retried);

		let said_again = MessageId::derive(&sender, 100, &random_nonce(), b"ok");
		assert_ne!(sent, said_again);
	}

	#[test]
	fn a_duplicate_is_only_accepted_once() {
		let sender = address();
		let nonce = random_nonce();
		let id = MessageId::derive(&sender, 1, &nonce, b"hi");

		let mut seen = SeenWindow::default();
		assert!(seen.observe(id), "first sighting is new");
		assert!(!seen.observe(id), "a retry must not be processed twice");
		assert!(seen.contains(&id));
	}

	#[test]
	fn the_seen_window_is_bounded() {
		let sender = address();
		let mut seen = SeenWindow::new(4);

		let ids: Vec<_> = (0..6)
			.map(|n| MessageId::derive(&sender, n, &random_nonce(), b"m"))
			.collect();
		for id in &ids {
			assert!(seen.observe(*id));
		}

		assert_eq!(seen.len(), 4);
		// The oldest have aged out; the newest are still remembered.
		assert!(!seen.contains(&ids[0]));
		assert!(seen.contains(&ids[5]));
	}

	#[test]
	fn a_chain_verifies_end_to_end() {
		let sender = address();
		let mut chain = Chain::new();
		let mut log = Vec::new();

		for n in 0..5u64 {
			let id = MessageId::derive(&sender, n, &random_nonce(), b"m");
			let placement = chain.append(id, 1000 + n);
			log.push((id, placement));
		}

		assert_eq!(chain.next_seq(), 6);
		assert!(Chain::verify(MessageId::ROOT, 1, &log).is_ok());
	}

	/// The property the chain exists for: a member holding a copy can prove
	/// history was altered, because changing a message changes its id and every
	/// later link stops matching.
	#[test]
	fn a_rewritten_message_breaks_the_chain() {
		let sender = address();
		let mut chain = Chain::new();
		let mut log = Vec::new();

		for n in 0..4u64 {
			let id = MessageId::derive(&sender, n, &random_nonce(), b"original");
			let placement = chain.append(id, n);
			log.push((id, placement));
		}
		assert!(Chain::verify(MessageId::ROOT, 1, &log).is_ok());

		// A host rewrites message 2 and re-ids it, leaving the rest alone.
		log[1].0 = MessageId::derive(&sender, 1, &random_nonce(), b"tampered");

		let broken = Chain::verify(MessageId::ROOT, 1, &log).unwrap_err();
		assert!(
			matches!(broken, ChainBreak::Link { seq: 3, .. }),
			"expected the break at the message after the edit, got {broken:?}"
		);
	}

	#[test]
	fn a_dropped_message_is_detected() {
		let sender = address();
		let mut chain = Chain::new();
		let mut log = Vec::new();

		for n in 0..4u64 {
			let id = MessageId::derive(&sender, n, &random_nonce(), b"m");
			let placement = chain.append(id, n);
			log.push((id, placement));
		}

		log.remove(1);
		assert!(matches!(
			Chain::verify(MessageId::ROOT, 1, &log).unwrap_err(),
			ChainBreak::Sequence {
				expected: 2,
				found: 3
			}
		));
	}

	/// Tombstoning (§10.5) blanks content but keeps the id, so the chain still
	/// verifies. This is why the chain links ids rather than stored rows.
	#[test]
	fn tombstoning_does_not_break_the_chain() {
		let sender = address();
		let mut chain = Chain::new();
		let mut log = Vec::new();

		for n in 0..3u64 {
			let id = MessageId::derive(&sender, n, &random_nonce(), b"secret");
			let placement = chain.append(id, n);
			log.push((id, placement));
		}

		// Deleting a message discards its content; the id and placement stay.
		// Nothing about the chain changes.
		assert!(Chain::verify(MessageId::ROOT, 1, &log).is_ok());
	}

	#[test]
	fn a_chain_resumes_across_a_restart() {
		let sender = address();
		let mut chain = Chain::new();
		let mut log = Vec::new();

		for n in 0..3u64 {
			let id = MessageId::derive(&sender, n, &random_nonce(), b"m");
			log.push((id, chain.append(id, n)));
		}

		// Host restarts and resumes from what it stored.
		let mut resumed = Chain::resume(chain.head(), chain.next_seq());
		let id = MessageId::derive(&sender, 99, &random_nonce(), b"after restart");
		log.push((id, resumed.append(id, 99)));

		assert!(Chain::verify(MessageId::ROOT, 1, &log).is_ok());
	}
}

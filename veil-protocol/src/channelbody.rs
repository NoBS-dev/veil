//! What a channel message actually contains — `DESIGN.md` §8.5, §10.1.
//!
//! The wire carries `body: Vec<u8>`, and this is what goes in it. In a Sealed
//! community the whole of this sits inside the Megolm ciphertext, which is the
//! point: **the host cannot read or alter any of it.**
//!
//! It exists to close a gap that documentation alone could not. A host serves
//! the policy chain and can decline to serve its newest record — sequence
//! numbers stop the chain being rewound, but not truncated — so a sender could
//! go on encrypting to a device a controller had already removed, and nobody
//! would notice.
//!
//! Every message now states the sender's view of policy. A recipient compares:
//!
//! - the sender's head is **ahead** of ours → our chain is short. Either we have
//!   not caught up or the host is withholding; either way we go and ask.
//! - the sender's head is **behind** ours → the sender was working from stale
//!   policy, so anything they encrypted may have reached somebody since removed.
//! - same sequence, **different hash** → the host has served two different
//!   chains, which is unambiguous misbehaviour rather than lag.
//!
//! None of this *prevents* withholding, and nothing served by a single host
//! could. It makes it visible, which is the same bargain §10.1 strikes for
//! history — and it is the difference between a silent failure and one somebody
//! notices.

use crate::attachment::Attachment;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ChannelBody {
	/// The sender's policy head when they sent (see module docs).
	pub policy_sequence: u64,
	pub policy_hash: [u8; 32],
	pub content: Content,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Content {
	Text(String),
	File(Attachment),
}

impl ChannelBody {
	pub fn text(head: (u64, [u8; 32]), text: impl Into<String>) -> Self {
		Self {
			policy_sequence: head.0,
			policy_hash: head.1,
			content: Content::Text(text.into()),
		}
	}

	pub fn file(head: (u64, [u8; 32]), attachment: Attachment) -> Self {
		Self {
			policy_sequence: head.0,
			policy_hash: head.1,
			content: Content::File(attachment),
		}
	}

	pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
		Ok(serde_json::to_vec(self)?)
	}

	pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
		Ok(serde_json::from_slice(bytes)?)
	}

	/// How the sender's view of policy compares with ours.
	pub fn compare(&self, ours: (u64, [u8; 32])) -> HeadComparison {
		let (our_sequence, our_hash) = ours;

		if self.policy_sequence == our_sequence {
			if self.policy_hash == our_hash {
				HeadComparison::Agreed
			} else {
				HeadComparison::Forked
			}
		} else if self.policy_sequence > our_sequence {
			HeadComparison::WeAreBehind
		} else {
			HeadComparison::SenderWasBehind
		}
	}
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HeadComparison {
	Agreed,
	/// The sender knew about policy we have not been served. Our host may
	/// simply be slow, or may be withholding.
	WeAreBehind,
	/// The sender had not caught up, so whatever they encrypted was addressed
	/// using policy that has since moved on.
	SenderWasBehind,
	/// The same sequence with a different hash. A host has served two different
	/// chains, and no amount of lag explains it.
	Forked,
}

impl HeadComparison {
	/// Whether this is worth telling a person about.
	pub fn is_notable(&self) -> bool {
		!matches!(self, HeadComparison::Agreed)
	}

	pub fn explain(&self) -> &'static str {
		match self {
			HeadComparison::Agreed => "policy agrees",
			HeadComparison::WeAreBehind => {
				"the sender knew of policy this device has not been served — its host may be \
				 withholding it"
			}
			HeadComparison::SenderWasBehind => {
				"the sender was working from older policy, so this may have been encrypted to \
				 somebody since removed"
			}
			HeadComparison::Forked => {
				"the host has served two different policy chains at the same position — this \
				 is not lag"
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const HEAD: (u64, [u8; 32]) = (7, [3u8; 32]);

	#[test]
	fn a_body_round_trips() {
		let body = ChannelBody::text(HEAD, "hello");
		assert_eq!(ChannelBody::decode(&body.encode().unwrap()).unwrap(), body);
	}

	#[test]
	fn matching_heads_agree() {
		assert_eq!(
			ChannelBody::text(HEAD, "hello").compare(HEAD),
			HeadComparison::Agreed
		);
	}

	/// The case the whole mechanism exists for: our host has not given us
	/// something the sender already had.
	#[test]
	fn a_newer_sender_reveals_that_we_are_short() {
		let comparison = ChannelBody::text((9, [4u8; 32]), "hello").compare(HEAD);

		assert_eq!(comparison, HeadComparison::WeAreBehind);
		assert!(comparison.is_notable());
		assert!(comparison.explain().contains("withholding"));
	}

	/// And the converse, which is the one that matters for safety: the sender
	/// may have encrypted to a device we know has been removed.
	#[test]
	fn an_older_sender_is_flagged() {
		let comparison = ChannelBody::text((2, [1u8; 32]), "hello").compare(HEAD);

		assert_eq!(comparison, HeadComparison::SenderWasBehind);
		assert!(comparison.explain().contains("since removed"));
	}

	/// Same position, different history. Lag cannot explain this.
	#[test]
	fn a_fork_is_distinguished_from_lag() {
		let comparison = ChannelBody::text((7, [9u8; 32]), "hello").compare(HEAD);

		assert_eq!(comparison, HeadComparison::Forked);
		assert!(comparison.explain().contains("not lag"));
	}
}

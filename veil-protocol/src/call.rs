//! Call setup and transport consent — `DESIGN.md` §9.1.
//!
//! **This is not a call.** §9 is explicit that media is foundational work rather
//! than a feature riding on messaging: it needs SRTP with per-frame keying, an
//! SFU that forwards streams it cannot decrypt, and MLS underneath. None of that
//! is here, and none of it should be pretended.
//!
//! What *is* here is the part that is pure protocol and carries the security
//! rules — how a call's transport is agreed. Those rules are easy to state and
//! easy to erode later, which is why they are a state machine with tests rather
//! than a paragraph somebody reads once:
//!
//! - **Relayed by default.** A call should not hand your IP to whoever you are
//!   talking to (§3.2 applied to media). The relay costs bandwidth, and that is
//!   the price of the property.
//! - **P2P needs *both* parties.** It exposes both IPs, and the person with the
//!   bad connection does not get to make that trade for the other one.
//! - **Per-call, never sticky.** §9.1 calls a preference that carries silently
//!   into a call with a stranger a security failure, in those words. So consent
//!   does not outlive the call it was given for.

use crate::identity::DeviceAddress;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// How a call's media travels.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
	/// Through the home server. Neither party learns the other's address.
	#[default]
	Relayed,
	/// Direct. Both parties have agreed to expose their addresses to each other.
	DirectPeerToPeer,
}

/// Who has agreed to what, for one call.
///
/// Dropped when the call ends. Nothing here is persisted, which is what makes
/// "per-call, never sticky" structural rather than a convention.
#[derive(Debug, Clone, Default)]
pub struct Negotiation {
	we_offered_direct: bool,
	they_offered_direct: bool,
	/// Set once either side withdraws, and never cleared.
	///
	/// A refusal that could be reversed by asking again is not a refusal — it is
	/// a prompt to wear somebody down.
	withdrawn: bool,
}

impl Negotiation {
	pub fn new() -> Self {
		Self::default()
	}

	/// The transport this call is using now.
	pub fn transport(&self) -> Transport {
		if self.we_offered_direct && self.they_offered_direct && !self.withdrawn {
			Transport::DirectPeerToPeer
		} else {
			Transport::Relayed
		}
	}

	/// This side offers to go direct.
	pub fn offer_direct(&mut self) {
		if !self.withdrawn {
			self.we_offered_direct = true;
		}
	}

	/// The other side offers to go direct.
	pub fn peer_offers_direct(&mut self) {
		if !self.withdrawn {
			self.they_offered_direct = true;
		}
	}

	/// Either side withdraws, at any point.
	///
	/// Falls back to relayed immediately and stays there for the rest of the
	/// call. Someone who changes their mind mid-call has changed it.
	pub fn withdraw(&mut self) {
		self.withdrawn = true;
	}

	/// Whether this side has offered and is waiting on the other.
	pub fn awaiting_peer(&self) -> bool {
		self.we_offered_direct && !self.they_offered_direct && !self.withdrawn
	}

	/// What to tell the person before they decide.
	///
	/// §9.1 wants the trade presented rather than hidden: the expensive case and
	/// the case where people least mind exposing an address — streaming to a
	/// friend — are the same case, so the honest framing is a choice and not a
	/// setting.
	pub fn explain_direct() -> &'static str {
		"Going direct shows your network address to the other person, and theirs to \
		 you. It is usually faster and costs your home server nothing. It applies to \
		 this call only."
	}
}

/// Who connects to whom in a group call — `DESIGN.md` §9.
///
/// **Full mesh: every participant holds a session with every other.** No SFU, so
/// there is nothing in the middle to keep out of the trust set, and no group key
/// to distribute — a mesh call needs exactly the cryptography a 1:1 call needs,
/// which is none beyond what WebRTC already does.
///
/// What it does not do is scale. Each participant uploads their stream once per
/// other participant, so cost grows as `n-1` per person and `n(n-1)/2` overall.
/// §9.1's figures make the shape clear: voice at 50–64 kbps is comfortable for a
/// handful, and video at 1–3 Mbps is not. That is the trade, and it is why the
/// SFU exists further up the design rather than being absent by oversight.
pub struct Mesh;

/// Beyond this, a mesh stops being kind to the participant with the worst
/// connection.
///
/// Five is where voice is still comfortable — four uploads at 64 kbps is about
/// 256 kbps, which a domestic connection carries without noticing. Video is
/// already marginal at four. The cap is deliberately low rather than optimistic:
/// a call that degrades for everyone because one more person joined is worse
/// than one that says no.
pub const MESH_LIMIT: usize = 5;

impl Mesh {
	/// Whether a call of this size should use a mesh at all.
	pub fn viable(participants: usize) -> bool {
		(2..=MESH_LIMIT).contains(&participants)
	}

	/// The devices `me` should send an offer to.
	///
	/// **Exactly one side of each pair offers**, decided by comparing addresses.
	/// Both offering is "glare" — two half-negotiated sessions that each think
	/// they are the caller — and the usual fix is a tie-break rather than
	/// coordination, because coordination needs a round trip that a peer-to-peer
	/// call does not otherwise have.
	///
	/// Ordering by address is arbitrary but *stable and shared*: every
	/// participant computes the same answer from the same roster without
	/// asking anyone.
	pub fn offers_from(me: &DeviceAddress, roster: &BTreeSet<DeviceAddress>) -> Vec<DeviceAddress> {
		roster
			.iter()
			.filter(|other| *other != me && me < other)
			.copied()
			.collect()
	}

	/// The devices `me` should expect an offer from.
	pub fn answers_from(
		me: &DeviceAddress,
		roster: &BTreeSet<DeviceAddress>,
	) -> Vec<DeviceAddress> {
		roster
			.iter()
			.filter(|other| *other != me && *other < me)
			.copied()
			.collect()
	}

	/// How many streams `me` will be sending.
	///
	/// Exposed because it is the number that decides whether a mesh is a good
	/// idea, and a UI that offers the choice should be able to say it.
	pub fn upload_streams(roster: &BTreeSet<DeviceAddress>) -> usize {
		roster.len().saturating_sub(1)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The default is the one that protects both parties, because a default is
	/// what most calls will use.
	#[test]
	fn a_call_starts_relayed() {
		assert_eq!(Negotiation::new().transport(), Transport::Relayed);
	}

	/// One side wanting it is not enough. P2P exposes both addresses, and the
	/// person with the bad connection does not get to trade the other's away.
	#[test]
	fn one_side_cannot_choose_direct_alone() {
		let mut call = Negotiation::new();

		call.offer_direct();
		assert_eq!(
			call.transport(),
			Transport::Relayed,
			"our offer alone must not move the call"
		);
		assert!(call.awaiting_peer());

		let mut other = Negotiation::new();
		other.peer_offers_direct();
		assert_eq!(
			other.transport(),
			Transport::Relayed,
			"their offer alone must not move it either"
		);
	}

	/// The control: with both, it goes direct — otherwise the tests above would
	/// pass against a negotiation that never agreed to anything.
	#[test]
	fn both_sides_agreeing_goes_direct() {
		let mut call = Negotiation::new();
		call.offer_direct();
		call.peer_offers_direct();

		assert_eq!(call.transport(), Transport::DirectPeerToPeer);
		assert!(!call.awaiting_peer());
	}

	/// Either side may change its mind, and the call falls back at once.
	#[test]
	fn withdrawing_returns_to_relayed() {
		let mut call = Negotiation::new();
		call.offer_direct();
		call.peer_offers_direct();
		assert_eq!(call.transport(), Transport::DirectPeerToPeer);

		call.withdraw();
		assert_eq!(call.transport(), Transport::Relayed);
	}

	/// A refusal that can be undone by asking again is not a refusal.
	#[test]
	fn a_withdrawal_cannot_be_talked_back_out_of() {
		let mut call = Negotiation::new();
		call.offer_direct();
		call.peer_offers_direct();
		call.withdraw();

		call.offer_direct();
		call.peer_offers_direct();

		assert_eq!(
			call.transport(),
			Transport::Relayed,
			"re-offering after a withdrawal must not resume direct media"
		);
	}

	/// §9.1 in its own words: a preference that carries silently into a call
	/// with a stranger is a security failure. A fresh call is a fresh decision.
	#[test]
	fn consent_does_not_survive_the_call_it_was_given_for() {
		let mut first = Negotiation::new();
		first.offer_direct();
		first.peer_offers_direct();
		assert_eq!(first.transport(), Transport::DirectPeerToPeer);

		// The next call is a new negotiation, because there is nowhere for the
		// old one to have been kept.
		let second = Negotiation::new();
		assert_eq!(
			second.transport(),
			Transport::Relayed,
			"a new call must start relayed however the last one ended"
		);
	}

	/// The choice is presented rather than hidden, and says what it costs.
	#[test]
	fn the_trade_is_stated_plainly() {
		let explanation = Negotiation::explain_direct();

		assert!(
			explanation.contains("address"),
			"it must name what is exposed"
		);
		assert!(
			explanation.contains("this call only"),
			"and that it does not carry forward"
		);
	}

	fn address(seed: u8) -> DeviceAddress {
		use crate::{crosssign::CrossSigningSecrets, identity::DeviceId};
		let _ = seed;
		DeviceAddress::new(CrossSigningSecrets::new().user_id(), DeviceId::generate())
	}

	fn roster(n: usize) -> BTreeSet<DeviceAddress> {
		(0..n).map(|i| address(i as u8)).collect()
	}

	/// Every pair connects, and exactly once. Both sides offering is glare: two
	/// half-negotiated sessions that each think they are the caller.
	#[test]
	fn exactly_one_side_of_each_pair_offers() {
		let roster = roster(5);

		for a in &roster {
			for b in &roster {
				if a == b {
					continue;
				}

				let a_offers = Mesh::offers_from(a, &roster).contains(b);
				let b_offers = Mesh::offers_from(b, &roster).contains(a);

				assert!(
					a_offers ^ b_offers,
					"exactly one of a pair must offer, or the two sides collide"
				);
			}
		}
	}

	/// Offers and answers have to be the same set seen from opposite ends, or
	/// somebody waits forever for a call that was never placed.
	#[test]
	fn every_offer_is_expected_by_its_recipient() {
		let roster = roster(4);

		for me in &roster {
			for target in Mesh::offers_from(me, &roster) {
				assert!(
					Mesh::answers_from(&target, &roster).contains(me),
					"an offer must be one the other side is waiting for"
				);
			}
		}
	}

	/// Nobody calls themselves.
	#[test]
	fn a_participant_does_not_connect_to_itself() {
		let roster = roster(3);

		for me in &roster {
			assert!(!Mesh::offers_from(me, &roster).contains(me));
			assert!(!Mesh::answers_from(me, &roster).contains(me));
		}
	}

	/// Every participant computes the same topology from the same roster,
	/// without asking anyone — which is what lets a mesh form with no
	/// coordinating round trip.
	#[test]
	fn the_topology_needs_no_coordination() {
		let roster = roster(4);

		let legs: usize = roster
			.iter()
			.map(|me| Mesh::offers_from(me, &roster).len())
			.sum();

		assert_eq!(
			legs,
			4 * 3 / 2,
			"a mesh of four is six sessions, each set up by exactly one end"
		);
	}

	/// A call that degrades for everyone because one more person joined is
	/// worse than one that says no.
	#[test]
	fn a_mesh_refuses_to_grow_past_what_it_can_carry() {
		assert!(Mesh::viable(2), "a pair is the ordinary case");
		assert!(Mesh::viable(MESH_LIMIT));
		assert!(
			!Mesh::viable(MESH_LIMIT + 1),
			"past the limit this needs an SFU, not optimism"
		);
		assert!(!Mesh::viable(1), "a call needs somebody else in it");
	}

	/// The number that decides whether a mesh is a good idea, so a UI offering
	/// the choice can say it.
	#[test]
	fn upload_cost_is_one_stream_per_other_participant() {
		assert_eq!(Mesh::upload_streams(&roster(2)), 1);
		assert_eq!(Mesh::upload_streams(&roster(5)), 4);
	}
}

//! Protocol version negotiation — `DESIGN.md` §3.6.
//!
//! Anyone can run a server, so **version skew is the normal state, not an edge
//! case**: operators run whatever they installed two years ago. A protocol with
//! no negotiation story fragments the network the first time it changes.
//!
//! The negotiation itself must be tamper-proof. If an attacker can edit the
//! advertised ranges in flight, they force both sides onto the oldest mutually
//! supported version and attack that instead — the downgrade family that
//! produced FREAK, Logjam and POODLE against TLS. Both ranges therefore travel
//! **inside already-signed envelopes**, and each side echoes back what it saw so
//! the other can confirm it arrived unaltered.

use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as De, Serialize as Ser};

/// Oldest version this build can speak.
///
/// Raising this cuts off every peer that has not updated, which §3.6 treats as a
/// §1.3 concern rather than a routine change: support at least the previous two
/// major versions, for a minimum of two years, and warn in-app well beforehand.
pub const MIN_SUPPORTED: u16 = 1;

/// Newest version this build can speak.
pub const MAX_SUPPORTED: u16 = 1;

/// A contiguous range of protocol versions a peer can speak.
///
/// A **range**, not just a maximum. Comparing maxima alone works only while
/// everyone still supports every version back to 1 — and old versions get
/// dropped for exactly the reasons that produced new ones. A peer speaking 3–5
/// meeting one speaking 1–2 has to fail cleanly, not "agree" on 2 that the first
/// cannot speak.
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub struct VersionRange {
	pub min: u16,
	pub max: u16,
}

impl VersionRange {
	/// What this build supports.
	pub const fn supported() -> Self {
		Self {
			min: MIN_SUPPORTED,
			max: MAX_SUPPORTED,
		}
	}

	pub const fn new(min: u16, max: u16) -> Self {
		Self { min, max }
	}

	pub fn is_well_formed(&self) -> bool {
		self.min > 0 && self.min <= self.max
	}

	pub fn contains(&self, version: u16) -> bool {
		version >= self.min && version <= self.max
	}

	/// The highest version both sides can speak, or an error naming the
	/// mismatch.
	///
	/// Failing loudly is the point: a peer that cannot be talked to should say
	/// so, not silently settle on something one side does not implement.
	pub fn agree(&self, other: &Self) -> anyhow::Result<u16> {
		if !self.is_well_formed() || !other.is_well_formed() {
			anyhow::bail!("malformed version range: {self} against {other}");
		}

		let agreed = self.max.min(other.max);

		if !self.contains(agreed) || !other.contains(agreed) {
			anyhow::bail!(
				"no shared protocol version: this build speaks {self}, the peer speaks {other}"
			);
		}

		Ok(agreed)
	}
}

impl Default for VersionRange {
	fn default() -> Self {
		Self::supported()
	}
}

impl std::fmt::Display for VersionRange {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.min == self.max {
			write!(f, "v{}", self.min)
		} else {
			write!(f, "v{}-v{}", self.min, self.max)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn overlapping_ranges_agree_on_the_highest_shared_version() {
		assert_eq!(
			VersionRange::new(1, 5)
				.agree(&VersionRange::new(1, 4))
				.unwrap(),
			4
		);
		assert_eq!(
			VersionRange::new(2, 3)
				.agree(&VersionRange::new(1, 9))
				.unwrap(),
			3
		);
		assert_eq!(
			VersionRange::new(4, 4)
				.agree(&VersionRange::new(4, 4))
				.unwrap(),
			4
		);
	}

	/// Why a range and not just a maximum: once old versions start being
	/// dropped, comparing maxima alone would "agree" on a version one side
	/// cannot speak.
	#[test]
	fn disjoint_ranges_fail_rather_than_agreeing_on_nothing() {
		// min(5, 2) = 2, which the first peer does not support.
		let modern = VersionRange::new(3, 5);
		let ancient = VersionRange::new(1, 2);

		assert!(modern.agree(&ancient).is_err());
		assert!(ancient.agree(&modern).is_err());
	}

	#[test]
	fn agreement_is_symmetric() {
		let a = VersionRange::new(1, 7);
		let b = VersionRange::new(3, 5);
		assert_eq!(a.agree(&b).unwrap(), b.agree(&a).unwrap());
	}

	#[test]
	fn malformed_ranges_are_refused() {
		assert!(
			VersionRange::new(0, 3)
				.agree(&VersionRange::supported())
				.is_err()
		);
		assert!(
			VersionRange::new(5, 2)
				.agree(&VersionRange::supported())
				.is_err()
		);
		assert!(
			VersionRange::supported()
				.agree(&VersionRange::new(9, 4))
				.is_err()
		);
	}

	#[test]
	fn this_build_agrees_with_itself() {
		let mine = VersionRange::supported();
		assert!(mine.is_well_formed());
		assert_eq!(mine.agree(&mine).unwrap(), MAX_SUPPORTED);
	}
}

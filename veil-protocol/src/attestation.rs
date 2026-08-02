//! Home server attestations — `DESIGN.md` §11.2.
//!
//! The blind relay collapses every user behind one address, so per-IP limiting
//! at a community host is meaningless. Per-`UserId` limiting does not save it
//! either, because **identity is free**: a `UserId` is a keypair, and an
//! attacker running one home server can mint ten thousand.
//!
//! So trust is anchored one level up. A user presents a short-lived signed
//! statement from their home server, and the server stakes its standing on the
//! users it vouches for. Community hosts then throttle and block at home-server
//! granularity.
//!
//! Two things this is deliberately **not**:
//!
//! - **Not an identity mechanism.** A home server can refuse to vouch for a
//!   user; it cannot forge who they are. Identity is self-certifying (§5.1) and
//!   nothing here touches it.
//! - **Not a claim about verification.** §11.2.1 has each community check
//!   whatever it requires *itself*, because a delegated claim is one a malicious
//!   server writes for free. This says only "this account is registered with
//!   me".

use crate::identity::UserId;
use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as De, Serialize as Ser};
use serde_with::serde_as;
use vodozemac::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

const ATTESTATION_DOMAIN: &[u8] = b"veil-home-server-attestation-v1";

/// How long an attestation stays good. Short, because lapsing *is* the
/// revocation mechanism — a home server that stops vouching for a user simply
/// stops reissuing.
pub const DEFAULT_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

#[serde_as]
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub struct Attestation {
	pub user: UserId,
	pub home_server: [u8; 32],
	pub issued_at: u64,
	pub expires_at: u64,
	#[serde_as(as = "[_; 64]")]
	pub signature: [u8; 64],
}

fn signing_input(
	user: &UserId,
	home_server: &[u8; 32],
	issued_at: u64,
	expires_at: u64,
) -> Vec<u8> {
	let mut buffer = Vec::with_capacity(ATTESTATION_DOMAIN.len() + 16 + 32 + 16);
	buffer.extend_from_slice(ATTESTATION_DOMAIN);
	buffer.extend_from_slice(user.as_bytes());
	buffer.extend_from_slice(home_server);
	buffer.extend_from_slice(&issued_at.to_le_bytes());
	buffer.extend_from_slice(&expires_at.to_le_bytes());
	buffer
}

impl Attestation {
	/// Issued by a home server for one of its users.
	pub fn issue(key: &Ed25519SecretKey, user: UserId, issued_at: u64, lifetime_ms: u64) -> Self {
		let home_server = *key.public_key().as_bytes();
		let expires_at = issued_at.saturating_add(lifetime_ms);

		Self {
			user,
			home_server,
			issued_at,
			expires_at,
			signature: key
				.sign(&signing_input(&user, &home_server, issued_at, expires_at))
				.to_bytes(),
		}
	}

	/// Checks the signature and that it has not lapsed.
	///
	/// `now` is passed rather than read, so a host on a synchronised clock
	/// (§13.4) judges expiry by network time rather than its own drift.
	pub fn verify(&self, now: u64) -> anyhow::Result<()> {
		if self.expires_at <= self.issued_at {
			anyhow::bail!("attestation expires before it was issued");
		}
		if now >= self.expires_at {
			anyhow::bail!(
				"attestation for {} lapsed {}s ago",
				self.user,
				(now - self.expires_at) / 1000
			);
		}

		let key = Ed25519PublicKey::from_slice(&self.home_server)?;
		key.verify(
			&signing_input(
				&self.user,
				&self.home_server,
				self.issued_at,
				self.expires_at,
			),
			&Ed25519Signature::from_slice(&self.signature)?,
		)
		.map_err(|e| anyhow::anyhow!("attestation signature is invalid: {e}"))?;

		Ok(())
	}
}

/// What a community host has decided about a home server.
///
/// **Trust is earned automatically, never granted by an authority** (§11.4).
/// A server nobody has heard of is throttled, not blocked, and earns headroom
/// through time and clean behaviour tracked locally. There is no registry to
/// petition, because a registry is how email made self-hosting impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
	/// Never seen. Admitted, but on a short leash.
	Unknown,
	/// Seen for a while with nothing against it.
	Established,
	/// Locally blocked by this host's operator.
	Blocked,
}

/// Per-home-server reputation, held locally by one community host.
///
/// Scope this narrowly on purpose: since §11.2.1 moved verification to be
/// direct, standing no longer adjudicates *identity* — it only rate-limits
/// traffic. Letting it grow back into a trust oracle is how the centralisation
/// in §11.4 starts.
#[derive(Debug, Default)]
pub struct Reputation {
	seen: std::collections::HashMap<[u8; 32], FirstSeen>,
	blocked: std::collections::HashSet<[u8; 32]>,
}

#[derive(Debug, Clone, Copy)]
struct FirstSeen {
	at: u64,
	requests: u64,
}

/// How long a home server must have been around before it stops being new.
pub const ESTABLISHED_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000;

impl Reputation {
	pub fn new() -> Self {
		Self::default()
	}

	/// Records a sighting and reports where the server stands.
	pub fn observe(&mut self, home_server: [u8; 32], now: u64) -> Standing {
		if self.blocked.contains(&home_server) {
			return Standing::Blocked;
		}

		let entry = self.seen.entry(home_server).or_insert(FirstSeen {
			at: now,
			requests: 0,
		});
		entry.requests += 1;

		if now.saturating_sub(entry.at) >= ESTABLISHED_AFTER_MS {
			Standing::Established
		} else {
			Standing::Unknown
		}
	}

	/// A local decision by this operator. Never shared as an oracle — §11.4
	/// allows blocklists to be *offered*, never required.
	pub fn block(&mut self, home_server: [u8; 32]) {
		self.blocked.insert(home_server);
	}

	pub fn unblock(&mut self, home_server: [u8; 32]) {
		self.blocked.remove(&home_server);
	}

	/// Requests allowed per window, by standing. A new server is throttled
	/// rather than refused, so it can earn its way up without asking anyone.
	pub fn budget(standing: Standing) -> u32 {
		match standing {
			Standing::Blocked => 0,
			Standing::Unknown => 10,
			Standing::Established => 120,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn server() -> Ed25519SecretKey {
		Ed25519SecretKey::new()
	}

	fn user() -> UserId {
		UserId::from_master_key(&Ed25519SecretKey::new().public_key())
	}

	#[test]
	fn an_attestation_verifies_while_it_is_current() {
		let key = server();
		let attestation = Attestation::issue(&key, user(), 1_000, DEFAULT_LIFETIME_MS);

		assert!(attestation.verify(1_000).is_ok());
		assert!(attestation.verify(1_000 + DEFAULT_LIFETIME_MS / 2).is_ok());
	}

	/// Lapsing is the revocation mechanism, so expiry has to actually bite.
	#[test]
	fn a_lapsed_attestation_is_refused() {
		let attestation = Attestation::issue(&server(), user(), 1_000, 60_000);
		assert!(attestation.verify(1_000 + 60_001).is_err());
	}

	#[test]
	fn an_attestation_cannot_be_edited() {
		let key = server();
		let original = Attestation::issue(&key, user(), 1_000, 60_000);

		// Extending its life.
		let mut extended = original.clone();
		extended.expires_at += 10_000_000;
		assert!(extended.verify(1_000).is_err());

		// Reusing it for somebody else.
		let mut lifted = original.clone();
		lifted.user = user();
		assert!(lifted.verify(1_000).is_err());
	}

	/// A home server can decline to vouch for someone; it cannot forge who they
	/// are. Signing with the wrong key proves nothing about the user.
	#[test]
	fn a_forged_attestation_does_not_verify() {
		let real = server();
		let impostor = server();

		let mut forged = Attestation::issue(&impostor, user(), 1_000, 60_000);
		forged.home_server = *real.public_key().as_bytes();

		assert!(forged.verify(1_000).is_err());
	}

	/// §11.4: a new server is throttled, not blocked, and earns headroom by
	/// existing rather than by petitioning anyone.
	#[test]
	fn standing_is_earned_by_time_not_granted() {
		let mut reputation = Reputation::new();
		let home = [7u8; 32];

		assert_eq!(reputation.observe(home, 0), Standing::Unknown);
		assert!(
			Reputation::budget(Standing::Unknown) > 0,
			"throttled, not blocked"
		);

		assert_eq!(
			reputation.observe(home, ESTABLISHED_AFTER_MS + 1),
			Standing::Established
		);
		assert!(Reputation::budget(Standing::Established) > Reputation::budget(Standing::Unknown));
	}

	#[test]
	fn blocking_is_a_local_decision_and_reversible() {
		let mut reputation = Reputation::new();
		let home = [7u8; 32];

		reputation.observe(home, 0);
		reputation.block(home);
		assert_eq!(reputation.observe(home, 0), Standing::Blocked);
		assert_eq!(Reputation::budget(Standing::Blocked), 0);

		reputation.unblock(home);
		assert_ne!(reputation.observe(home, 0), Standing::Blocked);
	}
}

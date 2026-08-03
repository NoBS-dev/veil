//! Invites — `DESIGN.md` §3.2, §11.6.
//!
//! An invite is how somebody first reaches a community, and it is the natural
//! place to close the one gap trust-on-first-use leaves.
//!
//! **The problem it solves.** A client reaching a host through a relay pins that
//! host's identity key the first time it sees it (invariant 6). Every connection
//! after that is protected — but on the *first* one there is nothing to compare
//! against, so a hostile relay could send a newcomer to a different genuine Veil
//! host and they would pin the wrong key. Every later check would then pass,
//! against the wrong server.
//!
//! Nothing about the connection can fix that, because the newcomer has no prior
//! knowledge to check against. The fix has to come from outside the connection —
//! and it already does, because invites travel as links and QR codes rather than
//! being discovered on the network. So the invite carries the host's identity
//! key, and the client refuses a host that does not sign with it.
//!
//! That moves the trust decision to where it belongs: whoever shared the link.
//! It does not eliminate trust, and pretending otherwise would be the sort of
//! claim §14 warns against — a forged invite is still a forged invite. What it
//! does is stop the *relay*, which the user did not choose to trust with this,
//! from making the decision.

use crate::community::CommunityId;
use data_encoding::BASE32_NOPAD;

/// Everything needed to reach a community for the first time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
	pub community: CommunityId,
	/// Where the community lives, as `host:port`.
	pub host: String,
	/// The host's Ed25519 identity key.
	///
	/// Present so a newcomer can check the very first challenge, rather than
	/// pinning whatever answers.
	pub host_key: [u8; 32],
}

impl Invite {
	/// Renders as a single string, for a link or a QR code.
	pub fn encode(&self) -> String {
		format!(
			"veil:{}:{}:{}",
			self.community,
			BASE32_NOPAD.encode(&self.host_key),
			self.host
		)
	}

	pub fn parse(text: &str) -> anyhow::Result<Self> {
		let text = text.trim();
		let rest = text
			.strip_prefix("veil:")
			.ok_or_else(|| anyhow::anyhow!("an invite starts with 'veil:'"))?;

		// The host is last and may itself contain a colon, so split from the
		// left exactly twice rather than splitting on every colon.
		let (community, rest) = rest
			.split_once(':')
			.ok_or_else(|| anyhow::anyhow!("an invite has three parts"))?;
		let (key, host) = rest
			.split_once(':')
			.ok_or_else(|| anyhow::anyhow!("an invite has three parts"))?;

		if host.is_empty() {
			anyhow::bail!("an invite must name a host");
		}

		let key = BASE32_NOPAD
			.decode(key.trim().to_ascii_uppercase().as_bytes())
			.map_err(|e| anyhow::anyhow!("the host key is not valid base32: {e}"))?;

		Ok(Self {
			community: CommunityId::parse(community)?,
			host: host.to_owned(),
			host_key: key
				.as_slice()
				.try_into()
				.map_err(|_| anyhow::anyhow!("a host key is 32 bytes; got {}", key.len()))?,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		community::{CommunityRoot, Mode},
		crosssign::CrossSigningSecrets,
	};

	fn invite() -> Invite {
		let founder = CrossSigningSecrets::new();
		let root = CommunityRoot::found(
			Mode::Sealed,
			vec![founder.master_public()],
			1,
			founder.master_secret(),
			1_000,
		)
		.unwrap();

		Invite {
			community: root.id(),
			host: "veil.example:9876".into(),
			host_key: [42u8; 32],
		}
	}

	#[test]
	fn an_invite_round_trips() {
		let invite = invite();
		assert_eq!(Invite::parse(&invite.encode()).unwrap(), invite);
	}

	/// The host is last precisely so it can carry a port, which contains the
	/// same separator the invite uses.
	#[test]
	fn a_host_may_contain_a_port() {
		let invite = invite();
		assert_eq!(
			Invite::parse(&invite.encode()).unwrap().host,
			"veil.example:9876"
		);
	}

	#[test]
	fn junk_is_refused() {
		for bad in [
			"",
			"veil:",
			"not-an-invite",
			"veil:AAAA",
			"veil:AAAA:BBBB",             // no host
			"https://example.com/invite", // a link, but not one of ours
		] {
			assert!(Invite::parse(bad).is_err(), "{bad:?} should not parse");
		}
	}

	/// A truncated key must not be accepted and silently zero-padded — that
	/// would make the check it exists for meaningless.
	#[test]
	fn a_short_host_key_is_refused() {
		let invite = invite();
		let encoded = invite.encode();
		let mangled = encoded.replace(&BASE32_NOPAD.encode(&invite.host_key), "AAAA");

		let error = Invite::parse(&mangled).unwrap_err();
		assert!(format!("{error}").contains("32 bytes"));
	}
}

//! Finding people — `DESIGN.md` §11.6.
//!
//! Three layers, and keeping them distinct is the whole design:
//!
//! - **Identity** is the `UserId`, derived from a public key. Self-certifying,
//!   portable, never changes.
//! - **Address** is `alice@veil.example`. Human-usable, server-controlled, and
//!   **re-assignable**.
//! - **Sharing** is a link carrying the whole `UserId`.
//!
//! **Sharing carries the whole key, so there is nothing to substitute.** A link
//! contains the identity itself rather than a name to look up, which removes the
//! substitution attack rather than mitigating it — no directory is consulted, so
//! no directory answer can be falsified.
//!
//! That matters because anything a server tells you, that server can lie about.
//! If somebody resolves `alice@veil.example` and the host is compromised, it can
//! hand back an attacker's identity and sit in the middle. A link that already
//! contains Alice's key has no such step.
//!
//! So resolution exists **only** for somebody typing an address by hand. It is
//! trust on first use, safety numbers (§6.1) remain the real verification, and
//! the client warns loudly if an alias later resolves to a different identity.

use crate::{messaging, state::State};
use anyhow::Result;
use veil_protocol::identity::UserId;

/// A contact, as shared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
	pub user: UserId,
	/// Where their mail goes. A hint for delivery, not part of who they are —
	/// identity carries no hostname (§5.3), which is what makes people portable.
	pub host: String,
}

impl Contact {
	pub fn encode(&self) -> String {
		format!("veil-user:{}:{}", self.user, self.host)
	}

	pub fn parse(text: &str) -> Result<Self> {
		let rest = text
			.trim()
			.strip_prefix("veil-user:")
			.ok_or_else(|| anyhow::anyhow!("a contact link starts with 'veil-user:'"))?;

		// The host is last and carries a port, which contains the separator.
		let (user, host) = rest
			.split_once(':')
			.ok_or_else(|| anyhow::anyhow!("a contact link has an identity and a host"))?;

		if host.is_empty() {
			anyhow::bail!("a contact link must name a host");
		}

		Ok(Self {
			user: UserId::parse(user)?,
			host: host.to_owned(),
		})
	}
}

/// Resolves `name@host` to the identity behind it, pinning what comes back.
///
/// Trust on first use and nothing more. The pin is what makes a later change
/// visible: an operator may genuinely have reassigned the name, but that and an
/// impersonation look identical from here, so neither is absorbed silently.
pub async fn resolve(state: &mut State, address: &str) -> Result<Contact> {
	let (name, host) = address
		.trim()
		.split_once('@')
		.ok_or_else(|| anyhow::anyhow!("an address looks like name@host"))?;

	let resolved = messaging::directory_client()?
		.get(format!("http://{host}/aliases/{}", name.to_lowercase()))
		.send()
		.await?
		.error_for_status()?
		.text()
		.await?;

	let user = UserId::parse(resolved.trim())?;
	state.pin_alias(address.trim(), user)?;

	Ok(Contact {
		user,
		host: host.to_owned(),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use veil_protocol::crosssign::CrossSigningSecrets;

	fn contact() -> Contact {
		Contact {
			user: CrossSigningSecrets::new().user_id(),
			host: "veil.example:9876".into(),
		}
	}

	/// A link carries the identity itself, which is what removes the
	/// substitution attack: there is no lookup to falsify.
	#[test]
	fn a_contact_link_carries_the_whole_identity() {
		let contact = contact();
		let parsed = Contact::parse(&contact.encode()).unwrap();

		assert_eq!(parsed, contact);
		assert!(
			contact.encode().contains(&contact.user.to_string()),
			"the identity travels in the link rather than being looked up"
		);
	}

	#[test]
	fn a_host_may_carry_a_port() {
		let parsed = Contact::parse(&contact().encode()).unwrap();
		assert_eq!(parsed.host, "veil.example:9876");
	}

	#[test]
	fn junk_is_refused() {
		for bad in [
			"",
			"veil-user:",
			"alice@example",
			"veil-user:AAAA",
			"https://example",
		] {
			assert!(Contact::parse(bad).is_err(), "{bad:?} should not parse");
		}
	}
}

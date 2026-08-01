use anyhow::Result;
use keyring::Entry;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;
use std::collections::HashMap;
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};

fn serialize_session<S: Serializer>(session: &Session, serializer: S) -> Result<S::Ok, S::Error> {
	session.pickle().serialize(serializer)
}
fn deserialize_session<'a, D: Deserializer<'a>>(deserializer: D) -> Result<Session, D::Error> {
	Ok(Session::from_pickle(SessionPickle::deserialize(
		deserializer,
	)?))
}
#[derive(Deserialize, Serialize)]
pub struct PeerSession {
	pub x25519: [u8; 32],
	#[serde(
		serialize_with = "serialize_session",
		deserialize_with = "deserialize_session"
	)]
	pub session: Session,
}

fn serialize_account<S: Serializer>(account: &Account, serializer: S) -> Result<S::Ok, S::Error> {
	account.pickle().serialize(serializer)
}
fn deserialize_account<'a, D: Deserializer<'a>>(deserializer: D) -> Result<Account, D::Error> {
	Ok(Account::from_pickle(AccountPickle::deserialize(
		deserializer,
	)?))
}
#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct State {
	#[serde(
		serialize_with = "serialize_account",
		deserialize_with = "deserialize_account"
	)]
	pub account: Account,
	#[serde_as(as = "Vec<(_, _)>")]
	pub peers: HashMap<[u8; 32], PeerSession>,
	pub ip_and_port: Box<str>,
	pub profile: Box<str>,
	/// Pinned on first connect. A server that later signs with a different key
	/// is refused rather than trusted afresh.
	#[serde(default)]
	pub server_identity: Option<[u8; 32]>,
	#[serde(default)]
	pub use_tls: bool,
}
impl State {
	pub fn new(server_address: &str, profile: &str) -> Result<Self> {
		let (ip_and_port, use_tls) = parse_server_address(server_address);

		Ok(Self {
			account: Account::new(),
			peers: HashMap::new(),
			ip_and_port,
			profile: normalized_profile(profile).into(),
			server_identity: None,
			use_tls,
		})
	}

	pub fn schemes(&self) -> (&'static str, &'static str) {
		if self.use_tls {
			("wss", "https")
		} else {
			("ws", "http")
		}
	}

	pub fn load_from_keyring(profile: &str) -> Result<Self> {
		Ok(serde_json::from_str(&entry_for(profile)?.get_password()?)?)
	}

	pub fn save_to_keyring(&self) -> Result<()> {
		entry_for(&self.profile)?.set_password(&serde_json::to_string(&self)?)?;
		Ok(())
	}

	pub fn delete_from_keyring(&self) -> Result<()> {
		entry_for(&self.profile)?.delete_password()?;
		Ok(())
	}
}

/// Accepts `host:port`, `ws://host:port` or `wss://host:port`, splitting the
/// transport choice out from the authority.
fn parse_server_address(input: &str) -> (Box<str>, bool) {
	let input = input.trim();

	for (prefix, use_tls) in [
		("wss://", true),
		("https://", true),
		("ws://", false),
		("http://", false),
	] {
		if let Some(authority) = input.strip_prefix(prefix) {
			return (authority.trim_end_matches('/').into(), use_tls);
		}
	}

	(input.into(), false)
}

pub fn normalized_profile(profile: &str) -> &str {
	let profile = profile.trim();
	if profile.is_empty() || profile.eq_ignore_ascii_case("default") {
		"default"
	} else {
		profile
	}
}

fn entry_for(profile: &str) -> Result<Entry> {
	Ok(Entry::new("veil-client", profile)?)
}

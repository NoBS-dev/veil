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
}
impl State {
	pub fn new(ip_and_port: &str, profile: &str) -> Result<Self> {
		Ok(Self {
			account: Account::new(),
			peers: HashMap::new(),
			ip_and_port: ip_and_port.into(),
			profile: normalized_profile(profile).into(),
		})
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

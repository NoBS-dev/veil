use anyhow::Result;
use keyring::Entry;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;
use std::collections::HashMap;
use veil_protocol::identity::{DeviceAddress, DeviceId, DeviceList, UserId, sign_device_binding};
use vodozemac::{
	Ed25519SecretKey,
	olm::{Account, AccountPickle, Session, SessionPickle},
};

/// Bumped whenever `State` changes shape. Profiles from an older version are
/// refused rather than migrated — see `load_from_keyring`.
const STATE_VERSION: u32 = 2;

fn serialize_master_key<S: Serializer>(
	key: &Ed25519SecretKey,
	serializer: S,
) -> Result<S::Ok, S::Error> {
	key.to_base64().serialize(serializer)
}
fn deserialize_master_key<'a, D: Deserializer<'a>>(
	deserializer: D,
) -> Result<Ed25519SecretKey, D::Error> {
	let encoded = String::deserialize(deserializer)?;
	Ed25519SecretKey::from_base64(&encoded).map_err(serde::de::Error::custom)
}

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
	/// The device signing key seen when this session was established.
	///
	/// Pinned on first contact and required to match afterwards. Until
	/// cross-signing (§5.4) nothing proves a claimed `DeviceAddress` belongs to
	/// the key that signed the envelope, so this at least stops a third party
	/// taking over an established session by claiming someone else's address.
	pub ed25519: [u8; 32],
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
	pub version: u32,

	// ---- who the user is (§5.1) ----
	/// Root of identity. Rotating it changes `user_id` and forces every peer to
	/// re-verify, so it is generated once and otherwise left alone (§5.5).
	#[serde(
		serialize_with = "serialize_master_key",
		deserialize_with = "deserialize_master_key"
	)]
	master_key: Ed25519SecretKey,
	/// Derived from `master_key`; stored so callers need not re-derive it.
	pub user_id: UserId,

	// ---- which device this is (§5.2) ----
	pub device_id: DeviceId,
	/// This *device's* Olm account. One per device, not one per user.
	#[serde(
		serialize_with = "serialize_account",
		deserialize_with = "deserialize_account"
	)]
	pub account: Account,

	/// Olm sessions, keyed by the device they talk to rather than by user —
	/// a peer with three devices is three sessions (§5.2).
	#[serde_as(as = "Vec<(_, _)>")]
	pub peers: HashMap<DeviceAddress, PeerSession>,
	/// Device lists we have learned for peers. Routing information only until
	/// cross-signing lands (§5.4).
	#[serde_as(as = "Vec<(_, _)>")]
	#[serde(default)]
	pub peer_devices: HashMap<UserId, DeviceList>,

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

		let master_key = Ed25519SecretKey::new();
		let user_id = UserId::from_master_key(&master_key.public_key());

		Ok(Self {
			version: STATE_VERSION,
			master_key,
			user_id,
			device_id: DeviceId::generate(),
			account: Account::new(),
			peers: HashMap::new(),
			peer_devices: HashMap::new(),
			ip_and_port,
			profile: normalized_profile(profile).into(),
			server_identity: None,
			use_tls,
		})
	}

	/// This device's address — what peers route to (§5.3).
	pub fn address(&self) -> DeviceAddress {
		DeviceAddress::new(self.user_id, self.device_id)
	}

	pub fn master_public_key(&self) -> [u8; 32] {
		*self.master_key.public_key().as_bytes()
	}

	/// Proof that this device belongs to this user, presented at handshake.
	///
	/// Signed by the master key directly for now; §5.4 will move it behind a
	/// self-signing key so the master can stay cold.
	pub fn device_binding(&self) -> [u8; 64] {
		sign_device_binding(
			&self.master_key,
			&self.user_id,
			&self.device_id,
			self.account.ed25519_key().as_bytes(),
		)
	}

	pub fn schemes(&self) -> (&'static str, &'static str) {
		if self.use_tls {
			("wss", "https")
		} else {
			("ws", "http")
		}
	}

	pub fn load_from_keyring(profile: &str) -> Result<Self> {
		let stored = entry_for(profile)?.get_password()?;

		// Profiles written before the identity model are refused rather than
		// migrated. The shape changed at the root — one Olm account was both
		// the user and the device — so there is nothing faithful to migrate to,
		// and inventing a master key for an existing account would produce an
		// identity the user's peers had never verified.
		let state: Self = serde_json::from_str(&stored).map_err(|e| {
			anyhow::anyhow!(
				"profile {profile:?} could not be read ({e}). Profiles created before \
				 the user/device split are not supported; remove it with the `remove` \
				 command, or start a new profile."
			)
		})?;

		if state.version != STATE_VERSION {
			anyhow::bail!(
				"profile {profile:?} is version {} but this build expects {STATE_VERSION}. \
				 Remove it and start again.",
				state.version
			);
		}

		// The stored identity must still hang together — a tampered or corrupt
		// keyring entry should fail here rather than silently give this client a
		// user id its master key does not derive.
		if !state.user_id.matches(&state.master_key.public_key()) {
			anyhow::bail!("profile {profile:?} has a user id its master key does not derive");
		}

		Ok(state)
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

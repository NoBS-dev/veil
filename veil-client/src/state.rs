use anyhow::Result;
use keyring::Entry;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;
use std::collections::HashMap;
use veil_protocol::{
	crosssign::{CrossSigningPublic, CrossSigningSecrets},
	identity::{DeviceAddress, DeviceId, DeviceList, UserId},
	message::{MessageId, SeenWindow},
};
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};

/// Bumped whenever `State` changes shape. Profiles from an older version are
/// refused rather than migrated — see `load_from_keyring`.
const STATE_VERSION: u32 = 5;

fn serialize_session<S: Serializer>(session: &Session, serializer: S) -> Result<S::Ok, S::Error> {
	session.pickle().serialize(serializer)
}
fn deserialize_session<'a, D: Deserializer<'a>>(deserializer: D) -> Result<Session, D::Error> {
	Ok(Session::from_pickle(SessionPickle::deserialize(
		deserializer,
	)?))
}
/// A person we have verified out of band (§5.4, §6.1).
///
/// Holding one of these means every device that user owns — including devices
/// added afterwards — verifies through their cross-signing chain without any
/// further action from us. That is the whole point of verifying a *person*
/// rather than a device.
#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct VerifiedUser {
	pub master_key: [u8; 32],
	/// Our user-signing key's signature over their master key.
	#[serde_as(as = "[_; 64]")]
	pub attestation: [u8; 64],
	pub verified_at: u64,
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
	/// Id of the most recent message received from this device. Sent back as
	/// `seen_head` so the peer knows where we are (§10.1).
	#[serde(default = "MessageId::root")]
	pub seen_head: MessageId,
	/// Ids already processed from this device, newest last. Bounded — a replayed
	/// message only needs catching inside a useful window, and this is a client
	/// cache rather than the authoritative log.
	#[serde(default)]
	pub seen_ids: SeenWindow,
	/// Ids we have sent to this device. Kept so that when the peer tells us
	/// what they last saw, we can tell whether we actually sent it (§10.1).
	#[serde(default)]
	pub sent_ids: SeenWindow,
	#[serde(
		serialize_with = "serialize_session",
		deserialize_with = "deserialize_session"
	)]
	pub session: Session,
}

impl PeerSession {
	/// Records a received message, reporting whether it is new.
	pub fn observe(&mut self, id: MessageId) -> bool {
		if !self.seen_ids.observe(id) {
			return false;
		}
		self.seen_head = id;
		true
	}

	/// Records a message we have sent, so the peer's `seen_head` can be checked
	/// against something.
	pub fn record_sent(&mut self, id: MessageId) {
		self.sent_ids.observe(id);
	}
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

	// ---- who the user is (§5.1, §5.4) ----
	/// Master, self-signing and user-signing keys. The master is the root of
	/// identity — rotating it changes `user_id` and forces every peer to
	/// re-verify, so day-to-day work uses the subkeys instead (§5.5).
	cross_signing: CrossSigningSecrets,
	/// Derived from the master key; stored so callers need not re-derive it.
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
	/// People we have verified. Keyed by user, never by device (§5.4).
	#[serde_as(as = "Vec<(_, _)>")]
	#[serde(default)]
	pub verified_users: HashMap<UserId, VerifiedUser>,

	pub ip_and_port: Box<str>,
	/// Home server to tunnel through, if any (§3.2).
	///
	/// With one set, the destination sees the relay's address rather than ours.
	/// Without one we connect directly, which is faster and exposes our IP to
	/// whoever runs the destination — a fine trade for a host you run yourself,
	/// and a poor one for a stranger's.
	#[serde(default)]
	pub relay: Option<Box<str>>,
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

		let cross_signing = CrossSigningSecrets::new();
		let user_id = cross_signing.user_id();

		Ok(Self {
			version: STATE_VERSION,
			cross_signing,
			user_id,
			device_id: DeviceId::generate(),
			account: Account::new(),
			peers: HashMap::new(),
			peer_devices: HashMap::new(),
			verified_users: HashMap::new(),
			ip_and_port,
			relay: None,
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
		self.cross_signing.master_public()
	}

	/// The publishable cross-signing keys, presented at handshake so peers can
	/// walk the chain down to a device.
	pub fn cross_signing_public(&self) -> CrossSigningPublic {
		self.cross_signing.public()
	}

	/// Proof that this device belongs to this user (§5.4).
	///
	/// Made with the **self-signing** key, so enrolling a device never touches
	/// the master key.
	pub fn device_binding(&self) -> [u8; 64] {
		self.cross_signing
			.sign_device(&self.device_id, self.account.ed25519_key().as_bytes())
	}

	/// Records that we have verified another person, after comparing safety
	/// numbers out of band. Every device they own — now and later — follows
	/// from this one signature (§5.4).
	pub fn verify_user(&mut self, subject_master: &[u8; 32]) -> Result<UserId> {
		let key = vodozemac::Ed25519PublicKey::from_slice(subject_master)?;
		let subject = UserId::from_master_key(&key);

		let attestation = self.cross_signing.attest_user(&subject, subject_master);
		self.verified_users.insert(
			subject,
			VerifiedUser {
				master_key: *subject_master,
				attestation,
				verified_at: veil_protocol::now_ms()?,
			},
		);

		Ok(subject)
	}

	pub fn is_verified(&self, user: &UserId) -> bool {
		self.verified_users.contains_key(user)
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
		state
			.cross_signing
			.public()
			.verify(&state.user_id)
			.map_err(|e| {
				anyhow::anyhow!("profile {profile:?} has an inconsistent identity: {e}")
			})?;

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

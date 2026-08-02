use anyhow::Result;
use keyring::Entry;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;
use std::collections::HashMap;
use veil_protocol::{
	community::{CommunityId, CommunityRoot, CommunityState, Mode, SignedPolicy},
	crosssign::{CrossSigningPublic, CrossSigningSecrets},
	groupkeys::{MegolmProvider, ProviderState},
	identity::{DeviceAddress, DeviceId, DeviceList, UserId},
	message::{MessageId, SeenWindow},
};
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};

/// An empty provider's state, for profiles written before Megolm was stored.
fn empty_provider() -> ProviderState {
	// The address is irrelevant for an empty provider — nothing is keyed by it
	// until a session exists, and `State::megolm` supplies the real one on every
	// restore.
	MegolmProvider::new(DeviceAddress::new(
		UserId::from_bytes([0; 16]),
		DeviceId::from_bytes([0; 16]),
	))
	.save()
	.expect("an empty provider always saves")
}

/// Bumped whenever `State` changes shape. Profiles from an older version are
/// refused rather than migrated — see `load_from_keyring`.
const STATE_VERSION: u32 = 6;

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
	/// Communities this device knows the mode of (§7).
	///
	/// Kept because the mode cannot be recovered from an id — the id is a hash
	/// of the root, which is what makes it unforgeable (invariant 13) and also
	/// what makes it opaque. A client that has verified a root records what it
	/// found, so it can refuse to send plaintext into a Sealed community later.
	#[serde_as(as = "Vec<(_, _)>")]
	#[serde(default)]
	pub known_communities: HashMap<CommunityId, Mode>,
	/// Roots and policy chains, as JSON, for communities this device has
	/// verified.
	///
	/// Kept raw rather than as a parsed `CommunityState` so it can be replayed
	/// and re-checked on use. Readership decides who receives Megolm keys, so a
	/// value cached in a form that no longer carries its own proof is a value a
	/// future bug can quietly widen (§8.5).
	#[serde_as(as = "Vec<(_, _)>")]
	#[serde(default)]
	pub community_roots: HashMap<CommunityId, String>,
	#[serde_as(as = "Vec<(_, _)>")]
	#[serde(default)]
	pub community_chains: HashMap<CommunityId, Vec<String>>,
	/// Megolm sessions (§8.4). Persisted because a session is the only thing
	/// that can read what was sent under it.
	#[serde(default = "empty_provider")]
	pub megolm: ProviderState,
	/// How many community states have been verified and applied this run.
	///
	/// Not persisted: it exists so startup can tell whether the chain it is
	/// about to encrypt against has caught up, and that question is only
	/// meaningful within one connection.
	#[serde(skip)]
	pub applied_states: u64,
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
	/// Check for mail on an interval instead of staying connected (§12.2).
	///
	/// Costs latency and battery; buys resistance to timing correlation, since
	/// nobody learns when each message arrived — only that the device checked in
	/// on a schedule. It is also the escape hatch that keeps push from being a
	/// §1.3 dependency: a user who will not route through a push gateway can
	/// poll instead and lose nothing but immediacy.
	#[serde(default)]
	pub poll_interval_secs: Option<u64>,
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
			known_communities: HashMap::new(),
			community_roots: HashMap::new(),
			community_chains: HashMap::new(),
			megolm: empty_provider(),
			applied_states: 0,
			verified_users: HashMap::new(),
			ip_and_port,
			relay: None,
			poll_interval_secs: None,
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

	/// This user's cross-signing secrets.
	///
	/// Exposed rather than public so the one caller that needs the master key —
	/// founding a community, which the founder signs with it (§7.1) — has to ask
	/// for it explicitly.
	pub fn cross_signing(&self) -> &CrossSigningSecrets {
		&self.cross_signing
	}

	/// What mode a community was founded in, if this device has verified its
	/// root.
	///
	/// `None` means "not known", not "Open". A caller deciding whether it is
	/// safe to send plaintext must treat the two differently.
	pub fn community_mode(&self, id: &CommunityId) -> Option<Mode> {
		self.known_communities.get(id).copied()
	}

	/// Records a community whose root has been checked against its id.
	pub fn remember_community(&mut self, root: &CommunityRoot) {
		self.known_communities.insert(root.id(), root.mode);
		if let Ok(json) = serde_json::to_string(root) {
			self.community_roots.insert(root.id(), json);
		}
	}

	/// Accepts a root and policy chain a host served, having checked them.
	///
	/// **The id is recomputed from the root.** That is the check that matters:
	/// the id is a hash of the root with the mode inside it (invariant 13), so a
	/// host cannot serve a different community — or the same one in a different
	/// mode — under an id somebody was given in an invite.
	///
	/// The chain is then replayed, which is what enforces k distinct
	/// controllers and advancing sequences (invariant 16). A record that does
	/// not apply causes the whole chain to be refused rather than the bad record
	/// skipped: policy is cumulative, so a chain with a hole in it is not a
	/// smaller truth, it is a different one.
	pub fn accept_community(
		&mut self,
		id: CommunityId,
		root_json: &str,
		chain: &[String],
	) -> Result<()> {
		let root: CommunityRoot = serde_json::from_str(root_json)?;

		if root.id() != id {
			anyhow::bail!(
				"the host served a root that hashes to {} under the id {id}",
				root.id()
			);
		}

		let mut community = CommunityState::without_founder_check(root.clone())?;
		for entry in chain {
			let policy: SignedPolicy = serde_json::from_str(entry)?;
			community.apply(&policy)?;
		}

		self.known_communities.insert(id, root.mode);
		self.community_roots.insert(id, root_json.to_owned());
		self.community_chains.insert(id, chain.to_vec());
		self.applied_states += 1;
		Ok(())
	}

	/// The verified policy for a community, replayed from what we stored.
	pub fn community_state(&self, id: &CommunityId) -> Result<CommunityState> {
		let root_json = self
			.community_roots
			.get(id)
			.ok_or_else(|| anyhow::anyhow!("no verified root for {id}; join it first"))?;

		let root: CommunityRoot = serde_json::from_str(root_json)?;
		let mut community = CommunityState::without_founder_check(root)?;

		for entry in self.community_chains.get(id).into_iter().flatten() {
			community.apply(&serde_json::from_str::<SignedPolicy>(entry)?)?;
		}

		Ok(community)
	}

	/// The Megolm provider, restored from stored state.
	pub fn megolm(&self) -> Result<MegolmProvider> {
		MegolmProvider::restore(self.megolm.clone(), self.address())
	}

	/// Writes the provider back. Callers must do this after anything that
	/// establishes, rotates or accepts a session, or the work is lost on exit.
	pub fn store_megolm(&mut self, provider: &MegolmProvider) -> Result<()> {
		self.megolm = provider.save()?;
		Ok(())
	}

	pub fn schemes(&self) -> (&'static str, &'static str) {
		if self.use_tls {
			("wss", "https")
		} else {
			("ws", "http")
		}
	}

	pub fn load_from_keyring(profile: &str) -> Result<Self> {
		let stored = store().load(profile)?;

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
		store().save(&self.profile, &serde_json::to_string(&self)?)
	}

	pub fn delete_from_keyring(&self) -> Result<()> {
		store().delete(&self.profile)
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

/// Where a profile's secrets live.
///
/// An indirection rather than calling the keyring directly, for two reasons
/// that turned out to be the same reason: the client could not be tested
/// without a Secret Service running, and it could not be *run* without one
/// either — which rules out containers, CI, and anything headless.
pub trait SecretStore: Send + Sync {
	fn load(&self, profile: &str) -> Result<String>;
	fn save(&self, profile: &str, data: &str) -> Result<()>;
	fn delete(&self, profile: &str) -> Result<()>;
}

/// The OS keyring, via Secret Service. The default.
pub struct Keyring;

impl SecretStore for Keyring {
	fn load(&self, profile: &str) -> Result<String> {
		Ok(Entry::new("veil-client", profile)?.get_password()?)
	}
	fn save(&self, profile: &str, data: &str) -> Result<()> {
		Entry::new("veil-client", profile)?.set_password(data)?;
		Ok(())
	}
	fn delete(&self, profile: &str) -> Result<()> {
		Entry::new("veil-client", profile)?.delete_password()?;
		Ok(())
	}
}

/// Profiles as files in a directory.
///
/// **Secrets sit on disk unencrypted**, protected only by file permissions, so
/// this is for tests and headless use rather than a desktop where the keyring
/// is available. Selected by setting `VEIL_STATE_DIR`, and the client says so
/// out loud when it is in use.
pub struct FileStore {
	dir: std::path::PathBuf,
}

impl FileStore {
	pub fn new(dir: impl Into<std::path::PathBuf>) -> Result<Self> {
		let dir = dir.into();
		std::fs::create_dir_all(&dir)?;
		Ok(Self { dir })
	}

	fn path(&self, profile: &str) -> std::path::PathBuf {
		// Profile names reach the filesystem here, so anything that could climb
		// out of the directory is replaced rather than trusted.
		let safe: String = profile
			.chars()
			.map(|c| {
				if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
					c
				} else {
					'_'
				}
			})
			.collect();
		self.dir.join(format!("{safe}.json"))
	}
}

impl SecretStore for FileStore {
	fn load(&self, profile: &str) -> Result<String> {
		Ok(std::fs::read_to_string(self.path(profile))?)
	}

	fn save(&self, profile: &str, data: &str) -> Result<()> {
		let path = self.path(profile);
		// Written beside and renamed, so an interrupted save cannot leave a
		// half-written profile where a whole one used to be.
		let temporary = path.with_extension("tmp");
		std::fs::write(&temporary, data)?;

		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
		}

		std::fs::rename(&temporary, &path)?;
		Ok(())
	}

	fn delete(&self, profile: &str) -> Result<()> {
		std::fs::remove_file(self.path(profile))?;
		Ok(())
	}
}

/// The process-wide store.
///
/// A global because `State` is serialised and cannot carry a handle. When the
/// UI-agnostic core is extracted (§17.1) this becomes something the core owns,
/// and the global goes away.
static STORE: std::sync::OnceLock<Box<dyn SecretStore>> = std::sync::OnceLock::new();

/// Initialises from the environment if nothing has been chosen yet.
pub fn store() -> &'static dyn SecretStore {
	STORE
		.get_or_init(|| default_store().expect("a usable secret store"))
		.as_ref()
}

/// `VEIL_STATE_DIR` selects files; otherwise the keyring.
pub fn default_store() -> Result<Box<dyn SecretStore>> {
	match std::env::var("VEIL_STATE_DIR") {
		Ok(dir) if !dir.trim().is_empty() => {
			eprintln!(
				"Using file-backed profiles in {dir} — secrets are stored unencrypted, \
				 protected only by file permissions."
			);
			Ok(Box::new(FileStore::new(dir)?))
		}
		_ => Ok(Box::new(Keyring)),
	}
}

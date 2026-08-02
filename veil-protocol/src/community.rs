//! Community identity and policy — `DESIGN.md` §7.4, §8.5, §12.4.
//!
//! The property everything here exists to provide: **a host cannot lie about a
//! community's encryption mode.** If the host declared the mode, a malicious one
//! would declare a Sealed community Open and read everything. So the mode lives
//! inside the community's *identity* — `CommunityId` is a hash of the root
//! record, mode included — and every later change is a signed record extending a
//! chain the host serves but does not author.
//!
//! §7.4 calls this the easiest thing in the design to get wrong, because getting
//! it wrong ships a protocol where the operator can switch encryption off.

use crate::identity::UserId;
use data_encoding::BASE32_NOPAD;
use rkyv::{Archive, Deserialize, Serialize};
use serde::{Deserialize as De, Serialize as Ser};
use serde_with::serde_as;
use sha2::{Digest, Sha256};
use vodozemac::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

const COMMUNITY_ID_DOMAIN: &[u8] = b"veil-community-v1";
const FOUNDER_DOMAIN: &[u8] = b"veil-community-founder-v1";
const POLICY_DOMAIN: &[u8] = b"veil-community-policy-v1";
const COMMUNITY_ID_LEN: usize = 16;

/// Encryption tier. Fixed at creation and only ever relaxed, never tightened
/// (§7.3) — a community cannot promise protection for history already readable.
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub enum Mode {
	/// End-to-end encrypted; the host stores ciphertext it cannot read.
	Sealed,
	/// Host-readable, which is what buys search, moderation and bots (§7.1).
	Open,
}

impl Mode {
	/// Sealed may become Open; the reverse cannot happen, because history that
	/// is already readable cannot retroactively be made private (§7.3).
	fn may_transition_to(self, next: Mode) -> bool {
		matches!((self, next), (Mode::Sealed, Mode::Open))
	}
}

impl std::fmt::Display for Mode {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Mode::Sealed => "sealed",
			Mode::Open => "open",
		})
	}
}

#[derive(
	Archive,
	Deserialize,
	Serialize,
	Debug,
	Clone,
	Copy,
	PartialEq,
	Eq,
	Hash,
	PartialOrd,
	Ord,
	Ser,
	De,
)]
#[rkyv(attr(derive(Debug)))]
pub struct CommunityId([u8; COMMUNITY_ID_LEN]);

impl CommunityId {
	pub fn parse(text: &str) -> anyhow::Result<Self> {
		let bytes = BASE32_NOPAD.decode(text.trim().to_ascii_uppercase().as_bytes())?;
		Ok(Self(bytes.as_slice().try_into().map_err(|_| {
			anyhow::anyhow!("expected a {COMMUNITY_ID_LEN}-byte community id")
		})?))
	}

	pub fn as_bytes(&self) -> &[u8; COMMUNITY_ID_LEN] {
		&self.0
	}
}

impl std::fmt::Display for CommunityId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&BASE32_NOPAD.encode(&self.0))
	}
}

/// The immutable founding record.
///
/// **Nothing that might ever change belongs here.** Every field is frozen for
/// the community's life, because the record is hashed to produce the
/// `CommunityId`. A minimum protocol version placed here could never be raised;
/// a community founded on v1 could never adopt a v5 feature. Mutable policy goes
/// in the chain (§7.4).
#[serde_as]
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub struct CommunityRoot {
	pub mode: Mode,
	/// Public keys authorised to sign policy records. k-of-n rather than one,
	/// because a lone key is held by exactly the person most likely to
	/// disappear, and the community's governance would die with them (§12.4).
	pub controllers: Vec<[u8; 32]>,
	/// How many distinct controllers must sign.
	pub threshold: u8,
	pub founder: UserId,
	pub created_at: u64,
	#[serde_as(as = "[_; 64]")]
	pub founder_signature: [u8; 64],
}

/// Deterministic bytes for hashing and signing.
///
/// Written out field by field with explicit lengths rather than leaning on a
/// serialiser's output, for the same reason `Envelope` keeps its payload
/// opaque: a hash or signature must cover bytes whose layout cannot drift with
/// a library version.
fn canonical(
	mode: Mode,
	controllers: &[[u8; 32]],
	threshold: u8,
	founder: &UserId,
	created_at: u64,
) -> Vec<u8> {
	let mut buffer = Vec::with_capacity(64 + controllers.len() * 32);
	buffer.push(match mode {
		Mode::Sealed => 0,
		Mode::Open => 1,
	});
	buffer.extend_from_slice(&(controllers.len() as u32).to_le_bytes());
	for controller in controllers {
		buffer.extend_from_slice(controller);
	}
	buffer.push(threshold);
	buffer.extend_from_slice(founder.as_bytes());
	buffer.extend_from_slice(&created_at.to_le_bytes());
	buffer
}

impl CommunityRoot {
	/// Founds a community. The founder signs the contents; the id is the hash of
	/// those same contents, so the two cannot disagree.
	pub fn found(
		mode: Mode,
		controllers: Vec<[u8; 32]>,
		threshold: u8,
		founder_key: &Ed25519SecretKey,
		created_at: u64,
	) -> anyhow::Result<Self> {
		if controllers.is_empty() {
			anyhow::bail!("a community needs at least one controller");
		}
		if threshold == 0 || usize::from(threshold) > controllers.len() {
			anyhow::bail!(
				"threshold {threshold} is not satisfiable by {} controller(s)",
				controllers.len()
			);
		}

		let founder = UserId::from_master_key(&founder_key.public_key());
		let body = canonical(mode, &controllers, threshold, &founder, created_at);

		let mut signed = Vec::with_capacity(FOUNDER_DOMAIN.len() + body.len());
		signed.extend_from_slice(FOUNDER_DOMAIN);
		signed.extend_from_slice(&body);

		Ok(Self {
			mode,
			controllers,
			threshold,
			founder,
			created_at,
			founder_signature: founder_key.sign(&signed).to_bytes(),
		})
	}

	/// `base32( SHA-256( domain || canonical(root) ) )`
	///
	/// The mode is inside this hash. That is the whole mechanism: a host cannot
	/// present a different mode for a given id without producing a different id.
	pub fn id(&self) -> CommunityId {
		let mut hasher = Sha256::new();
		hasher.update(COMMUNITY_ID_DOMAIN);
		hasher.update(canonical(
			self.mode,
			&self.controllers,
			self.threshold,
			&self.founder,
			self.created_at,
		));

		let mut id = [0u8; COMMUNITY_ID_LEN];
		id.copy_from_slice(&hasher.finalize()[..COMMUNITY_ID_LEN]);
		CommunityId(id)
	}

	/// Checks the root is well formed and really was founded by whom it claims.
	///
	/// `founder_master_key` comes from the founder's published identity; it is
	/// checked against `self.founder`, which is derived from it.
	pub fn verify(&self, founder_master_key: &[u8; 32]) -> anyhow::Result<()> {
		if self.controllers.is_empty() {
			anyhow::bail!("root lists no controllers");
		}
		if self.threshold == 0 || usize::from(self.threshold) > self.controllers.len() {
			anyhow::bail!(
				"threshold {} is not satisfiable by {} controller(s)",
				self.threshold,
				self.controllers.len()
			);
		}

		let key = Ed25519PublicKey::from_slice(founder_master_key)?;
		if !self.founder.matches(&key) {
			anyhow::bail!("founder key does not derive the claimed founder id");
		}

		let body = canonical(
			self.mode,
			&self.controllers,
			self.threshold,
			&self.founder,
			self.created_at,
		);
		let mut signed = Vec::with_capacity(FOUNDER_DOMAIN.len() + body.len());
		signed.extend_from_slice(FOUNDER_DOMAIN);
		signed.extend_from_slice(&body);

		key.verify(
			&signed,
			&Ed25519Signature::from_slice(&self.founder_signature)?,
		)
		.map_err(|e| anyhow::anyhow!("founder signature is invalid: {e}"))?;

		Ok(())
	}
}

/// A change to community policy. Everything mutable is one of these.
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub enum PolicyRecord {
	/// Sealed -> Open only, one way, non-retroactive (§7.3).
	ModeTransition { new_mode: Mode },
	/// Hosts below this refuse to serve the community (§3.6).
	VersionRequirement { min_version: u16 },
	/// The community has moved (§12.4).
	Migration { new_host: String },
	/// Who may read a channel.
	///
	/// In Sealed this is *not* an ACL the host enforces — read access is key
	/// possession, and senders consult this to decide who receives Megolm keys.
	/// A host able to edit it could add a reader and have every sender
	/// dutifully encrypt to them, so it has to be signed like anything else
	/// (§8.5).
	ChannelReaders {
		channel: String,
		readers: Vec<UserId>,
	},
	/// What a member may do (§8.5).
	///
	/// In the signed chain rather than a host-side table, so there is one source
	/// of truth for both halves of the split: the host enforces the permissions
	/// it can enforce, and clients read the same record when deciding who
	/// receives keys. A host with its own role table could grant itself
	/// moderation, and — worse — a role that carried read access would let it
	/// add itself to a reader set every sender then encrypts to.
	MemberRole { user: UserId, role: Role },
}

/// What a member may do, in increasing order of authority.
///
/// **Only reading is enforced cryptographically** (§8.5). Everything else —
/// posting, kicking, banning, renaming — is an action the host can simply
/// refuse, and a host that ignores its own ACL is misbehaving in a way members
/// can observe. Reading is the one permission that cannot be clawed back after
/// the fact, so it is the only one that has to be key possession.
///
/// That collapses a Discord-sized permission matrix into one cryptographic
/// question — who holds the key for this channel — and leaves the rest as
/// ordinary bookkeeping.
#[derive(
	Archive,
	Deserialize,
	Serialize,
	Debug,
	Clone,
	Copy,
	PartialEq,
	Eq,
	PartialOrd,
	Ord,
	Ser,
	De,
	Default,
)]
#[rkyv(attr(derive(Debug)))]
pub enum Role {
	/// Cannot post or read. Kept as a role rather than removed from the member
	/// list so the ban survives them being re-added by someone who did not know.
	Banned,
	#[default]
	Member,
	/// May ban and unban.
	Moderator,
}

impl std::fmt::Display for Role {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Role::Banned => "banned",
			Role::Member => "member",
			Role::Moderator => "moderator",
		})
	}
}

/// One controller's signature, tagged with which controller made it.
#[serde_as]
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub struct ControllerSignature {
	/// Index into `CommunityRoot::controllers`.
	pub controller: u16,
	#[serde_as(as = "[_; 64]")]
	pub signature: [u8; 64],
}

/// A policy record with the signatures authorising it.
#[derive(Archive, Deserialize, Serialize, Debug, Clone, Ser, De)]
#[rkyv(attr(derive(Debug)))]
pub struct SignedPolicy {
	pub community: CommunityId,
	/// Monotonic. Blocks replay of a stale record — without it an old
	/// migration could redirect a community to a host it has left (§12.4).
	pub sequence: u64,
	pub record: PolicyRecord,
	pub signatures: Vec<ControllerSignature>,
}

fn policy_input(community: &CommunityId, sequence: u64, record: &PolicyRecord) -> Vec<u8> {
	let mut buffer = Vec::with_capacity(64);
	buffer.extend_from_slice(POLICY_DOMAIN);
	buffer.extend_from_slice(community.as_bytes());
	buffer.extend_from_slice(&sequence.to_le_bytes());

	match record {
		PolicyRecord::ModeTransition { new_mode } => {
			buffer.push(0);
			buffer.push(match new_mode {
				Mode::Sealed => 0,
				Mode::Open => 1,
			});
		}
		PolicyRecord::VersionRequirement { min_version } => {
			buffer.push(1);
			buffer.extend_from_slice(&min_version.to_le_bytes());
		}
		PolicyRecord::Migration { new_host } => {
			buffer.push(2);
			buffer.extend_from_slice(&(new_host.len() as u32).to_le_bytes());
			buffer.extend_from_slice(new_host.as_bytes());
		}
		PolicyRecord::MemberRole { user, role } => {
			buffer.push(4);
			buffer.extend_from_slice(user.as_bytes());
			buffer.push(match role {
				Role::Banned => 0,
				Role::Member => 1,
				Role::Moderator => 2,
			});
		}
		PolicyRecord::ChannelReaders { channel, readers } => {
			buffer.push(3);
			buffer.extend_from_slice(&(channel.len() as u32).to_le_bytes());
			buffer.extend_from_slice(channel.as_bytes());
			buffer.extend_from_slice(&(readers.len() as u32).to_le_bytes());
			for reader in readers {
				buffer.extend_from_slice(reader.as_bytes());
			}
		}
	}

	buffer
}

impl SignedPolicy {
	pub fn sign(
		community: CommunityId,
		sequence: u64,
		record: PolicyRecord,
		signers: &[(u16, &Ed25519SecretKey)],
	) -> Self {
		let input = policy_input(&community, sequence, &record);

		Self {
			community,
			sequence,
			signatures: signers
				.iter()
				.map(|(index, key)| ControllerSignature {
					controller: *index,
					signature: key.sign(&input).to_bytes(),
				})
				.collect(),
			record,
		}
	}
}

/// A community's current policy, produced by replaying its chain.
#[derive(Debug, Clone)]
pub struct CommunityState {
	pub id: CommunityId,
	pub mode: Mode,
	pub min_version: u16,
	pub host: Option<String>,
	pub channel_readers: std::collections::HashMap<String, Vec<UserId>>,
	/// Roles, as the chain has assigned them. Absent means [`Role::Member`].
	pub roles: std::collections::HashMap<UserId, Role>,
	/// Highest sequence applied. Records at or below this are refused.
	pub sequence: u64,
	root: CommunityRoot,
}

impl CommunityState {
	/// Starts from a verified root.
	pub fn from_root(root: CommunityRoot, founder_master_key: &[u8; 32]) -> anyhow::Result<Self> {
		root.verify(founder_master_key)?;

		Ok(Self {
			id: root.id(),
			mode: root.mode,
			min_version: 1,
			host: None,
			channel_readers: std::collections::HashMap::new(),
			roles: std::collections::HashMap::new(),
			sequence: 0,
			root,
		})
	}

	/// Starts from a root whose founder signature has already been checked.
	///
	/// For a host replaying its own stored chain. The root is immutable — its
	/// hash *is* the id — and it was verified when the community was
	/// registered, so re-checking it here would only require keeping the
	/// founder's master key on hand forever to learn nothing new.
	///
	/// Not for anything that received a root from elsewhere: there,
	/// [`Self::from_root`] is the one that makes the founder prove it.
	pub fn without_founder_check(root: CommunityRoot) -> anyhow::Result<Self> {
		Ok(Self {
			id: root.id(),
			mode: root.mode,
			min_version: 1,
			host: None,
			channel_readers: std::collections::HashMap::new(),
			roles: std::collections::HashMap::new(),
			sequence: 0,
			root,
		})
	}

	/// Applies one policy record, or explains why it was refused.
	///
	/// Four independent checks, and every one is load-bearing:
	///
	/// 1. the record names this community — signatures are bound to the id;
	/// 2. its sequence advances — otherwise a stale record could be replayed;
	/// 3. enough *distinct* controllers signed — a single controller repeating
	///    itself must not reach the threshold;
	/// 4. the change itself is legal, e.g. Open never becomes Sealed.
	pub fn apply(&mut self, policy: &SignedPolicy) -> anyhow::Result<()> {
		if policy.community != self.id {
			anyhow::bail!(
				"policy names community {} but this is {}",
				policy.community,
				self.id
			);
		}

		if policy.sequence <= self.sequence {
			anyhow::bail!(
				"policy sequence {} does not advance past {}",
				policy.sequence,
				self.sequence
			);
		}

		self.verify_signatures(policy)?;

		match &policy.record {
			PolicyRecord::ModeTransition { new_mode } => {
				if !self.mode.may_transition_to(*new_mode) {
					anyhow::bail!("{} may not transition to {new_mode}", self.mode);
				}
				self.mode = *new_mode;
			}
			PolicyRecord::VersionRequirement { min_version } => {
				self.min_version = *min_version;
			}
			PolicyRecord::Migration { new_host } => {
				self.host = Some(new_host.clone());
			}
			PolicyRecord::MemberRole { user, role } => {
				self.roles.insert(*user, *role);
			}
			PolicyRecord::ChannelReaders { channel, readers } => {
				self.channel_readers
					.insert(channel.clone(), readers.clone());
			}
		}

		self.sequence = policy.sequence;
		Ok(())
	}

	fn verify_signatures(&self, policy: &SignedPolicy) -> anyhow::Result<()> {
		let input = policy_input(&policy.community, policy.sequence, &policy.record);
		let mut counted = std::collections::HashSet::new();

		for signature in &policy.signatures {
			let Some(controller) = self.root.controllers.get(usize::from(signature.controller))
			else {
				anyhow::bail!(
					"signature names controller {} which does not exist",
					signature.controller
				);
			};

			// A controller signing twice must not count twice, or one key could
			// reach any threshold on its own.
			if !counted.insert(signature.controller) {
				continue;
			}

			let key = Ed25519PublicKey::from_slice(controller)?;
			if key
				.verify(&input, &Ed25519Signature::from_slice(&signature.signature)?)
				.is_err()
			{
				anyhow::bail!(
					"controller {} produced an invalid signature",
					signature.controller
				);
			}
		}

		if counted.len() < usize::from(self.root.threshold) {
			anyhow::bail!(
				"policy has {} valid controller signature(s) but {} are required",
				counted.len(),
				self.root.threshold
			);
		}

		Ok(())
	}

	/// Replays a whole chain in order, as a client does on join and reconnect.
	pub fn replay(&mut self, chain: &[SignedPolicy]) -> anyhow::Result<()> {
		for policy in chain {
			self.apply(policy)?;
		}
		Ok(())
	}

	/// A member's role. Anyone unmentioned is an ordinary member.
	pub fn role(&self, user: &UserId) -> Role {
		// The founder is a moderator by construction. A community whose founder
		// could be banned out of their own community by a moderator they
		// appointed would have no recoverable state.
		if *user == self.root.founder {
			return Role::Moderator;
		}
		self.roles.get(user).copied().unwrap_or_default()
	}

	/// Whether a member may post. Banned is the only role that cannot.
	pub fn may_post(&self, user: &UserId) -> bool {
		self.role(user) > Role::Banned
	}

	/// Whether a member may change other members' roles.
	pub fn may_moderate(&self, user: &UserId) -> bool {
		self.role(user) >= Role::Moderator
	}

	pub fn root(&self) -> &CommunityRoot {
		&self.root
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	struct Fixture {
		founder: Ed25519SecretKey,
		controllers: Vec<Ed25519SecretKey>,
		root: CommunityRoot,
	}

	fn found(mode: Mode, n: usize, threshold: u8) -> Fixture {
		let founder = Ed25519SecretKey::new();
		let controllers: Vec<_> = (0..n).map(|_| Ed25519SecretKey::new()).collect();
		let root = CommunityRoot::found(
			mode,
			controllers
				.iter()
				.map(|k| *k.public_key().as_bytes())
				.collect(),
			threshold,
			&founder,
			1_000,
		)
		.unwrap();

		Fixture {
			founder,
			controllers,
			root,
		}
	}

	impl Fixture {
		fn state(&self) -> CommunityState {
			CommunityState::from_root(self.root.clone(), self.founder.public_key().as_bytes())
				.unwrap()
		}

		fn signers(&self, indices: &[u16]) -> Vec<(u16, &Ed25519SecretKey)> {
			indices
				.iter()
				.map(|i| (*i, &self.controllers[usize::from(*i)]))
				.collect()
		}
	}

	/// The property the whole mechanism exists for: the mode is inside the id,
	/// so a host cannot serve a different mode under the same id.
	#[test]
	fn the_mode_is_bound_into_the_community_id() {
		let sealed = found(Mode::Sealed, 3, 2);

		// Same everything, mode flipped — a different community entirely.
		let mut forged = sealed.root.clone();
		forged.mode = Mode::Open;

		assert_ne!(
			sealed.root.id(),
			forged.id(),
			"flipping the mode must change the id, or a host could lie about it"
		);
	}

	#[test]
	fn a_root_verifies_against_its_founder() {
		let f = found(Mode::Sealed, 3, 2);
		assert!(f.root.verify(f.founder.public_key().as_bytes()).is_ok());

		// Someone else's key does not vouch for it.
		let stranger = Ed25519SecretKey::new();
		assert!(f.root.verify(stranger.public_key().as_bytes()).is_err());
	}

	#[test]
	fn a_tampered_root_fails_verification() {
		let f = found(Mode::Sealed, 3, 2);

		let mut tampered = f.root.clone();
		tampered.threshold = 1; // an attacker lowering the bar
		assert!(
			tampered.verify(f.founder.public_key().as_bytes()).is_err(),
			"the founder signature must cover the threshold"
		);

		let mut swapped = f.root.clone();
		swapped.controllers[0] = *Ed25519SecretKey::new().public_key().as_bytes();
		assert!(
			swapped.verify(f.founder.public_key().as_bytes()).is_err(),
			"the founder signature must cover the controller set"
		);
	}

	#[test]
	fn unsatisfiable_thresholds_are_refused_at_founding() {
		let founder = Ed25519SecretKey::new();
		let one = vec![*Ed25519SecretKey::new().public_key().as_bytes()];

		assert!(CommunityRoot::found(Mode::Sealed, vec![], 1, &founder, 0).is_err());
		assert!(CommunityRoot::found(Mode::Sealed, one.clone(), 0, &founder, 0).is_err());
		assert!(CommunityRoot::found(Mode::Sealed, one, 2, &founder, 0).is_err());
	}

	#[test]
	fn k_of_n_is_enforced() {
		let f = found(Mode::Sealed, 3, 2);
		let mut state = f.state();

		let record = PolicyRecord::VersionRequirement { min_version: 4 };

		// One signature is not enough.
		let under = SignedPolicy::sign(state.id, 1, record.clone(), &f.signers(&[0]));
		assert!(state.apply(&under).is_err());

		// Two is.
		let ok = SignedPolicy::sign(state.id, 1, record, &f.signers(&[0, 1]));
		assert!(state.apply(&ok).is_ok());
		assert_eq!(state.min_version, 4);
	}

	/// One controller signing twice must not reach a threshold of two, or k-of-n
	/// collapses to 1-of-n.
	#[test]
	fn a_controller_cannot_reach_the_threshold_alone() {
		let f = found(Mode::Sealed, 3, 2);
		let mut state = f.state();

		let doubled = SignedPolicy::sign(
			state.id,
			1,
			PolicyRecord::VersionRequirement { min_version: 2 },
			&f.signers(&[0, 0]),
		);

		assert!(state.apply(&doubled).is_err());
	}

	#[test]
	fn a_non_controller_signature_is_refused() {
		let f = found(Mode::Sealed, 3, 2);
		let mut state = f.state();
		let outsider = Ed25519SecretKey::new();

		// Valid signature, but from a key the root does not list. Claiming an
		// existing controller's index makes it verifiably wrong.
		let mut forged = SignedPolicy::sign(
			state.id,
			1,
			PolicyRecord::VersionRequirement { min_version: 2 },
			&f.signers(&[0, 1]),
		);
		forged.signatures[1] = ControllerSignature {
			controller: 1,
			signature: outsider.sign(b"whatever").to_bytes(),
		};

		assert!(state.apply(&forged).is_err());
	}

	/// Sealed may become Open. Open must never become Sealed — history already
	/// readable cannot be made private after the fact (§7.3).
	#[test]
	fn mode_transitions_are_one_way() {
		let f = found(Mode::Sealed, 3, 2);
		let mut state = f.state();
		assert_eq!(state.mode, Mode::Sealed);

		let open = SignedPolicy::sign(
			state.id,
			1,
			PolicyRecord::ModeTransition {
				new_mode: Mode::Open,
			},
			&f.signers(&[0, 1]),
		);
		assert!(state.apply(&open).is_ok());
		assert_eq!(state.mode, Mode::Open);

		// ...and back is refused, even with valid signatures.
		let back = SignedPolicy::sign(
			state.id,
			2,
			PolicyRecord::ModeTransition {
				new_mode: Mode::Sealed,
			},
			&f.signers(&[0, 1]),
		);
		assert!(state.apply(&back).is_err());
		assert_eq!(state.mode, Mode::Open);
	}

	/// A stale record must not be replayable — otherwise an old migration could
	/// redirect a community back to a host it has left (§12.4).
	#[test]
	fn a_stale_record_cannot_be_replayed() {
		let f = found(Mode::Sealed, 3, 2);
		let mut state = f.state();

		let first = SignedPolicy::sign(
			state.id,
			1,
			PolicyRecord::Migration {
				new_host: "old.example".into(),
			},
			&f.signers(&[0, 1]),
		);
		let second = SignedPolicy::sign(
			state.id,
			2,
			PolicyRecord::Migration {
				new_host: "new.example".into(),
			},
			&f.signers(&[0, 1]),
		);

		state.replay(&[first.clone(), second]).unwrap();
		assert_eq!(state.host.as_deref(), Some("new.example"));

		// Replaying the older record does not move it back.
		assert!(state.apply(&first).is_err());
		assert_eq!(state.host.as_deref(), Some("new.example"));
	}

	#[test]
	fn a_record_for_another_community_is_refused() {
		let mine = found(Mode::Sealed, 3, 2);
		let theirs = found(Mode::Sealed, 3, 2);
		let mut state = mine.state();

		let elsewhere = SignedPolicy::sign(
			theirs.root.id(),
			1,
			PolicyRecord::VersionRequirement { min_version: 9 },
			&theirs.signers(&[0, 1]),
		);

		assert!(state.apply(&elsewhere).is_err());
	}

	/// §8.5: senders consult channel readership to decide who receives Megolm
	/// keys, so a host able to edit it could add a reader and have every sender
	/// encrypt to them. It has to be signed like any other policy.
	#[test]
	fn channel_readership_is_signed_policy() {
		let f = found(Mode::Sealed, 3, 2);
		let mut state = f.state();

		let alice = UserId::from_master_key(&Ed25519SecretKey::new().public_key());
		let mallory = UserId::from_master_key(&Ed25519SecretKey::new().public_key());

		let readers = SignedPolicy::sign(
			state.id,
			1,
			PolicyRecord::ChannelReaders {
				channel: "general".into(),
				readers: vec![alice],
			},
			&f.signers(&[0, 1]),
		);
		state.apply(&readers).unwrap();
		assert_eq!(state.channel_readers["general"], vec![alice]);

		// A host adding itself, without controller signatures, gets nowhere.
		let mut forged = SignedPolicy::sign(
			state.id,
			2,
			PolicyRecord::ChannelReaders {
				channel: "general".into(),
				readers: vec![alice, mallory],
			},
			&f.signers(&[0]),
		);
		forged.signatures.push(ControllerSignature {
			controller: 1,
			signature: [0; 64],
		});

		assert!(state.apply(&forged).is_err());
		assert_eq!(
			state.channel_readers["general"],
			vec![alice],
			"a refused policy must not partially apply"
		);
	}

	#[test]
	fn a_chain_replays_to_the_same_state() {
		let f = found(Mode::Sealed, 3, 2);

		let id = f.root.id();
		let chain = vec![
			SignedPolicy::sign(
				id,
				1,
				PolicyRecord::VersionRequirement { min_version: 3 },
				&f.signers(&[0, 1]),
			),
			SignedPolicy::sign(
				id,
				2,
				PolicyRecord::ModeTransition {
					new_mode: Mode::Open,
				},
				&f.signers(&[1, 2]),
			),
			SignedPolicy::sign(
				id,
				3,
				PolicyRecord::Migration {
					new_host: "veil.example".into(),
				},
				&f.signers(&[0, 2]),
			),
		];

		let mut a = f.state();
		let mut b = f.state();
		a.replay(&chain).unwrap();
		b.replay(&chain).unwrap();

		assert_eq!(a.mode, Mode::Open);
		assert_eq!(a.min_version, 3);
		assert_eq!(a.host.as_deref(), Some("veil.example"));
		assert_eq!(a.sequence, 3);
		assert_eq!(
			(b.mode, b.min_version, b.sequence),
			(a.mode, a.min_version, a.sequence)
		);
	}

	/// Roles come from the chain, so the ordinary case is that a record grants
	/// one and every replayer agrees.
	#[test]
	fn a_signed_record_grants_a_role() {
		let (mut community, controller, _) = community();
		let subject = UserId::from_master_key(&Ed25519SecretKey::new().public_key());

		assert_eq!(community.role(&subject), Role::Member);
		assert!(!community.may_moderate(&subject));

		community
			.apply(&SignedPolicy::sign(
				community.id,
				1,
				PolicyRecord::MemberRole {
					user: subject,
					role: Role::Moderator,
				},
				&[(0, &controller)],
			))
			.unwrap();

		assert_eq!(community.role(&subject), Role::Moderator);
		assert!(community.may_moderate(&subject));
	}

	/// A ban is a role, not a deletion, so it survives the member being re-added
	/// by somebody who did not know.
	#[test]
	fn a_ban_denies_posting() {
		let (mut community, controller, _) = community();
		let subject = UserId::from_master_key(&Ed25519SecretKey::new().public_key());

		community
			.apply(&SignedPolicy::sign(
				community.id,
				1,
				PolicyRecord::MemberRole {
					user: subject,
					role: Role::Banned,
				},
				&[(0, &controller)],
			))
			.unwrap();

		assert!(!community.may_post(&subject));
		assert!(!community.may_moderate(&subject));
	}

	/// The founder cannot be demoted out of their own community.
	///
	/// Otherwise a moderator they appointed could ban them, and the community
	/// would have no one able to recover it — the succession problem §12.4
	/// exists to avoid, arriving through the back door.
	#[test]
	fn the_founder_keeps_authority() {
		let (mut community, controller, founder) = community();

		community
			.apply(&SignedPolicy::sign(
				community.id,
				1,
				PolicyRecord::MemberRole {
					user: founder,
					role: Role::Banned,
				},
				&[(0, &controller)],
			))
			.unwrap();

		assert_eq!(community.role(&founder), Role::Moderator);
		assert!(community.may_post(&founder));
	}

	/// A role record is signed like anything else, so one controller short of
	/// the threshold cannot grant itself moderation (invariant 16).
	#[test]
	fn a_role_record_below_the_threshold_is_refused() {
		let first = Ed25519SecretKey::new();
		let second = Ed25519SecretKey::new();
		let founder = Ed25519SecretKey::new();

		let root = CommunityRoot::found(
			Mode::Sealed,
			vec![
				first.public_key().as_bytes().to_owned(),
				second.public_key().as_bytes().to_owned(),
			],
			2,
			&founder,
			1_000,
		)
		.unwrap();
		let mut community =
			CommunityState::from_root(root, founder.public_key().as_bytes()).unwrap();

		let subject = UserId::from_master_key(&Ed25519SecretKey::new().public_key());
		let record = PolicyRecord::MemberRole {
			user: subject,
			role: Role::Moderator,
		};

		assert!(
			community
				.apply(&SignedPolicy::sign(
					community.id,
					1,
					record.clone(),
					&[(0, &first)]
				))
				.is_err(),
			"one of two controllers must not be enough to grant a role"
		);
		assert_eq!(community.role(&subject), Role::Member);

		assert!(
			community
				.apply(&SignedPolicy::sign(
					community.id,
					1,
					record,
					&[(0, &first), (1, &second)]
				))
				.is_ok(),
			"and two of two must be"
		);
		assert_eq!(community.role(&subject), Role::Moderator);
	}

	/// A community with one controller, plus that controller's key and the
	/// founder's user id.
	fn community() -> (CommunityState, Ed25519SecretKey, UserId) {
		let founder = Ed25519SecretKey::new();
		let controller = Ed25519SecretKey::new();

		let root = CommunityRoot::found(
			Mode::Sealed,
			vec![controller.public_key().as_bytes().to_owned()],
			1,
			&founder,
			1_000,
		)
		.unwrap();
		let founder_id = root.founder;
		let community = CommunityState::from_root(root, founder.public_key().as_bytes()).unwrap();

		(community, controller, founder_id)
	}
}

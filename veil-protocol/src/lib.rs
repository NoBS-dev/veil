pub mod clock;
pub mod community;
pub mod crosssign;
pub mod groupkeys;
pub mod identity;
pub mod message;
pub mod version;

use crosssign::CrossSigningPublic;
use identity::{DeviceAddress, DeviceId, UserId};
use message::MessageId;
use version::VersionRange;

use rkyv::{
	Archive, Deserialize, Serialize, deserialize, rancor::Error, to_bytes, util::AlignedVec,
};
use sha2::{Digest, Sha256};
use std::{
	collections::HashMap,
	hash::Hash,
	time::{SystemTime, UNIX_EPOCH},
};
use vodozemac::{Ed25519PublicKey, Ed25519Signature, olm::Account};

/// Every signature in the protocol covers this prefix, so a signature produced
/// for one purpose can never be reinterpreted as one for another.
const SIGNING_DOMAIN: &[u8] = b"veil-envelope-v1";

/// How far an envelope's timestamp may drift from local time before we reject
/// it. Bounds how long a captured envelope stays replayable.
pub const REPLAY_WINDOW_MS: u64 = 60_000;

pub fn now_ms() -> anyhow::Result<u64> {
	Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

/// A signed, replay-resistant wrapper around a [`ProtocolMessage`].
///
/// The payload stays an opaque byte string rather than a nested struct so that
/// verification can run over the exact bytes that arrived. Decoding and
/// re-encoding is not guaranteed to be byte-identical, and verifying a
/// re-serialization would let two distinct wire forms share one signature.
#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct Envelope {
	pub payload: Vec<u8>,
	pub ed25519_public_key: [u8; 32],
	pub ed25519_signature: [u8; 64],
	pub timestamp_ms: u64,
	pub nonce: [u8; 16],
}

fn signing_input(
	payload: &[u8],
	public_key: &[u8; 32],
	timestamp_ms: u64,
	nonce: &[u8; 16],
) -> Vec<u8> {
	let mut buffer = Vec::with_capacity(SIGNING_DOMAIN.len() + 64 + payload.len());
	buffer.extend_from_slice(SIGNING_DOMAIN);
	buffer.extend_from_slice(public_key);
	buffer.extend_from_slice(&timestamp_ms.to_le_bytes());
	buffer.extend_from_slice(nonce);
	buffer.extend_from_slice(&(payload.len() as u64).to_le_bytes());
	buffer.extend_from_slice(payload);
	buffer
}

impl Envelope {
	pub fn seal(data: &ProtocolMessage, account: &Account) -> anyhow::Result<AlignedVec> {
		let payload = to_bytes::<Error>(data)?.to_vec();
		let public_key = *account.ed25519_key().as_bytes();
		let timestamp_ms = now_ms()?;

		let mut nonce = [0u8; 16];
		rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

		let signature = account
			.sign(signing_input(&payload, &public_key, timestamp_ms, &nonce))
			.to_bytes();

		Ok(to_bytes::<Error>(&Envelope {
			payload,
			ed25519_public_key: public_key,
			ed25519_signature: signature,
			timestamp_ms,
			nonce,
		})?)
	}
}

/// A verified envelope. Holding one means the signature checked out, so
/// `sender` is an identity the peer provably controls.
#[derive(Debug)]
pub struct OpenedEnvelope {
	pub sender: [u8; 32],
	pub message: ProtocolMessage,
	pub timestamp_ms: u64,
	pub nonce: [u8; 16],
}

fn aligned_copy(bytes: &[u8]) -> AlignedVec {
	let mut aligned: AlignedVec = AlignedVec::new();
	aligned.extend_from_slice(bytes);
	aligned
}

pub fn open_envelope(bytes: &[u8]) -> anyhow::Result<OpenedEnvelope> {
	let aligned = aligned_copy(bytes);

	let archived = rkyv::access::<ArchivedEnvelope, Error>(&aligned)?;

	let payload: &[u8] = &archived.payload;
	let sender = archived.ed25519_public_key;
	let timestamp_ms = archived.timestamp_ms.to_native();
	let nonce = archived.nonce;

	let public_key = Ed25519PublicKey::from_slice(&sender)?;
	let signature = Ed25519Signature::from_slice(&archived.ed25519_signature)?;

	public_key.verify(
		&signing_input(payload, &sender, timestamp_ms, &nonce),
		&signature,
	)?;

	let payload_aligned = aligned_copy(payload);
	let archived_message = rkyv::access::<ArchivedProtocolMessage, Error>(&payload_aligned)?;
	let message = deserialize::<ProtocolMessage, Error>(archived_message)?;

	Ok(OpenedEnvelope {
		sender,
		message,
		timestamp_ms,
		nonce,
	})
}

/// Rejects envelopes timestamped outside the accepted window, and any nonce
/// seen before within it. A signature stays valid forever, so without this an
/// attacker could re-send a captured envelope verbatim: replaying a
/// [`ProtocolMessage::UploadKeys`] would resurrect already-consumed one-time
/// keys, defeating the point of them being one-time.
pub struct ReplayGuard {
	window_ms: u64,
	seen: HashMap<[u8; 16], u64>,
	/// When the expired entries were last swept out.
	last_prune_ms: u64,
}

impl ReplayGuard {
	pub fn new(window_ms: u64) -> Self {
		Self {
			window_ms,
			seen: HashMap::new(),
			last_prune_ms: 0,
		}
	}

	/// Entries seen but not yet swept. Exposed for tests and diagnostics.
	pub fn tracked(&self) -> usize {
		self.seen.len()
	}

	pub fn check(&mut self, timestamp_ms: u64, nonce: [u8; 16]) -> anyhow::Result<()> {
		self.check_at(now_ms()?, timestamp_ms, nonce)
	}

	/// As [`Self::check`], with the current time supplied.
	///
	/// Exists because "now" is not always the system clock: §13.4 has servers
	/// keep an SNTP offset rather than trusting a container's wall clock, and a
	/// guard that reads the clock itself cannot be told about it — nor driven
	/// by a test.
	pub fn check_at(&mut self, now: u64, timestamp_ms: u64, nonce: [u8; 16]) -> anyhow::Result<()> {
		let drift = timestamp_ms.abs_diff(now);
		if drift > self.window_ms {
			// Named as clock skew rather than reported as a bad envelope. This
			// is almost always a drifting clock, and §13.4 exists because the
			// alternative — failing as a signature rejection — is close to
			// undiagnosable for whoever is running the box.
			anyhow::bail!(
				"clock skew: peer timestamp differs by {:.1}s, outside the {:.0}s window. \
				 Check the clock on both ends.",
				drift as f64 / 1000.0,
				self.window_ms as f64 / 1000.0,
			);
		}

		// Sweeping on every call is O(n) per message, which is fine at a
		// hundred messages a second and not at ten thousand (§13.3). Anything
		// older than the window is rejected above, so sweeping late cannot let
		// a replay back in — it only costs memory until the sweep happens.
		if now.saturating_sub(self.last_prune_ms) >= self.window_ms {
			self.seen
				.retain(|_, seen_at| seen_at.abs_diff(now) <= self.window_ms);
			self.last_prune_ms = now;
		}

		if self.seen.insert(nonce, timestamp_ms).is_some() {
			anyhow::bail!("envelope nonce was already used; this is a replay");
		}

		Ok(())
	}
}

impl Default for ReplayGuard {
	fn default() -> Self {
		Self::new(REPLAY_WINDOW_MS)
	}
}

/// Fixed-window request counter.
pub struct RateLimiter<K> {
	limit: u32,
	window_ms: u64,
	windows: HashMap<K, (u64, u32)>,
	last_prune_ms: u64,
}

impl<K: Eq + Hash> RateLimiter<K> {
	pub fn new(limit: u32, window_ms: u64) -> Self {
		Self {
			limit,
			window_ms,
			windows: HashMap::new(),
			last_prune_ms: 0,
		}
	}

	/// Keys currently tracked. Exposed for tests and diagnostics.
	pub fn tracked(&self) -> usize {
		self.windows.len()
	}

	/// Records a hit and reports whether the caller is still within budget.
	pub fn allow(&mut self, key: K, now_ms: u64) -> bool {
		// Without this the map grows for the life of the process — one entry per
		// IP ever seen, which is a slow memory leak on a public server (§13.3).
		// A key whose window has fully elapsed carries no information.
		if now_ms.saturating_sub(self.last_prune_ms) >= self.window_ms {
			let window_ms = self.window_ms;
			self.windows
				.retain(|_, (started, _)| now_ms.saturating_sub(*started) < window_ms);
			self.last_prune_ms = now_ms;
		}

		let window = self.windows.entry(key).or_insert((now_ms, 0));

		if now_ms.saturating_sub(window.0) >= self.window_ms {
			*window = (now_ms, 0);
		}

		window.1 = window.1.saturating_add(1);
		window.1 <= self.limit
	}
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub enum ProtocolMessage {
	/// Server -> client, sent first on every connection. The client must sign
	/// the challenge back to prove it holds the private half of the identity it
	/// claims before the server will route anything to it.
	Challenge(Challenge),
	/// Client -> server, echoing the challenge inside a signed envelope and
	/// declaring which identity this connection speaks for.
	///
	/// The envelope proves the device holds its own key; `keys` plus `binding`
	/// prove the device belongs to `user` (§5.4). Without them a device could
	/// quote any public master key and claim that user's identity.
	Authenticate(Box<Authenticate>),
	UploadKeys(UploadKeys),
	EncryptedMessage(EncryptedMessage),
	/// Server -> client: a frame that was queued while the device was away.
	///
	/// The inner frame is the sender's own signed envelope, untouched — this
	/// wrapper only carries the id to acknowledge. The server is not trusted for
	/// the contents; it is trusted to say what it is holding.
	Mail(Mail),
	/// Client -> server: these mailbox entries arrived and may be dropped.
	///
	/// Delivery is by acknowledgement rather than by send (§12.2), so a client
	/// that dies mid-flush gets the same mail again rather than losing it.
	Acknowledge(Vec<u64>),
	RemainingOneTimeKeys(u16),
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(attr(derive(Debug)))]
pub struct Challenge {
	pub challenge: [u8; 32],
	/// What the server can speak (§3.6). Carried inside this signed envelope
	/// rather than exchanged separately, so tampering breaks the signature
	/// instead of silently forcing a downgrade.
	pub versions: VersionRange,
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct Authenticate {
	pub challenge: [u8; 32],
	/// What the client can speak.
	pub versions: VersionRange,
	/// The server's range as the client received it.
	///
	/// Transcript binding: the server checks this against what it actually
	/// advertised, so an attacker who rewrites the challenge in flight is
	/// caught even though they could not have forged either signature.
	pub server_versions_seen: VersionRange,
	pub user: UserId,
	pub device: DeviceId,
	/// The user's cross-signing keys (§5.4). Public by design — the master key
	/// is checked against `user`, which is derived from it, and it must have
	/// signed both subkeys.
	pub keys: CrossSigningPublic,
	/// The **self-signing** key's signature over (user, device, device key).
	/// Verified against `keys`, so the chain runs device -> SSK -> MSK -> user.
	pub binding: [u8; 64],
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct Mail {
	pub id: u64,
	/// A complete signed envelope from the original sender.
	pub frame: Vec<u8>,
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct UploadKeys {
	pub encryption_key: [u8; 32], // x25519 key
	pub one_time_keys: Vec<[u8; 32]>,
	pub fallback_key: [u8; 32],
	/// Shown to peers so they can find this device without having messaged it.
	pub display_name: String,
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct EncryptedMessage {
	/// Sessions are device-to-device (§5.2), so both ends address a device
	/// rather than a user. A message to a user fans out to one of these per
	/// active device.
	pub sender: DeviceAddress,
	pub recipient: DeviceAddress,
	pub sender_x25519: [u8; 32],

	/// Distinguishes two otherwise identical messages, and is reused on retry so
	/// a resend lands on the same id and dedups (§10).
	pub nonce: [u8; 16],
	/// Sender's clock. Untrusted — it is an input to the message id, not an
	/// ordering authority.
	pub origin_ts: u64,
	/// The latest message this sender had seen from us when they sent (§10.1).
	///
	/// Sender-attested and inside the signed envelope, so a relay cannot forge
	/// or alter it. `ROOT` on the first message of a conversation.
	pub seen_head: MessageId,

	// I don't know why they're using usize instead of u8/bool but whatever
	pub message_type: usize, // 0: Normal, 1: PreKey
	pub message: Vec<u8>,
}

impl EncryptedMessage {
	/// Recomputed by the receiver rather than carried, so a sender cannot claim
	/// an id that disagrees with its content (§10).
	pub fn id(&self) -> MessageId {
		MessageId::derive(&self.sender, self.origin_ts, &self.nonce, &self.message)
	}
}

pub fn display_key(bytes: &[u8; 32]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex_key(hex: &str) -> anyhow::Result<[u8; 32]> {
	let bytes = hex::decode(hex)?;
	if bytes.len() != 32 {
		anyhow::bail!("Invalid key length: expected 32 bytes, got {}", bytes.len());
	}

	let mut array = [0u8; 32];
	array.copy_from_slice(&bytes);
	Ok(array)
}

/// A short code both sides of a conversation can read aloud to confirm nobody
/// swapped keys on them. Sorting the two identities first means both peers
/// derive the same digits without agreeing on who is "first".
pub fn safety_number(a: &[u8; 32], b: &[u8; 32]) -> String {
	let (first, second) = if a <= b { (a, b) } else { (b, a) };

	let mut hasher = Sha256::new();
	hasher.update(b"veil-safety-number-v1");
	hasher.update(first);
	hasher.update(second);
	let digest = hasher.finalize();

	digest
		.chunks_exact(5)
		.take(6)
		.map(|chunk| {
			let value = chunk.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
			format!("{:05}", value % 100_000)
		})
		.collect::<Vec<_>>()
		.join(" ")
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sealed(account: &Account) -> AlignedVec {
		Envelope::seal(&ProtocolMessage::RemainingOneTimeKeys(7), account).unwrap()
	}

	/// Round-trips an envelope through its decoded form so a test can change one
	/// field and re-seal without the signature being recomputed.
	fn tamper(bytes: &[u8], edit: impl FnOnce(&mut Envelope)) -> AlignedVec {
		let aligned = aligned_copy(bytes);
		let archived = rkyv::access::<ArchivedEnvelope, Error>(&aligned).unwrap();
		let mut envelope = deserialize::<Envelope, Error>(archived).unwrap();
		edit(&mut envelope);
		to_bytes::<Error>(&envelope).unwrap()
	}

	#[test]
	fn round_trip_reports_the_real_signer() {
		let account = Account::new();
		let opened = open_envelope(&sealed(&account)).unwrap();

		assert_eq!(&opened.sender, account.ed25519_key().as_bytes());
		assert!(matches!(
			opened.message,
			ProtocolMessage::RemainingOneTimeKeys(7)
		));
	}

	#[test]
	fn tampered_payload_is_rejected() {
		let account = Account::new();
		let forged = tamper(&sealed(&account), |envelope| envelope.payload[0] ^= 1);

		assert!(open_envelope(&forged).is_err());
	}

	#[test]
	fn tampered_signature_is_rejected() {
		let account = Account::new();
		let forged = tamper(&sealed(&account), |envelope| {
			envelope.ed25519_signature[0] ^= 1
		});

		assert!(open_envelope(&forged).is_err());
	}

	#[test]
	fn tampered_timestamp_is_rejected() {
		let account = Account::new();
		let forged = tamper(&sealed(&account), |envelope| envelope.timestamp_ms += 1);

		assert!(open_envelope(&forged).is_err());
	}

	/// The identity key is bound into the signed bytes, so an envelope cannot be
	/// re-labelled as coming from someone else.
	#[test]
	fn envelope_cannot_be_reattributed() {
		let account = Account::new();
		let impostor = Account::new();

		let forged = tamper(&sealed(&account), |envelope| {
			envelope.ed25519_public_key = *impostor.ed25519_key().as_bytes()
		});

		assert!(open_envelope(&forged).is_err());
	}

	#[test]
	fn replay_guard_rejects_a_repeated_nonce() {
		let mut guard = ReplayGuard::default();
		let now = now_ms().unwrap();

		assert!(guard.check(now, [1; 16]).is_ok());
		assert!(guard.check(now, [2; 16]).is_ok());
		assert!(guard.check(now, [1; 16]).is_err());
	}

	#[test]
	fn replay_guard_rejects_a_stale_timestamp() {
		let mut guard = ReplayGuard::default();
		let now = now_ms().unwrap();

		assert!(guard.check(now - REPLAY_WINDOW_MS - 1, [1; 16]).is_err());
		assert!(guard.check(now + REPLAY_WINDOW_MS + 1, [2; 16]).is_err());
	}

	/// §13.3: the limiter must not accumulate an entry per key ever seen.
	#[test]
	fn the_rate_limiter_forgets_keys_whose_window_elapsed() {
		let mut limiter = RateLimiter::new(5, 1_000);

		for n in 0..100u64 {
			limiter.allow(format!("ip-{n}"), 0);
		}
		assert_eq!(limiter.tracked(), 100);

		// Well past the window, those keys carry no information.
		limiter.allow("ip-fresh".to_owned(), 10_000);
		assert_eq!(limiter.tracked(), 1, "stale windows should have been swept");
	}

	/// The sweep is periodic rather than per-call, so it must still bound growth
	/// over a long run.
	#[test]
	fn the_replay_guard_does_not_grow_without_bound() {
		let mut guard = ReplayGuard::new(1_000);
		let start = 1_000_000u64;

		for n in 0..500u64 {
			let mut nonce = [0u8; 16];
			nonce[..8].copy_from_slice(&n.to_le_bytes());
			guard.check_at(start, start, nonce).unwrap();
		}
		assert_eq!(guard.tracked(), 500);

		// A later message, still inside its own window, triggers the sweep.
		let mut nonce = [0u8; 16];
		nonce[0] = 0xff;
		guard.check_at(start + 5_000, start + 5_000, nonce).unwrap();

		assert_eq!(
			guard.tracked(),
			1,
			"only the fresh nonce should remain, tracking {}",
			guard.tracked()
		);
	}

	/// Sweeping late must not let a replay back in — the timestamp window is
	/// what rejects old messages, not the presence of a remembered nonce.
	#[test]
	fn a_late_sweep_does_not_reopen_the_replay_window() {
		let mut guard = ReplayGuard::new(1_000);
		let start = 1_000_000u64;
		let nonce = [7u8; 16];

		guard.check_at(start, start, nonce).unwrap();
		// Same nonce, same timestamp, before any sweep: caught by memory.
		assert!(guard.check_at(start + 100, start, nonce).is_err());
		// Same nonce long after: caught by the timestamp window even though the
		// sweep has since forgotten it.
		assert!(guard.check_at(start + 60_000, start, nonce).is_err());
	}

	#[test]
	fn both_peers_derive_the_same_safety_number() {
		let a = [1; 32];
		let b = [2; 32];

		assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
		assert_ne!(safety_number(&a, &b), safety_number(&a, &[3; 32]));
		assert_eq!(safety_number(&a, &b).len(), 6 * 5 + 5);
	}

	#[test]
	fn rate_limiter_caps_then_recovers_next_window() {
		let mut limiter = RateLimiter::new(2, 1_000);

		assert!(limiter.allow("a", 0));
		assert!(limiter.allow("a", 0));
		assert!(!limiter.allow("a", 0));
		// A separate key has its own budget.
		assert!(limiter.allow("b", 0));
		// And the window rolls over.
		assert!(limiter.allow("a", 1_000));
	}
}

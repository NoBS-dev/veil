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
}

impl ReplayGuard {
	pub fn new(window_ms: u64) -> Self {
		Self {
			window_ms,
			seen: HashMap::new(),
		}
	}

	pub fn check(&mut self, timestamp_ms: u64, nonce: [u8; 16]) -> anyhow::Result<()> {
		let now = now_ms()?;

		if timestamp_ms.abs_diff(now) > self.window_ms {
			anyhow::bail!(
				"envelope timestamp is outside the {}ms replay window",
				self.window_ms
			);
		}

		// Anything older than the window is rejected above, so forgetting it
		// here cannot let a replay back in.
		self.seen
			.retain(|_, seen_at| seen_at.abs_diff(now) <= self.window_ms);

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
}

impl<K: Eq + Hash> RateLimiter<K> {
	pub fn new(limit: u32, window_ms: u64) -> Self {
		Self {
			limit,
			window_ms,
			windows: HashMap::new(),
		}
	}

	/// Records a hit and reports whether the caller is still within budget.
	pub fn allow(&mut self, key: K, now_ms: u64) -> bool {
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
	Challenge([u8; 32]),
	/// Client -> server, echoing the challenge inside a signed envelope.
	Authenticate([u8; 32]),
	UploadKeys(UploadKeys),
	EncryptedMessage(EncryptedMessage),
	RemainingOneTimeKeys(u16),
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct UploadKeys {
	pub encryption_key: [u8; 32], // x25519 key
	pub one_time_keys: Vec<[u8; 32]>,
	pub fallback_key: [u8; 32],
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct EncryptedMessage {
	pub sender_x25519: [u8; 32],
	pub recipient_ed25519: [u8; 32],

	// I don't know why they're using usize instead of u8/bool but whatever
	pub message_type: usize, // 0: Normal, 1: PreKey
	pub message: Vec<u8>,
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

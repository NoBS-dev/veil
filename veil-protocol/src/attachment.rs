//! Attachments — `DESIGN.md` §10.2.
//!
//! **Encryption follows the container's tier, and is never a per-file choice.**
//! A Sealed community gets end-to-end encrypted attachments; an Open one gets
//! attachments the host can process. That is §7.2's container inheritance
//! applied to media, and the tempting alternative — a per-upload "encrypt or
//! plaintext for speed" toggle — is deliberately absent.
//!
//! Two reasons, and the first is the one that matters. **It is a silent
//! downgrade, and one user makes it for everyone.** Bob posts something
//! sensitive in a Sealed community relying on the guarantee; Alice uploads a
//! screenshot of it unencrypted because that was faster, and Bob's disclosure
//! decision has been undone by somebody else's convenience setting. The person
//! bearing the cost is not the person making the choice.
//!
//! The second is that encryption is not the bottleneck it is imagined to be —
//! ChaCha20 runs at gigabytes per second, so a 100 MB video encrypts in well
//! under a tenth of a second. What makes Sealed media feel slow is the absence
//! of server transcoding, which a toggle would not fix.
//!
//! Consequences of the host holding ciphertext, all of them the host losing the
//! ability to process media: thumbnails are generated and uploaded by the
//! sender, there is no transcoding and so no adaptive quality, and two identical
//! files encrypt differently so nothing deduplicates. Quota enforcement still
//! works, because opaque sizes are all it needs.

use chacha20poly1305::{
	XChaCha20Poly1305, XNonce,
	aead::{Aead, KeyInit},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What a message carries in place of the file itself.
///
/// In a Sealed community this travels inside the Megolm-encrypted body, so the
/// key never reaches the host. In an Open one the `key` is absent and the blob
/// is the file.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
	pub blob: [u8; 32],
	pub filename: String,
	/// Plaintext length. The stored blob is longer when encrypted, by the AEAD
	/// tag — quotas count the stored size, not this.
	pub size: u64,
	/// Absent in an Open community, where the host holds the file itself.
	pub key: Option<[u8; 32]>,
	pub nonce: Option<[u8; 24]>,
}

/// A blob's id is the hash of the bytes the host stores.
///
/// Content-addressed so a host cannot substitute one blob for another: the
/// recipient recomputes this and refuses a mismatch. That check is what makes it
/// safe to fetch a file from a host nobody trusts — the same reasoning as
/// message ids (invariant 12), applied to bytes too large to put in a message.
pub fn blob_id(bytes: &[u8]) -> [u8; 32] {
	let mut hasher = Sha256::new();
	hasher.update(b"veil-blob-v1");
	hasher.update(bytes);
	hasher.finalize().into()
}

/// Prepares a file for a Sealed community: a fresh key per file.
///
/// Per file rather than per channel, so a leaked attachment key discloses one
/// file rather than every file ever posted.
pub fn seal(filename: &str, plaintext: &[u8]) -> anyhow::Result<(Attachment, Vec<u8>)> {
	let mut key = [0u8; 32];
	let mut nonce = [0u8; 24];
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

	let ciphertext = XChaCha20Poly1305::new((&key).into())
		.encrypt(XNonce::from_slice(&nonce), plaintext)
		.map_err(|e| anyhow::anyhow!("could not encrypt the attachment: {e}"))?;

	Ok((
		Attachment {
			blob: blob_id(&ciphertext),
			filename: filename.to_owned(),
			size: plaintext.len() as u64,
			key: Some(key),
			nonce: Some(nonce),
		},
		ciphertext,
	))
}

/// Prepares a file for an Open community, where the host holds the file itself.
pub fn open_tier(filename: &str, plaintext: &[u8]) -> Attachment {
	Attachment {
		blob: blob_id(plaintext),
		filename: filename.to_owned(),
		size: plaintext.len() as u64,
		key: None,
		nonce: None,
	}
}

/// Recovers a file from what the host served.
///
/// The id is checked before anything else, so a host that serves different bytes
/// is caught whether or not they would have decrypted.
pub fn open(attachment: &Attachment, stored: &[u8]) -> anyhow::Result<Vec<u8>> {
	if blob_id(stored) != attachment.blob {
		anyhow::bail!(
			"the host served bytes that do not hash to {}'s blob id — refusing them",
			attachment.filename
		);
	}

	let (Some(key), Some(nonce)) = (attachment.key, attachment.nonce) else {
		// No key: an Open community, where the blob is the file.
		return Ok(stored.to_vec());
	};

	XChaCha20Poly1305::new((&key).into())
		.decrypt(XNonce::from_slice(&nonce), stored)
		.map_err(|_| anyhow::anyhow!("could not decrypt {}", attachment.filename))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_sealed_attachment_round_trips() {
		let (attachment, stored) = seal("holiday.png", b"the actual file").unwrap();

		assert_ne!(stored, b"the actual file", "the host must hold ciphertext");
		assert_eq!(open(&attachment, &stored).unwrap(), b"the actual file");
		assert_eq!(attachment.size, "the actual file".len() as u64);
	}

	#[test]
	fn an_open_attachment_round_trips() {
		let attachment = open_tier("public.txt", b"nothing secret");
		assert_eq!(
			open(&attachment, b"nothing secret").unwrap(),
			b"nothing secret"
		);
	}

	/// The check that makes it safe to fetch from a host nobody trusts.
	#[test]
	fn substituted_bytes_are_refused() {
		let (attachment, _) = seal("holiday.png", b"the actual file").unwrap();

		let error = open(&attachment, b"something else entirely").unwrap_err();
		assert!(
			format!("{error}").contains("do not hash"),
			"a substituted blob must be refused on its id, got: {error}"
		);
	}

	/// And in an Open community too, where there is no decryption to fail.
	#[test]
	fn substituted_bytes_are_refused_without_encryption() {
		let attachment = open_tier("public.txt", b"nothing secret");
		assert!(
			open(&attachment, b"tampered").is_err(),
			"an Open attachment is still content-addressed"
		);
	}

	/// A tampered ciphertext that somehow kept its id would still fail the AEAD.
	#[test]
	fn a_tampered_ciphertext_is_refused() {
		let (mut attachment, mut stored) = seal("holiday.png", b"the actual file").unwrap();
		stored[0] ^= 1;
		attachment.blob = blob_id(&stored); // pretend the id matches

		assert!(
			open(&attachment, &stored).is_err(),
			"the AEAD tag must catch modification the id check would miss"
		);
	}

	/// Every file gets its own key, so one leaked key is one leaked file.
	#[test]
	fn each_file_gets_its_own_key() {
		let (first, _) = seal("a", b"same contents").unwrap();
		let (second, _) = seal("b", b"same contents").unwrap();

		assert_ne!(first.key, second.key);
		assert_ne!(
			first.blob, second.blob,
			"identical files must not deduplicate, which is the cost §10.2 accepts"
		);
	}
}

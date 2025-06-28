use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Deserialize, Serialize)]
pub struct EncryptedMessage {
	pub recipient: [u8; 32],
	/// Compressed with zstd and encrypted with AES-GCM-SIV
	pub message: Box<[u8]>,
}

use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Deserialize, Serialize)]
pub struct EncryptedMessage {
	pub recipient: [u8; 32],

	/// Compressed with zstd and encrypted with AES-GCM-SIV
	pub message: Box<[u8]>,
}

pub fn display_key(bytes: &[u8; 32]) -> String {
	bytes.iter().map(|b| format!("{:02x}", b)).collect()
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

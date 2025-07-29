use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Deserialize, Serialize)]
pub struct Signed<T> {
	pub data: T,
	pub signature: [u8; 64],
}
impl<T> Signed<T> {
	pub fn verify_signature(&self) {}
}

#[derive(Archive, Deserialize, Serialize)]
pub enum ProtocolMessage {
	EncryptedMessage(EncryptedMessage),
	KeyExchangeRequest(KeyExchangeRequest),
	KeyExchangeResponse(KeyExchangeResponse),
}

#[derive(Archive, Deserialize, Serialize)]
pub struct EncryptedMessage {
	pub recipient: [u8; 32],

	/// Compressed with zstd and encrypted with AES-GCM-SIV
	pub message: Box<[u8]>,
}

// Request will be sent by the client
#[derive(Archive, Deserialize, Serialize)]
pub struct KeyExchangeRequest {
	pub origin_identity_key: [u8; 32],
	pub origin_public_key: [u8; 32],
	pub target_identity_key: [u8; 32],
}

// Response will be sent by the server
#[derive(Archive, Deserialize, Serialize)]
pub struct KeyExchangeResponse {
	pub origin_identity_key: [u8; 32],
	pub target_identity_key: [u8; 32],
	// Implement double ratchet later, keys other than identity should only be used once
	pub target_public_key: [u8; 32],
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

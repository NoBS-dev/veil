use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rkyv::{Archive, Deserialize, Serialize, rancor::Error, to_bytes};

#[derive(Archive, Deserialize, Serialize, Debug)]
pub struct Signed {
	pub data: ProtocolMessage,
	pub identity_signature: [u8; 64],
}
impl Signed {
	pub fn verify_sig(&self, identity_pub_key: &[u8; 32]) -> anyhow::Result<bool> {
		let signature = Signature::from_bytes(&self.identity_signature);

		let mut data_bytes = to_bytes::<Error>(&self.data)?;
		data_bytes.extend_from_slice(identity_pub_key);

		let pub_key = VerifyingKey::from_bytes(&identity_pub_key)?;

		pub_key.verify(&data_bytes, &signature)?;

		Ok(true)
	}
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub enum ProtocolMessage {
	EncryptedMessage(EncryptedMessage),
	KeyExchangeRequest(KeyExchangeRequest),
	KeyExchangeResponse(KeyExchangeResponse),
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct EncryptedMessage {
	pub recipient: [u8; 32],

	/// Compressed with zstd and encrypted with AES-GCM-SIV
	pub message: Box<[u8]>,
}

// Request will be sent by the client
#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct KeyExchangeRequest {
	pub origin_identity_key: [u8; 32],
	pub origin_public_key: [u8; 32],
	pub target_identity_key: [u8; 32],
}

// Response will be sent by the server
#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
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

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rkyv::{
	Archive, Deserialize, Serialize, deserialize, rancor::Error, to_bytes, util::AlignedVec,
};
use tungstenite::Bytes;

#[derive(Archive, Deserialize, Serialize, Debug)]
pub struct Signed {
	pub data: ProtocolMessage,
	pub identity_key: [u8; 32],
	pub identity_signature: [u8; 64],
}
impl Signed {
	pub fn new_archived(data: ProtocolMessage, keypair: &SigningKey) -> anyhow::Result<AlignedVec> {
		let mut bytes = to_bytes::<Error>(&data)?;

		bytes.extend_from_slice(keypair.verifying_key().as_bytes());
		let signature = keypair.sign(&bytes);

		bytes.extend_from_slice(&signature.to_bytes());

		Ok(bytes)
	}
	pub fn verify_sig(&self) -> anyhow::Result<bool> {
		let signature = Signature::from_bytes(&self.identity_signature);

		let mut data_bytes = to_bytes::<Error>(&self.data)?;
		data_bytes.extend_from_slice(&self.identity_key);

		let pub_key = VerifyingKey::from_bytes(&self.identity_key)?;

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

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct KeyExchangeRequest {
	pub initiator_identity_key: [u8; 32],
	pub initiator_public_key: [u8; 32],
	pub recipient_identity_key: [u8; 32],
}

// This is constructed in response to a KeyExchangeRequest, so you are the recipient
#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct KeyExchangeResponse {
	pub initiator_identity_key: [u8; 32],
	// Implement double ratchet later, keys other than identity should only be used once
	pub recipient_public_key: [u8; 32],
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

pub async fn process_data(
	bytes: &Bytes,
	sender_public_key: &[u8; 32],
) -> anyhow::Result<ProtocolMessage> {
	let mut aligned: AlignedVec = AlignedVec::new();
	aligned.extend_from_slice(&bytes);

	let archived_signed = rkyv::access::<ArchivedSigned, rkyv::rancor::Error>(&aligned)?;
	let signed = deserialize::<Signed, rkyv::rancor::Error>(archived_signed)?;

	if !signed.verify_sig()? {
		anyhow::bail!(
			"Signature was received from {} and deserialized properly, though is invalid.",
			display_key(&sender_public_key)
		);
	} else {
		println!("Signature verified: {}", display_key(&signed.identity_key));
	}

	Ok(signed.data)
}

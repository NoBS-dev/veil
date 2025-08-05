use rkyv::{
	Archive, Deserialize, Serialize, deserialize, rancor::Error, to_bytes, util::AlignedVec,
};
use tungstenite::Bytes;
use vodozemac::{
	Ed25519PublicKey, Ed25519Signature,
	olm::{Account, OlmMessage, Session},
};

pub struct PeerSession {
	pub x25519: [u8; 32],
	pub session: Session,
}

#[derive(Archive, Deserialize, Serialize, Debug)]
pub struct Signed {
	pub data: ProtocolMessage,
	pub ed25519_public_key: [u8; 32],
	pub ed25519_signature: [u8; 64],
}
impl Signed {
	pub fn new_archived(data: ProtocolMessage, account: &Account) -> anyhow::Result<AlignedVec> {
		let mut bytes = to_bytes::<Error>(&data)?;

		bytes.extend_from_slice(account.ed25519_key().as_bytes());

		// Yes, this is referencing a to_bytes() instead of just as_bytes() because vodozemac goofy like that
		bytes.extend_from_slice(&account.sign(&bytes).to_bytes());

		Ok(bytes)
	}
	pub fn verify_sig(&self) -> anyhow::Result<bool> {
		let public_key = Ed25519PublicKey::from_slice(&self.ed25519_public_key)?;
		let signature = Ed25519Signature::from_slice(&self.ed25519_signature)?;

		let mut data_bytes = to_bytes::<Error>(&self.data)?;
		data_bytes.extend_from_slice(&self.ed25519_public_key);

		public_key.verify(&data_bytes, &signature)?;

		Ok(true)
	}
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub enum ProtocolMessage {
	UploadKeys(UploadKeys),
	// KeyRequest([u8; 32]), // recipient identity key
	EncryptedMessage(EncryptedMessage),
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[rkyv(attr(derive(Debug)))]
pub struct UploadKeys {
	// pub identity_key: [u8; 32],   // ed25519 key
	pub encryption_key: [u8; 32], // x25519 key
	pub one_time_keys: Vec<[u8; 32]>,
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

pub async fn process_data(
	bytes: &Bytes,
	sender_public_key: &[u8; 32],
) -> anyhow::Result<([u8; 32], ProtocolMessage)> {
	let mut aligned: AlignedVec = AlignedVec::new();
	aligned.extend_from_slice(&bytes);

	let archived_signed = rkyv::access::<ArchivedSigned, rkyv::rancor::Error>(&aligned)?;
	let signed = deserialize::<Signed, rkyv::rancor::Error>(archived_signed)?;

	if signed.verify_sig()? {
		// println!(
		// 	"Signature verified: {}",
		// 	display_key(&signed.ed25519_public_key)
		// );
	} else {
		anyhow::bail!(
			"Signature was received from {} and deserialized properly, though is invalid.",
			display_key(&sender_public_key)
		);
	}

	Ok((signed.ed25519_public_key, signed.data))
}

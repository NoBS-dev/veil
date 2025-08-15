use crate::{PeerSession, display_key, parse_hex_key};
use anyhow::Result;
use dashmap::DashMap;
use std::{
	io::{self, Write},
	sync::Arc,
};
use veil_protocol::{EncryptedMessage, ProtocolMessage};

pub async fn build_message(
	x25519_key: [u8; 32],
	target_client: [u8; 32],
	messageable_users: &Arc<DashMap<[u8; 32], PeerSession>>,
) -> Result<ProtocolMessage> {
	print!("Enter message: ");
	io::stdout().flush()?;

	let mut message = String::new();
	io::stdin().read_line(&mut message)?;

	if let Some(mut peer_session) = messageable_users.get_mut(&target_client) {
		let (msg_type, msg) = peer_session.session.encrypt(message).to_parts();

		let msg = ProtocolMessage::EncryptedMessage(EncryptedMessage {
			sender_x25519: x25519_key,
			recipient_ed25519: target_client,
			message_type: msg_type,
			message: msg,
		});

		Ok(msg)
	} else {
		Err(anyhow::anyhow!("No session found with target client."))
	}
}

pub async fn fetch_encryption_key_and_otk(
	target_identity_key: &[u8; 32],
	url: &str,
) -> Result<([u8; 32], [u8; 32])> {
	let target_client = display_key(target_identity_key);
	let url = format!("{}/clients/{}/otk", url, target_client);

	let body = reqwest::get(url).await?.text().await?;
	let mut lines = body.lines();
	let encryption_key =
		parse_hex_key(lines.next().ok_or_else(|| anyhow::anyhow!("missing key"))?)?;
	let otk = parse_hex_key(lines.next().ok_or_else(|| anyhow::anyhow!("missing otk"))?)?;

	Ok((encryption_key, otk))
}

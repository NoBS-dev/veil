use crate::{
	WriteStream, display_key, parse_hex_key,
	state::{PeerSession, State},
};
use anyhow::Result;
use futures_util::SinkExt;
use std::io::{self, Write};
use tungstenite::{Bytes, Message};
use veil_protocol::{EncryptedMessage, ProtocolMessage, Signed};
use vodozemac::olm::SessionConfig;

pub async fn send(write: &mut WriteStream, state: &mut State, url: &str) -> Result<()> {
	print!("Enter target client: ");
	io::stdout().flush()?;

	let target_client = {
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;
		parse_hex_key(input.trim())?
	};

	{
		if let std::collections::hash_map::Entry::Vacant(entry) = state.peers.entry(target_client) {
			let (their_x25519, otk) = fetch_encryption_key_and_otk(&target_client, url).await?;
			let session = state.account.create_outbound_session(
				SessionConfig::version_2(),
				their_x25519.into(),
				otk.into(),
			);

			entry.insert(PeerSession {
				x25519: their_x25519,
				session,
			});

			if let Err(e) = state.save_to_keyring() {
				eprintln!("Save state failed: {e:?}");
			} else {
				eprintln!("Saved!");
			}
		}
	}

	print!("Enter message: ");
	io::stdout().flush()?;
	let mut message = String::new();
	io::stdin().read_line(&mut message)?;
	let message = message.trim();

	let (msg_type, ciphertext) = {
		let peer = match state.peers.get_mut(&target_client) {
			Some(peer) => peer,
			None => {
				anyhow::bail!("No session with that client.")
			}
		};

		peer.session.encrypt(message).to_parts()
	};

	if let Err(e) = state.save_to_keyring() {
		eprintln!("Save state failed: {e:?}");
	} else {
		eprintln!("Saved!");
	}

	let signed_bytes = {
		let msg = ProtocolMessage::EncryptedMessage(EncryptedMessage {
			sender_x25519: state.account.curve25519_key().to_bytes(),
			recipient_ed25519: target_client,
			message_type: msg_type,
			message: ciphertext,
		});

		Signed::new_archived(msg, &state.account)?
	};

	write
		.send(Message::Binary(Bytes::copy_from_slice(&signed_bytes)))
		.await?;

	Ok(())
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

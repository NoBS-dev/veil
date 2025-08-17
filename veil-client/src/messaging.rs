use crate::{PeerSession, display_key, parse_hex_key, persistence::save_state_to_keyring};
use anyhow::Result;
use futures_util::{SinkExt, stream::SplitSink};
use std::{
	collections::HashMap,
	io::{self, Write},
	sync::Arc,
};
use tokio::{
	net::TcpStream,
	sync::{Mutex, RwLock},
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::{Bytes, Message};
use veil_protocol::{EncryptedMessage, ProtocolMessage, Signed};
use vodozemac::olm::Account;

pub async fn send_message(
	acc: &Arc<Mutex<Account>>,
	target_client: [u8; 32],
	msgable_users: &Arc<RwLock<HashMap<[u8; 32], PeerSession>>>,
	write: &Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
	ip_and_port: &String,
	profile: &String,
) -> Result<()> {
	print!("Enter message: ");
	io::stdout().flush()?;
	let mut message = String::new();
	io::stdin().read_line(&mut message)?;
	let message = message.trim();

	let (msg_type, ciphertext) = {
		let mut msgable_users_write_lock = msgable_users.write().await;

		let peer_session = match msgable_users_write_lock.get_mut(&target_client) {
			Some(session) => session,
			None => {
				anyhow::bail!("No session with that client.")
			}
		};

		peer_session.session.encrypt(message).to_parts()
	};

	let signed_bytes = {
		let acc_guard = acc.lock().await;
		let msg = ProtocolMessage::EncryptedMessage(EncryptedMessage {
			sender_x25519: acc_guard.curve25519_key().to_bytes(),
			recipient_ed25519: target_client,
			message_type: msg_type,
			message: ciphertext,
		});

		Signed::new_archived(msg, &acc_guard)?
	};

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(&signed_bytes)))
		.await?;

	if let Err(e) = save_state_to_keyring(&acc, &msgable_users, &ip_and_port, &profile).await {
		eprintln!("Save state failed: {e:?}");
	} else {
		eprintln!("Saved!");
	}

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

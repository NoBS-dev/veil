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
use vodozemac::olm::{Account, SessionConfig};

pub async fn send_message(
	acc: &Arc<Mutex<Account>>,
	peers: &Arc<RwLock<HashMap<[u8; 32], PeerSession>>>,
	write: &Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
	ip_and_port: &String,
	profile: &String,
	url: &String,
) -> Result<()> {
	print!("Enter target client: ");
	io::stdout().flush()?;

	let target_client = {
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;
		parse_hex_key(input.trim())?
	};

	{
		let mut peers_write_lock = peers.write().await;

		if !peers_write_lock.contains_key(&target_client) {
			let (their_x25519, otk) = fetch_encryption_key_and_otk(&target_client, url).await?;
			let session = acc.lock().await.create_outbound_session(
				SessionConfig::version_2(),
				their_x25519.into(),
				otk.into(),
			);

			peers_write_lock.insert(
				target_client,
				PeerSession {
					x25519: their_x25519,
					session,
				},
			);

			drop(peers_write_lock);

			if let Err(e) = save_state_to_keyring(&acc, &peers, &ip_and_port, &profile).await {
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
		let mut peers_write_lock = peers.write().await;

		let peer = match peers_write_lock.get_mut(&target_client) {
			Some(peer) => peer,
			None => {
				anyhow::bail!("No session with that client.")
			}
		};

		peer.session.encrypt(message).to_parts()
	};

	if let Err(e) = save_state_to_keyring(&acc, &peers, &ip_and_port, &profile).await {
		eprintln!("Save state failed: {e:?}");
	} else {
		eprintln!("Saved!");
	}

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

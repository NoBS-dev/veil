use crate::state::{PeerSession, State};
use futures_util::{StreamExt, stream::SplitStream};
use std::sync::Arc;
use tokio::{net::TcpStream, sync::Mutex};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::protocol::Message;
use veil_protocol::{EncryptedMessage, ProtocolMessage};
use vodozemac::olm::OlmMessage;

type ReadStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

pub async fn listener(mut read: ReadStream, state: Arc<Mutex<State>>) {
	let public_key_bytes = *state.lock().await.account.ed25519_key().as_bytes();

	while let Some(incoming_data) = read.next().await {
		match incoming_data {
			Ok(Message::Binary(protocol_message)) => {
				if let Ok((sender_public_key, signed_protocol_message)) =
					veil_protocol::process_signed_protocol_messages(
						&protocol_message,
						&public_key_bytes,
					)
					.await
				{
					match signed_protocol_message {
						ProtocolMessage::UploadKeys(resp) => {
							println!("Received an OTK upload request: {resp:?}");

							// TODO: Actually handle the server request
						}
						ProtocolMessage::EncryptedMessage(encrypted_message) => {
							println!("Received a msg: {encrypted_message:?}");
							process_encrypted_message(
								state.clone(),
								sender_public_key,
								encrypted_message,
							)
							.await;
						}
					}
				}
			}
			Ok(_) => println!("[Notification] Received something of unknown type."),
			Err(e) => println!("[Notification] Error: {e}"),
		}
	}
}

async fn process_encrypted_message(
	state: Arc<Mutex<State>>,
	sender_public_key: [u8; 32],
	message: EncryptedMessage,
) {
	let olm_message = match OlmMessage::from_parts(message.message_type, &message.message) {
		Ok(olm_message) => olm_message,
		Err(_) => {
			eprintln!("Invalid message recieved.");
			return;
		}
	};

	let mut state = state.lock().await;
	match olm_message {
		OlmMessage::PreKey(prekey_msg) => {
			println!("Received prekey message.");

			if !state.peers.contains_key(&sender_public_key) {
				match state
					.account
					.create_inbound_session(prekey_msg.identity_key(), &prekey_msg)
				{
					Ok(session) => {
						println!("Inbound session created successfully.");

						let text = String::from_utf8_lossy(&session.plaintext);
						println!("Message: {text}");

						state.peers.insert(
							sender_public_key,
							PeerSession {
								x25519: message.sender_x25519,
								session: session.session,
							},
						);
					}
					Err(e) => {
						eprintln!("Prekey parsing error: {e:#}")
					}
				}
			} else {
				eprintln!("Already had a session.");

				// TODO: don't repeat yourself
				if let Some(peer) = state.peers.get_mut(&sender_public_key) {
					match peer.session.decrypt(&prekey_msg.into()) {
						Ok(pt) => {
							println!("Received: {}", String::from_utf8_lossy(&pt));
						}
						Err(e) => eprintln!("Decrypt failed: {e:?}"),
					}
				} else {
					eprintln!("Normal message but no stored session for sender; dropping.");
				}
			}
		}

		OlmMessage::Normal(normal_msg) => {
			if let Some(peer) = state.peers.get_mut(&sender_public_key) {
				match peer.session.decrypt(&normal_msg.into()) {
					Ok(pt) => {
						let text = String::from_utf8_lossy(&pt);
						println!("Received: {text}");
					}
					Err(e) => eprintln!("Decrypt failed: {e:?}"),
				}
			} else {
				eprintln!("Normal message but no stored session for sender; dropping.");
			}
		}
	}

	if let Err(e) = state.save_to_keyring() {
		eprintln!("Save state failed: {e:?}");
	} else {
		eprintln!("Saved!");
	}
}

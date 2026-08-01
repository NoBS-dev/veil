use crate::{
	ReadStream,
	state::{PeerSession, State},
};
use futures_util::StreamExt;
use std::sync::Arc;
use tokio::sync::Mutex;
use tungstenite::protocol::Message;
use veil_protocol::{EncryptedMessage, ProtocolMessage, ReplayGuard, display_key, open_envelope};
use vodozemac::olm::OlmMessage;

pub async fn listener(mut read: ReadStream, state: Arc<Mutex<State>>, server_identity: [u8; 32]) {
	let mut replay_guard = ReplayGuard::default();

	while let Some(incoming_data) = read.next().await {
		match incoming_data {
			Ok(Message::Binary(protocol_message)) => {
				let opened = match open_envelope(&protocol_message) {
					Ok(opened) => opened,
					Err(e) => {
						eprintln!("[Notification] Discarding an unverifiable envelope: {e:#}");
						continue;
					}
				};

				if let Err(e) = replay_guard.check(opened.timestamp_ms, opened.nonce) {
					eprintln!("[Notification] Discarding a replayed envelope: {e:#}");
					continue;
				}

				match opened.message {
					ProtocolMessage::EncryptedMessage(encrypted_message) => {
						println!("Received a msg: {encrypted_message:?}");
						process_encrypted_message(state.clone(), opened.sender, encrypted_message)
							.await;
					}
					ProtocolMessage::RemainingOneTimeKeys(remaining_otks) => {
						// Only the server has a view of the pool, so anyone else
						// claiming to report on it is trying to talk us into
						// regenerating keys.
						if opened.sender != server_identity {
							eprintln!(
								"[Notification] Ignoring an OTK count from {}, which is not the server.",
								display_key(&opened.sender)
							);
							continue;
						}

						println!("We have {remaining_otks} OTKs left.");

						// If we have less than half OTKs in our pool, regen some more
					}
					protocol_message => {
						println!(
							"Received a protocol message that we don't usually handle: {:?}",
							protocol_message
						);
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

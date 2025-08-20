use crate::persistence::save_state_to_keyring;
use futures_util::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use tungstenite::protocol::Message;
use veil_protocol::{PeerSession, ProtocolMessage, process_signed_protocol_messages};
use vodozemac::{
	Curve25519PublicKey,
	olm::{Account, OlmMessage},
};

pub async fn start_listener(
	mut read: impl StreamExt<Item = Result<Message, tungstenite::Error>> + Unpin + Send + 'static,
	pub_key_bytes_clone: [u8; 32],
	acc_clone: Arc<Mutex<Account>>,
	peers: Arc<RwLock<HashMap<[u8; 32], PeerSession>>>,
	ip_and_port: &String,
	profile: &String,
) {
	let ip_and_port = ip_and_port.clone();
	let profile = profile.clone();

	tokio::spawn(async move {
		while let Some(incoming_data) = read.next().await {
			match incoming_data {
				Ok(Message::Binary(protocol_message)) => {
					if let Ok((sender_pub_key, signed_protocol_message)) =
						process_signed_protocol_messages(&protocol_message, &pub_key_bytes_clone)
							.await
					{
						match signed_protocol_message {
							ProtocolMessage::UploadKeys(resp) => {
								println!("Received an OTK upload request: {resp:?}");

								// TODO: Actually handle the server request
							}
							ProtocolMessage::EncryptedMessage(encrypted_message) => {
								println!("Received a msg: {encrypted_message:?}");

								if let Ok(olm_message) = OlmMessage::from_parts(
									encrypted_message.message_type,
									&encrypted_message.message,
								) {
									match olm_message {
										OlmMessage::PreKey(prekey_msg) => {
											println!("Received prekey message.");

											if !peers.read().await.contains_key(&sender_pub_key) {
												match acc_clone.lock().await.create_inbound_session(
													Curve25519PublicKey::from(
														prekey_msg.identity_key(),
													),
													&prekey_msg,
												) {
													Ok(session) => {
														println!(
															"Inbound session created successfully."
														);

														let text = String::from_utf8_lossy(
															&session.plaintext,
														);
														println!("Message: {text}");

														peers.write().await.insert(
															sender_pub_key,
															PeerSession {
																x25519: encrypted_message
																	.sender_x25519,
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
												if let Some(peer) =
													peers.write().await.get_mut(&sender_pub_key)
												{
													match peer.session.decrypt(&prekey_msg.into()) {
														Ok(pt) => {
															let text = String::from_utf8_lossy(&pt);
															println!("Received: {text}");
														}
														Err(e) => {
															eprintln!("Decrypt failed: {e:?}")
														}
													}
												} else {
													eprintln!(
														"Normal message but no stored session for sender; dropping."
													);
												}
											}
										}
										OlmMessage::Normal(normal_msg) => {
											if let Some(peer) =
												peers.write().await.get_mut(&sender_pub_key)
											{
												match peer.session.decrypt(&normal_msg.into()) {
													Ok(pt) => {
														let text = String::from_utf8_lossy(&pt);
														println!("Received: {text}");
													}
													Err(e) => eprintln!("Decrypt failed: {e:?}"),
												}
											} else {
												eprintln!(
													"Normal message but no stored session for sender; dropping."
												);
											}
										}
									}

									if let Err(e) = save_state_to_keyring(
										&acc_clone,
										&peers,
										&ip_and_port,
										&profile,
									)
									.await
									{
										eprintln!("Save state failed: {e:?}");
									} else {
										eprintln!("Saved!");
									}
								} else {
									println!("Invalid message received.");
								}
							}
						}
					}
				}
				Ok(_) => println!("[Notification] Received something of unknown type."),
				Err(e) => println!("[Notification] Error: {e}"),
			}
		}
	});
}

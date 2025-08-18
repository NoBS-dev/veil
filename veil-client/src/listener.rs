use crate::persistence::save_state_to_keyring;
use futures_util::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use tungstenite::protocol::Message;
use veil_protocol::{PeerSession, ProtocolMessage, process_data};
use vodozemac::{
	Curve25519PublicKey,
	olm::{Account, OlmMessage, SessionConfig},
};

pub async fn start_listener(
	mut read: impl StreamExt<Item = Result<Message, tungstenite::Error>> + Unpin + Send + 'static,
	pub_key_bytes_clone: [u8; 32],
	acc_clone: Arc<Mutex<Account>>,
	msgable_users_clone: Arc<RwLock<HashMap<[u8; 32], PeerSession>>>,
	ip_and_port: &String,
	profile: &String,
) {
	let ip_and_port = ip_and_port.clone();
	let profile = profile.clone();

	tokio::spawn(async move {
		while let Some(msg) = read.next().await {
			match msg {
				Ok(Message::Binary(data)) => {
					if let Ok((sender_pub_key, data)) =
						process_data(&data, &pub_key_bytes_clone).await
					{
						match data {
							ProtocolMessage::UploadKeys(resp) => {
								println!("Received an OTK upload request: {resp:?}");

								let session = acc_clone.lock().await.create_outbound_session(
									SessionConfig::version_2(),
									Curve25519PublicKey::from(resp.encryption_key),
									Curve25519PublicKey::from(resp.one_time_keys[0]),
								);

								msgable_users_clone.write().await.insert(
									sender_pub_key,
									PeerSession {
										x25519: resp.encryption_key,
										session,
									},
								);
								if let Err(e) = save_state_to_keyring(
									&acc_clone,
									&msgable_users_clone,
									&ip_and_port,
									&profile,
								)
								.await
								{
									eprintln!("Save state failed: {e:?}");
								} else {
									eprintln!("Saved!");
								}
							}
							ProtocolMessage::EncryptedMessage(message) => {
								println!("Received a msg: {message:?}");

								if let Ok(msg) =
									OlmMessage::from_parts(message.message_type, &message.message)
								{
									match msg {
										OlmMessage::PreKey(prekey_msg) => {
											println!("Received prekey message.");

											if let Ok(session) =
												acc_clone.lock().await.create_inbound_session(
													Curve25519PublicKey::from(
														message.sender_x25519,
													),
													&prekey_msg,
												) {
												println!("Inbound session created successfully.");

												let text =
													String::from_utf8_lossy(&session.plaintext);
												println!("Message: {text}");

												msgable_users_clone.write().await.insert(
													sender_pub_key,
													PeerSession {
														x25519: message.sender_x25519,
														session: session.session,
													},
												);
											} else {
												println!("Failed to create inbound session.");
											}
										}
										OlmMessage::Normal(normal_msg) => {
											if let Some(peer) = msgable_users_clone
												.write()
												.await
												.get_mut(&sender_pub_key)
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
										&msgable_users_clone,
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

use crate::persistence::save_state_to_keyring;
use dashmap::DashMap;
use futures_util::StreamExt;
use std::{
	io::{self, Write},
	sync::Arc,
};
use tokio::sync::Mutex;
use tungstenite::protocol::Message;
use veil_protocol::{PeerSession, ProtocolMessage, process_data};
use vodozemac::{
	Curve25519PublicKey,
	olm::{OlmMessage, SessionConfig},
};

pub async fn start_listener(
	mut read: impl StreamExt<Item = Result<Message, tungstenite::Error>> + Unpin + Send + 'static,
	pub_key_bytes_clone: [u8; 32],
	acc_clone: Arc<Mutex<vodozemac::olm::Account>>,
	msgable_users_clone: Arc<DashMap<[u8; 32], PeerSession>>,
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
								println!("Received an OTK: {resp:?}");

								let session = acc_clone.lock().await.create_outbound_session(
									SessionConfig::version_2(),
									Curve25519PublicKey::from(resp.encryption_key),
									Curve25519PublicKey::from(resp.one_time_keys[0]),
								);

								msgable_users_clone.insert(
									sender_pub_key,
									PeerSession {
										x25519: resp.encryption_key,
										session,
									},
								);

								if let Err(e) = save_state_to_keyring(
									&acc_clone,
									&msgable_users_clone,
									&ip_and_port.clone(),
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
									let mut acc_guard = acc_clone.lock().await;
									match msg {
										OlmMessage::PreKey(prekey_msg) => {
											println!("Received prekey message.");

											if let Ok(session) = &acc_guard.create_inbound_session(
												Curve25519PublicKey::from(message.sender_x25519),
												&prekey_msg,
											) {
												println!("Inbound session created successfully.");

												let text =
													String::from_utf8_lossy(&session.plaintext);
												println!("Message: {text}");
											} else {
												println!("Failed to create inbound session.");
											}
										}
										OlmMessage::Normal(_) => {
											println!("Received normal message.");
										}
									}

									if let Err(e) = save_state_to_keyring(
										&acc_clone,
										&msgable_users_clone,
										&ip_and_port.clone(),
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

			// TODO: Should prob fix prompting here
			println!();
			io::stdout().flush().unwrap();
		}
	});
}

use constcat::concat;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use std::{
	io::{self, Write},
	path::PathBuf,
	sync::Arc,
};
use tokio::{fs::File, io::AsyncWriteExt, sync::Mutex};
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{
	EncryptedMessage, PeerSession, ProtocolMessage, Signed, UploadKeys, display_key, parse_hex_key,
	process_data,
};
use vodozemac::{
	Curve25519PublicKey, Ed25519PublicKey,
	olm::{Account, MessageType, OlmMessage, Session, SessionConfig},
};

// TODO: Let user specify ip/port
const IP_AND_PORT: &str = "localhost:3000";
const SOCKET: &str = concat!("ws://", IP_AND_PORT);
const URL: &str = concat!("http://", IP_AND_PORT);
const PROMPT: &str = concat!(SOCKET, " > ");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	// Messagable users should store target client identity key, as well as secret
	// At first, the secret will be your ephemeral secret,
	// but when you get a call back or receive a key exchange request,
	// it will be replaced by the diffie hellman derived shared secret
	let messageable_users: Arc<DashMap<[u8; 32], PeerSession>> = Arc::new(DashMap::new());
	let messageable_users_clone = messageable_users.clone();

	let (ws_stream, _) = tokio_tungstenite::connect_async(SOCKET).await?;
	let (write, mut read) = ws_stream.split();
	let write = Arc::new(Mutex::new(write));
	let write_clone = write.clone();

	let acc = Arc::new(Mutex::new(Account::new()));
	let acc_clone = acc.clone();

	let mut acc_guard = acc.lock().await;
	let pub_key_bytes = acc_guard.ed25519_key().as_bytes().clone();
	let pub_key_bytes_clone = pub_key_bytes.clone();
	let signing_key_clone = acc_guard.identity_keys().ed25519.clone();

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(&pub_key_bytes)))
		.await?;

	println!("My public key: {}", display_key(&pub_key_bytes));

	// We're just generating 20 for now, should increase later in prod
	const OTK_NUM: usize = 20;
	acc_guard.generate_one_time_keys(OTK_NUM);

	let otks = acc_guard
		.one_time_keys()
		.iter()
		.map(|(_, key)| key.as_bytes().clone())
		.collect();

	let key_upload_request = ProtocolMessage::UploadKeys(UploadKeys {
		// identity_key: acc_guard.identity_keys().ed25519.as_bytes().clone(),
		encryption_key: acc_guard.curve25519_key().to_bytes(),
		one_time_keys: otks,
	});

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(
			&Signed::new_archived(key_upload_request, &acc_guard)?,
		)))
		.await?;

	acc_guard.mark_keys_as_published();

	drop(acc_guard);

	// Listener
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

								messageable_users_clone.insert(
									sender_pub_key,
									PeerSession {
										x25519: resp.encryption_key,
										session: session,
									},
								);
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
										OlmMessage::Normal(normal_msg) => {
											println!("Received normal message.");
										}
									}
								} else {
									println!("Invalid message received.");
								}
							}
							_ => println!("[Notification] Received message: {data:?}"),
						}
					}
				}
				Ok(_) => {
					println!("[Notification] Received something of unknown type.");
				}
				Err(e) => {
					println!("[Notification] Error: {e}");
				}
			}
			print!("{PROMPT}");
			io::stdout().flush().unwrap();
		}
	});

	// Talking to server
	loop {
		print!("{PROMPT}");
		io::stdout().flush()?;
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;

		// Cmds (pre-conversation)
		match input.to_lowercase().trim() {
			"help" => {
				println!("-- Command list --");
				println!("list: Lists the clients that are connected to the server");
				println!(
					"msgable: Lists the clients that you have a session with and can message them properly"
				);
				println!("quit | exit: Shuts down the client");
				println!(
					"msg | key-exchange: Sends a message to or initiates a key exchange to a client, depending on if you have a valid session with them or not"
				);
			}
			"list" => {
				println!("{:?}", list_clients().await?);
			}
			"quit" | "exit" => {
				println!("Quitting...");
				std::process::exit(0);
			}
			"msgable" => {
				for entry in messageable_users.iter() {
					println!("{}", display_key(entry.key()));
				}
			}
			"msg" | "key-exchange" => {
				println!("{:?}", list_clients().await?);

				print!("Enter target client: ");
				io::stdout().flush()?;

				let target_client = {
					let mut input = String::new();
					io::stdin().read_line(&mut input)?;
					parse_hex_key(input.trim())?
				};

				if messageable_users.contains_key(&target_client) {
					// TODO: Start messaging
				} else {
					if let Ok((encryption_key, otk)) =
						fetch_encryption_key_and_otk(&target_client).await
					{
						let acc_guard = acc.lock().await;
						let session = {
							acc_guard.create_outbound_session(
								SessionConfig::version_2(),
								Curve25519PublicKey::from(encryption_key),
								Curve25519PublicKey::from(otk),
							)
						};

						messageable_users.insert(
							target_client,
							PeerSession {
								x25519: encryption_key,
								session: session,
							},
						);

						let msg = build_message(
							acc_guard.curve25519_key().to_bytes(),
							target_client,
							&messageable_users,
						)
						.await?;

						write
							.lock()
							.await
							.send(Message::Binary(Bytes::copy_from_slice(
								&Signed::new_archived(msg, &acc_guard)?,
							)))
							.await?;

						println!("Sent a pre-key message to {}", display_key(&target_client));
					}
				}
			}

			_ => println!("Invalid option. Ignoring..."),
		}
	}
}

async fn list_clients() -> anyhow::Result<Vec<String>> {
	Ok(reqwest::get(format!("{URL}/clients"))
		.await?
		.text()
		.await?
		.lines()
		.map(|line| line.trim().to_string())
		.collect())
}

async fn build_message(
	x25519_key: [u8; 32],
	target_client: [u8; 32],
	messageable_users: &Arc<DashMap<[u8; 32], PeerSession>>,
) -> anyhow::Result<ProtocolMessage> {
	print!("Enter message: ");
	io::stdout().flush()?;

	let message = {
		let mut message = String::new();
		io::stdin().read_line(&mut message)?;
		message
	};

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

async fn open_or_save_to_file(filename: PathBuf) -> anyhow::Result<()> {
	// TODO: Actually account for encryption and serialization
	if filename.exists() {
		// File exists, open and read it
		let contents = tokio::fs::read_to_string(&filename).await?;
		println!("File contents: {contents}");
	} else {
		// // File doesn't exist, create it and write some data
		let mut file = File::create(&filename).await?;
		file.write_all(b"New file created").await?;
		println!("Created new file: {filename:?}");
	}

	Ok(())
}

async fn fetch_encryption_key_and_otk(
	target_identity_key: &[u8; 32],
) -> anyhow::Result<([u8; 32], [u8; 32])> {
	let target_client = display_key(&target_identity_key);
	let url = format!("{}/clients/{}/otk", URL, target_client);

	let body = reqwest::get(url).await?.text().await?;

	let mut lines = body.lines();
	let encryption_key =
		parse_hex_key(lines.next().ok_or_else(|| anyhow::anyhow!("missing key"))?)?;
	let otk = parse_hex_key(lines.next().ok_or_else(|| anyhow::anyhow!("missing otk"))?)?;

	Ok((encryption_key, otk))
}

use constcat::concat;
use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use std::{
	io::{self, Write},
	path::PathBuf,
	sync::Arc,
};
use tokio::{fs::File, io::AsyncWriteExt, sync::Mutex};
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{
	KeyExchangeRequest, KeyExchangeResponse, ProtocolMessage, Signed, display_key, parse_hex_key,
	process_data,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

// TODO: Let user specify ip/port
const IP_AND_PORT: &str = "localhost:3000";
const SOCKET: &str = concat!("ws://", IP_AND_PORT);
const URL: &str = concat!("http://", IP_AND_PORT);
const PROMPT: &str = concat!(SOCKET, " > ");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	// It's kinda confusing, but the signing key contains both the public and private keys
	let signing_key = Arc::new(SigningKey::generate(&mut OsRng));

	// Messagable users should store target client identity key, as well as secret
	// At first, the secret will be your ephemeral secret,
	// but when you get a call back or receive a key exchange request,
	// it will be replaced by the diffie hellman derived shared secret
	let messageable_users: Arc<DashMap<[u8; 32], [u8; 32]>> = Arc::new(DashMap::new());
	let messageable_users_clone = messageable_users.clone();

	let pending_key_exchanges: Arc<DashMap<[u8; 32], EphemeralSecret>> = Arc::new(DashMap::new());
	let pending_key_exchanges_clone = pending_key_exchanges.clone();

	let (ws_stream, _) = tokio_tungstenite::connect_async(SOCKET).await?;
	let (write, mut read) = ws_stream.split();
	let write = Arc::new(Mutex::new(write));

	let pub_key_bytes = signing_key.verifying_key().to_bytes();

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(&pub_key_bytes)))
		.await?;

	println!("My public key: {}", display_key(&pub_key_bytes));

	let write_clone = write.clone();
	let signing_key_clone = signing_key.clone();

	// Listener
	tokio::spawn(async move {
		while let Some(msg) = read.next().await {
			match msg {
				Ok(Message::Binary(data)) => match process_data(&data, &pub_key_bytes).await {
					Ok(processed_data) => match processed_data {
						ProtocolMessage::KeyExchangeRequest(req) => {
							println!("[Notification] Received a key exchange request: {req:?}");
							println!("Sending a key exchange response...");

							if let Ok(response_msg) = generate_key_exchange_response(
								&req,
								&signing_key_clone,
								&messageable_users_clone,
							)
							.await
							{
								if let Err(e) = write_clone.lock().await.send(response_msg).await {
									eprintln!("Failed to send key exchange response: {e:?}");
								} else {
									println!("Key exchange response sent.");
								}
							} else {
								eprintln!("Failed to build key exchange response.");
							}
						}
						ProtocolMessage::KeyExchangeResponse(resp) => {
							println!("[Notification] Receieved a key exchange response: {resp:?}");

							handle_key_exchange_response(
								&resp,
								&pending_key_exchanges_clone,
								&messageable_users_clone,
							)
							.await;
						}
						_ => println!("[Notification] Received message: {data:?}"),
					},
					Err(e) => println!("{e:?}"),
				},
				Ok(_) => {
					println!("[Notification] Received something of unknown type.");
				}
				Err(e) => {
					println!("[Notification] Error: {e}");
					break;
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
			"list" => {
				println!("{:?}", list_clients().await?);
			}
			"quit" | "exit" => {
				println!("Quitting...");
				std::process::exit(0);
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
					print!("Key exchange has not been performed.\nDo it now? (Y/n) ");
					io::stdout().flush()?;

					let input: String = {
						let mut input = String::new();
						io::stdin().read_line(&mut input)?;
						input
					};

					match input.trim().to_lowercase().as_str() {
						"y" | "" => {
							// TODO: Figure out how to not store the ephemeral key, but also use it to diffie hellman the other's public key once a response arrives
							let message = generate_key_exchange_request(
								pub_key_bytes,
								target_client,
								&signing_key,
								&pending_key_exchanges,
							)
							.await?;
							write.lock().await.send(message).await?;
						}
						_ => {
							println!("Can't communicate without exchanging keys. Leaving...");
						}
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

async fn generate_key_exchange_request(
	recipient_identity_key: [u8; 32],
	target_client: [u8; 32],
	signing_key: &SigningKey,
	pending_key_exchanges: &DashMap<[u8; 32], EphemeralSecret>,
) -> anyhow::Result<(Message)> {
	let private_key = EphemeralSecret::random();
	let public_key = PublicKey::from(&private_key);

	let request = ProtocolMessage::KeyExchangeRequest(KeyExchangeRequest {
		initiator_identity_key: recipient_identity_key,
		initiator_public_key: public_key.to_bytes(),
		recipient_identity_key: target_client,
	});

	let archived_signed_request = Signed::new_archived(request, signing_key)?;

	pending_key_exchanges.insert(target_client, private_key);

	Ok(Message::Binary(Bytes::copy_from_slice(
		archived_signed_request.as_slice(),
	)))
}

async fn generate_key_exchange_response(
	request: &KeyExchangeRequest,
	signing_key: &SigningKey,
	messageable_users: &DashMap<[u8; 32], [u8; 32]>,
) -> anyhow::Result<Message> {
	let private_key = EphemeralSecret::random();
	let public_key = PublicKey::from(&private_key);
	let shared_secret = private_key.diffie_hellman(&PublicKey::from(request.initiator_public_key));

	println!("Shared secret: {}", display_key(&shared_secret.as_bytes()));

	let response = KeyExchangeResponse {
		initiator_identity_key: request.initiator_identity_key,
		recipient_public_key: public_key.to_bytes(),
		recipient_identity_key: signing_key.verifying_key().to_bytes(),
	};

	messageable_users.insert(response.initiator_identity_key, shared_secret.to_bytes());

	let archived_signed_response =
		Signed::new_archived(ProtocolMessage::KeyExchangeResponse(response), signing_key)?;

	Ok(Message::Binary(Bytes::copy_from_slice(
		archived_signed_response.as_slice(),
	)))
}

async fn handle_key_exchange_response(
	response: &KeyExchangeResponse,
	pending_key_exchanges: &DashMap<[u8; 32], EphemeralSecret>,
	messageable_users: &DashMap<[u8; 32], [u8; 32]>,
) {
	println!("Handling key exchange response...");

	if let Some((_, private_key)) = pending_key_exchanges.remove(&response.recipient_identity_key) {
		let shared_secret =
			private_key.diffie_hellman(&PublicKey::from(response.recipient_public_key));

		println!("Shared secret: {}", display_key(shared_secret.as_bytes()));

		messageable_users.insert(response.recipient_identity_key, shared_secret.to_bytes());
	} else {
		eprintln!(
			"Something went wrong extracting the ephemeral key from the pending key exchanges map."
		);
	}
}

async fn send_message(target_client: [u8; 32]) -> anyhow::Result<()> {
	print!("Enter message: ");
	io::stdout().flush()?;

	let message = {
		let mut message = String::new();
		io::stdin().read_line(&mut message)?;
		message
	};

	Ok(())
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

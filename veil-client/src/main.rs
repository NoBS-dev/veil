use constcat::concat;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use std::{
	collections::HashMap,
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
	let messageable_users: HashMap<[u8; 32], [u8; 32]> = HashMap::new();

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

							write_clone
								.lock()
								.await
								.send(
									generate_key_exchange_response(&req, &signing_key)
										.await
										.unwrap(),
								)
								.await
								.unwrap();
						}
						ProtocolMessage::KeyExchangeResponse(resp) => {
							println!("[Notification] Receieved a key exchange response: {resp:?}");
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
							write
								.lock()
								.await
								.send(
									generate_key_exchange_request(
										pub_key_bytes,
										target_client,
										&signing_key_clone,
									)
									.await?,
								)
								.await?
						}
						_ => {
							println!("Can't communicate without exchanging keys. Leaving...");
						}
					}
				}

				// TODO: Make work
				// if let Ok(shared_secret) = key_exchange_request(&signing_key, target_client).await {
				// 	messageable_users.insert(target_client, shared_secret);
				// }

				// send_message(target_client).await?;

				// TODO: Ensure that we have a shared secret key with the recipient.
				// If not, we need to prompt them to initiate a key exchange.

				// TODO encryption and zstd compression, then send message
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
	initiator_identity_key: [u8; 32],
	target_client: [u8; 32],
	signing_key: &SigningKey,
) -> anyhow::Result<Message> {
	let private_key = EphemeralSecret::random();
	let public_key = PublicKey::from(&private_key);

	let request = KeyExchangeRequest {
		initiator_identity_key,
		initiator_public_key: public_key.to_bytes(),
		recipient_identity_key: target_client,
	};

	let request = ProtocolMessage::KeyExchangeRequest(request);

	let archived_signed_request = Signed::new_archived(request, signing_key)?;

	Ok(Message::Binary(Bytes::copy_from_slice(
		archived_signed_request.as_slice(),
	)))
}

async fn generate_key_exchange_response(
	request: &KeyExchangeRequest,
	signing_key: &SigningKey,
) -> anyhow::Result<Message> {
	let private_key = EphemeralSecret::random();
	let public_key = PublicKey::from(&private_key);
	let shared_secret = private_key.diffie_hellman(&PublicKey::from(request.initiator_public_key));

	println!("{}", display_key(&shared_secret.as_bytes()));

	let response = KeyExchangeResponse {
		initiator_identity_key: request.initiator_identity_key,
		recipient_public_key: public_key.to_bytes(),
	};

	let archived_signed_response =
		Signed::new_archived(ProtocolMessage::KeyExchangeResponse(response), signing_key)?;

	Ok(Message::Binary(Bytes::copy_from_slice(
		archived_signed_response.as_slice(),
	)))
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

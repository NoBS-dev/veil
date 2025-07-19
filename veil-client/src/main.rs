use constcat::concat;
use futures_util::{SinkExt, StreamExt};
use std::{
	io::{self, Write},
	path::PathBuf,
};
use tokio::{fs::File, io::AsyncWriteExt};
use tokio_tungstenite::connect_async;
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::*;
use vodozemac::Ed25519Keypair;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

const IP_AND_PORT: &str = "localhost:3000";
const SOCKET: &str = concat!("ws://", IP_AND_PORT);
const URL: &str = concat!("http://", IP_AND_PORT);
const PROMPT: &str = concat!(SOCKET, " > ");

struct MessageableUsers {
	other_public_key: PublicKey,
	shared_secret: SharedSecret,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let mut messageable_users: Vec<MessageableUsers> = Vec::new();

	let (ws_stream, _) = connect_async(SOCKET).await?;
	let (mut write, mut read) = ws_stream.split();

	let identity_key_pair = Ed25519Keypair::new();
	let pub_key_bytes = *identity_key_pair.public_key().as_bytes();

	write
		.send(Message::Binary(Bytes::copy_from_slice(&pub_key_bytes)))
		.await?;

	println!("My public key: {}", display_key(&pub_key_bytes));

	// Spawn a task to listen for incoming notifs
	tokio::spawn(async move {
		while let Some(msg) = read.next().await {
			match msg {
				Ok(Message::Binary(data)) => {
					println!("\n[Notification] Received binary message: {:?}", data);
					print!("{}", PROMPT);
					io::stdout().flush().unwrap();
				}
				Ok(_) => {}
				Err(e) => {
					println!("\n[Notification] Error: {}", e);
					break;
				}
			}
		}
	});

	// Talking to server
	loop {
		print!("{}", PROMPT);
		io::stdout().flush()?;
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;

		// Cmds (pre-conversation)
		match input.to_lowercase().trim() {
			"list" => {
				println!("{:?}", list_clients().await?);
			}
			"quit" => {
				println!("Quitting...");
				std::process::exit(0);
			}
			"msg" | "key-exchange" => {
				println!("{:?}", list_clients().await?);

				print!(
					"Enter target client\n(you are {}): ",
					display_key(&pub_key_bytes)
				);
				io::stdout().flush()?;

				let target_client = {
					let mut input = String::new();
					io::stdin().read_line(&mut input)?;
					parse_hex_key(input.trim())?
				};

				if list_clients().await?.contains(&display_key(&target_client)) {
					if let Some(_) = messageable_users
						.iter()
						.find(|user| user.other_public_key.as_bytes() == &target_client)
					{
						// TODO: Start messaging
					} else {
						println!("Key exchange has not been performed\nDo it now? (Y/n) ");

						let input: String = {
							let mut input = String::new();
							io::stdin().read_line(&mut input)?;
							input
						};

						match input.trim().to_lowercase().as_str() {
							"y" | "" => {
								send_key_exchange_request(target_client).await?;
							}
							_ => println!("Can't communicate without exchanging keys. Leaving..."),
						}
					}
				} else {
					println!("Invalid client.");
				}

				// TODO: Make work
				if let Ok(shared_secret) = send_key_exchange_request(target_client).await {
					messageable_users.push(MessageableUsers {
						other_public_key: PublicKey::from(target_client),
						shared_secret: shared_secret,
					});
				}

				print!("Enter message: ");
				io::stdout().flush()?;

				let message = {
					let mut message = String::new();
					io::stdin().read_line(&mut message)?;
					let message = message.trim();
				};

				// TODO: Ensure that we have a shared secret key with the recipient.
				// If not, we need to prompt them to initiate a key exchange.

				// TODO encryption and zstd compression, then send message
			}
			_ => println!("Invalid option. Ignoring."), // Do nothing
		}
	}
}

async fn list_clients() -> anyhow::Result<Vec<String>> {
	Ok(reqwest::get(format!("{}/clients", URL))
		.await?
		.text()
		.await?
		.lines()
		.map(|line| line.trim().to_string())
		.collect())
}

async fn send_key_exchange_request(target_client: [u8; 32]) -> anyhow::Result<SharedSecret> {
	let private_key = EphemeralSecret::random();
	let public_key = PublicKey::from(&private_key); // TODO: Send this to the server

	// TODO: Actually get the pub key from the server
	let other_private_key = EphemeralSecret::random();
	let other_public_key = PublicKey::from(&other_private_key);

	Ok(private_key.diffie_hellman(&other_public_key))
}

async fn open_or_save_to_file(filename: PathBuf) -> anyhow::Result<()> {
	// TODO: Actually account for encryption and serialization
	if filename.exists() {
		// File exists, open and read it
		let contents = tokio::fs::read_to_string(&filename).await?;
		println!("File contents: {}", contents);
	} else {
		// // File doesn't exist, create it and write some data
		let mut file = File::create(&filename).await?;
		file.write_all(b"New file created").await?;
		println!("Created new file: {:?}", filename);
	}

	Ok(())
}

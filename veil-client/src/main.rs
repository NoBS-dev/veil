use constcat::concat;
use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use once_cell::sync::Lazy;
use rkyv::{rancor::Error, to_bytes, validation::archive};
use std::{
	collections::HashMap,
	io::{self, Write},
	path::PathBuf,
	sync::Arc,
};
use tokio::{fs::File, io::AsyncWriteExt, sync::Mutex};
use tokio_tungstenite::{WebSocketStream, connect_async};
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::*;
use vodozemac::Ed25519Keypair;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

// TODO: Let user specify ip/port
const IP_AND_PORT: &str = "localhost:3000";
const SOCKET: &str = concat!("ws://", IP_AND_PORT);
const URL: &str = concat!("http://", IP_AND_PORT);
const PROMPT: &str = concat!(SOCKET, " > ");

static IDENTITY_KEYPAIR: Lazy<Ed25519Keypair> = Lazy::new(|| Ed25519Keypair::new());

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	// The first hashmap entry will contain the other users' identity key.
	// The second will be the shared secret from the key exchange.
	let mut messageable_users: HashMap<[u8; 32], [u8; 32]> = HashMap::new();

	let (ws_stream, _) = connect_async(SOCKET).await?;
	let (write, read) = ws_stream.split();

	let write = Arc::new(Mutex::new(write));
	let read = Arc::new(Mutex::new(read));

	let pub_key_bytes = *IDENTITY_KEYPAIR.public_key().as_bytes();

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(&pub_key_bytes)))
		.await?;

	println!("My public key: {}", display_key(&pub_key_bytes));

	// Spawn a task to listen for incoming notifs
	tokio::spawn(async move {
		while let Some(msg) = read.lock().await.next().await {
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
					if messageable_users.contains_key(&target_client) {
						// TODO: Start messaging
					} else {
						print!("Key exchange has not been performed\nDo it now? (Y/n) ");

						let input: String = {
							let mut input = String::new();
							io::stdin().read_line(&mut input)?;
							input
						};

						match input.trim().to_lowercase().as_str() {
							"y" | "" => {
								send_key_exchange_request(target_client, write.clone()).await?;
							}
							_ => println!("Can't communicate without exchanging keys. Leaving..."),
						}
					}
				} else {
					println!("Client not connected.");
				}

				// TODO: Make work
				if let Ok(shared_secret) =
					send_key_exchange_request(target_client, write.clone()).await
				{
					messageable_users.insert(target_client, *shared_secret.as_bytes());
				}

				send_message(target_client).await?;

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

async fn send_key_exchange_request(
	target_client: [u8; 32],
	write: Arc<
		tokio::sync::Mutex<
			SplitSink<
				WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
				tungstenite::Message,
			>,
		>,
	>,
) -> anyhow::Result<SharedSecret> {
	let private_key = EphemeralSecret::random();
	let public_key = PublicKey::from(&private_key); // TODO: Send this to the server

	let request = KeyExchangeRequest {
		origin_identity_key: *IDENTITY_KEYPAIR.public_key().as_bytes(),
		origin_public_key: *public_key.as_bytes(),
		target_identity_key: target_client,
	};

	let signature = IDENTITY_KEYPAIR
		.sign(&to_bytes::<Error>(&request)?)
		.to_bytes();

	let signed_request = Signed {
		generic: request,
		signature,
	};

	let archived_signed_request = to_bytes::<Error>(&signed_request)?;

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(
			&archived_signed_request,
		)))
		.await?;

	// TODO: Actually get the pub key from the server
	let other_private_key = EphemeralSecret::random();
	let other_public_key = PublicKey::from(&other_private_key);

	Ok(private_key.diffie_hellman(&other_public_key))
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
		println!("File contents: {}", contents);
	} else {
		// // File doesn't exist, create it and write some data
		let mut file = File::create(&filename).await?;
		file.write_all(b"New file created").await?;
		println!("Created new file: {:?}", filename);
	}

	Ok(())
}

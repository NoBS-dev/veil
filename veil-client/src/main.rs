use constcat::concat;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rkyv::{rancor::Error, to_bytes, util::AlignedVec};
use std::{
	collections::HashMap,
	io::{self, Write},
	path::PathBuf,
	sync::Arc,
};

use tokio::{fs::File, io::AsyncWriteExt, net::TcpStream, sync::Mutex};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::*;
// use vodozemac::Ed25519Keypair;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

// TODO: Let user specify ip/port
const IP_AND_PORT: &str = "localhost:3000";
const SOCKET: &str = concat!("ws://", IP_AND_PORT);
const URL: &str = concat!("http://", IP_AND_PORT);
const PROMPT: &str = concat!(SOCKET, " > ");

// It's kinda confusing, but the signing key contains both the public and private keys
static SIGNING_KEY: Lazy<SigningKey> = Lazy::new(|| SigningKey::generate(&mut OsRng));

// Messagable users should store target client identity key, as well as secret
// At first, the secret will be your ephemeral secret,
// but when you get a call back or receive a key exchange request,
// it will be replaced by the diffie hellman derived shared secret
static MESSAGEABLE_USERS: Lazy<Mutex<HashMap<[u8; 32], [u8; 32]>>> =
	Lazy::new(|| Mutex::new(HashMap::new()));

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let (ws_stream, _) = connect_async(SOCKET).await?;
	let (write, read) = ws_stream.split();

	let write = Arc::new(Mutex::new(write));
	let read = Arc::new(Mutex::new(read));

	let pub_key_bytes = SIGNING_KEY.verifying_key().to_bytes();

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
					println!("\n[Notification] Received message: {:?}", data);
				}
				Ok(_) => {
					println!("\n[Notification] Received something of unknown type.");
				}
				Err(e) => {
					println!("\n[Notification] Error: {}", e);
					break;
				}
			}
			print!("{}", PROMPT);
			io::stdout().flush().unwrap();
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

				if MESSAGEABLE_USERS.lock().await.contains_key(&target_client) {
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
							send_key_exchange_request(target_client, write.clone()).await?;
						}
						_ => {
							println!("Can't communicate without exchanging keys. Leaving...");
						}
					}
				}

				// // TODO: Make work
				// if let Ok(shared_secret) =
				// 	send_key_exchange_request(target_client, write.clone()).await
				// {
				// 	messageable_users.insert(target_client, *shared_secret.as_bytes());
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
	write: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
) -> anyhow::Result<()> {
	let private_key = EphemeralSecret::random();
	let public_key = PublicKey::from(&private_key);

	let request = KeyExchangeRequest {
		origin_identity_key: SIGNING_KEY.verifying_key().to_bytes(),
		origin_public_key: public_key.to_bytes(),
		target_identity_key: target_client,
	};

	let request = ProtocolMessage::KeyExchangeRequest(request);

	let signature = sign_key_exchange(&request, SIGNING_KEY.verifying_key().as_bytes())?;

	let signed_request = Signed {
		data: request,
		identity_signature: signature,
	};

	// TODO: Remove when done testing
	if signed_request.verify_sig(&SIGNING_KEY.verifying_key().as_bytes())? {
		println!("Signature verified successfully, yippee!!");
	}

	let archived_signed_request = to_bytes::<Error>(&signed_request)?;

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(
			&archived_signed_request,
		)))
		.await?;

	Ok(())
}

async fn send_key_exchange_response(
	binary_key_exchange_request: Vec<u8>,
	target_client: [u8; 32],
	write: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
) -> anyhow::Result<()> {
	let private_key = EphemeralSecret::random();
	let public_key = PublicKey::from(&private_key);

	let mut aligned: AlignedVec = AlignedVec::new();
	aligned.extend_from_slice(&binary_key_exchange_request);

	match rkyv::access::<ArchivedSigned, rkyv::rancor::Error>(&aligned) {
		Ok(archived_signed) => match archived_signed.data {
			_ => (),
		},
		Err(e) => println!("Error: {:?}", e),
	}

	let request = KeyExchangeRequest {
		origin_identity_key: SIGNING_KEY.verifying_key().to_bytes(),
		origin_public_key: public_key.to_bytes(),
		target_identity_key: target_client,
	};

	let request = ProtocolMessage::KeyExchangeRequest(request);

	let signature = sign_key_exchange(&request, SIGNING_KEY.verifying_key().as_bytes())?;

	let signed_request = Signed {
		data: request,
		identity_signature: signature,
	};

	// TODO: Remove when done testing
	if signed_request.verify_sig(&SIGNING_KEY.verifying_key().as_bytes())? {
		println!("Signature verified successfully, yippee!!");
	}

	let archived_signed_request = to_bytes::<Error>(&signed_request)?;

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(
			&archived_signed_request,
		)))
		.await?;

	Ok(())
}

async fn send_message(
	target_client: [u8; 32],
	write: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
) -> anyhow::Result<()> {
	// Need to finish key exchange responses first
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

// Uses the signing key to sign the request + the pub key, returns the signature within the result
fn sign_key_exchange(
	request: &ProtocolMessage,
	identity_pub_key: &[u8; 32],
) -> anyhow::Result<[u8; 64]> {
	let mut data = to_bytes::<Error>(request)?;
	data.extend_from_slice(identity_pub_key);
	Ok(SIGNING_KEY.sign(&data).to_bytes())
}

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

const IP_AND_PORT: &str = "localhost:3000";
const SOCKET: &str = concat!("ws://", IP_AND_PORT);
const URL: &str = concat!("http://", IP_AND_PORT);
const PROMPT: &str = concat!(SOCKET, " > ");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
					println!("\n[Notification] Received binary message: {data:?}");
					print!("{PROMPT}");
					io::stdout().flush().unwrap();
				}
				Ok(_) => {}
				Err(e) => {
					println!("\n[Notification] Error: {e}");
					break;
				}
			}
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
				println!("{:?}", list_clients(URL).await?);
			}
			"quit" => {
				println!("Quitting...");
				std::process::exit(0);
			}
			"msg" => {
				println!("{:?}", list_clients(URL).await?);

				print!(
					"Enter client to message\n(you are {}): ",
					display_key(&pub_key_bytes)
				);
				io::stdout().flush()?;

				let mut recipient = String::new();
				io::stdin().read_line(&mut recipient)?;
				let recipient = recipient.trim();

				// TODO encryption and zstd compression, then send message
			}
			_ => (), // Do nothing
		}
	}
	// Ok(())
}

async fn list_clients(url: &str) -> anyhow::Result<Vec<String>> {
	Ok(reqwest::get(format!("{url}/clients"))
		.await?
		.text()
		.await?
		.lines()
		.map(|line| line.trim().to_string())
		.collect())
}

async fn send_key_exchange_request(recipient: &str) {}

async fn open_or_save_to_file(filename: PathBuf) -> anyhow::Result<()> {
	// TODO: Actually account for encryption and serialization
	if filename.exists() {
		// File exists, open and read it
		let contents = tokio::fs::read_to_string(&filename).await?;
		println!("File contents: {contents}");
	} else {
		// File doesn't exist, create it and write some data
		let mut file = File::create(&filename).await?;
		file.write_all(b"New file created").await?;
		println!("Created new file: {filename:?}");
	}

	Ok(())
}

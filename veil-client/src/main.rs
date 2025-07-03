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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let ip_and_port = "localhost:3000";
	let socket = format!("ws://{}", ip_and_port);
	let url = format!("http://{}", ip_and_port);
	let prompt = format!("{} > ", &socket);

	let (ws_stream, _) = connect_async(&socket).await?;
	let (mut write, mut read) = ws_stream.split();

	let identity_key_pair = Ed25519Keypair::new();
	let pub_key_bytes = *identity_key_pair.public_key().as_bytes();

	write
		.send(Message::Binary(Bytes::copy_from_slice(&pub_key_bytes)))
		.await?;

	println!("My public key: {}", display_key(&pub_key_bytes));

	// Clone the prompt for the spawned task, arc is prob overkill for just a string
	let prompt_clone = prompt.clone();

	// Spawn a task to listen for incoming notifs
	tokio::spawn(async move {
		while let Some(msg) = read.next().await {
			match msg {
				Ok(Message::Binary(data)) => {
					println!("\n[Notification] Received binary message: {:?}", data);
					print!("{}", prompt_clone);
					io::stdout().flush().unwrap();
				}
				Ok(Message::Text(text)) => {
					println!("\n[Notification] Received text: {}", text);
					print!("{}", prompt_clone);
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
		print!("{}", &prompt);
		io::stdout().flush()?;
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;

		// Cmds (pre-conversation)
		match input.to_lowercase().trim() {
			"list" => {
				println!("{:?}", list_clients(&url).await?);
			}
			"quit" => {
				println!("Quitting...");
				std::process::exit(0);
			}
			"msg" => {
				println!("{:?}", list_clients(&url).await?);

				print!(
					"Enter client to message\n(you are {}): ",
					display_key(&pub_key_bytes)
				);
				io::stdout().flush()?;

				let mut recipient = String::new();
				io::stdin().read_line(&mut recipient)?;
				let recipient = recipient.trim();

				let clients = list_clients(&url).await?;

				if clients.contains(&recipient.to_string()) {
					println!("Recipient: {}", recipient);

					// TODO: Check profile to see if they have their key. If not, send key exchange req
				} else {
					println!("Invalid recipient: {}", recipient);
				}
			}
			_ => (), // Do nothing
		}
	}
	// Ok(())
}

async fn list_clients(url: &String) -> anyhow::Result<Vec<String>> {
	let response = reqwest::get(format!("{}/clients", url))
		.await?
		.text()
		.await?;
	let clients: Vec<String> = response
		.lines()
		.map(|line| line.trim().to_string())
		.collect();
	Ok(clients)
}

async fn send_key_exchange_request(recipient: &String) {}

async fn _open_or_save_to_file(filename: PathBuf) -> anyhow::Result<()> {
	// TODO: Actually account for encryption and serialization
	if filename.exists() {
		// File exists, open and read it
		let contents = tokio::fs::read_to_string(&filename).await?;
		println!("File contents: {}", contents);
	} else {
		// File doesn't exist, create it and write some data
		let mut file = File::create(&filename).await?;
		file.write_all(b"New file created").await?;
		println!("Created new file: {:?}", filename);
	}

	Ok(())
}

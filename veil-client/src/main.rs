mod listener;
mod messaging;
mod persistence;
mod types;

use crate::{
	listener::start_listener,
	persistence::{load_state_from_keyring, save_state_to_keyring},
};
use constcat::concat;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use messaging::{build_message, fetch_encryption_key_and_otk};
use std::{
	io::{self, Write},
	sync::Arc,
};
use tokio::sync::Mutex;
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{PeerSession, ProtocolMessage, Signed, UploadKeys, display_key, parse_hex_key};
use vodozemac::{
	Curve25519PublicKey,
	olm::{Account, Session, SessionConfig},
};

// TODO: Let user specify ip/port
pub const IP_AND_PORT: &str = "localhost:3000";
pub const SOCKET: &str = concat!("ws://", IP_AND_PORT);
pub const URL: &str = concat!("http://", IP_AND_PORT);
pub const PROMPT: &str = concat!(SOCKET, " > ");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	// Try to load from keyring; fall back to fresh account + empty map.
	let (acc, msgable_users): (Arc<Mutex<Account>>, Arc<DashMap<[u8; 32], PeerSession>>) =
		// Messagable users should store target client identity key, as well as secret
		// At first, the secret will be your ephemeral secret,
		// but when you get a call back or receive a key exchange request,
		// it will be replaced by the diffie hellman derived shared secret
		match load_state_from_keyring() {
			Ok(state) => {
				let acc = Account::from_pickle(state.account);
				let map = Arc::new(DashMap::new());
				for p in state.peers {
					let session = Session::from_pickle(p.session);
					map.insert(
						p.identity_key,
						PeerSession {
							x25519: p.x25519,
							session,
						},
					);
				}

				eprintln!("Prior state found. Loading...");

				(Arc::new(Mutex::new(acc)), map)
			}
			Err(e) => {
				eprintln!(
					"[state] No prior state in keyring (or failed to load): {e:#}. Generating a new profile..."
				);
				(
					Arc::new(Mutex::new(Account::new())),
					Arc::new(DashMap::new()),
				)
			}
		};

	let (ws_stream, _) = tokio_tungstenite::connect_async(SOCKET).await?;
	let (write, read) = ws_stream.split();
	let write = Arc::new(Mutex::new(write));

	let mut acc_guard = acc.lock().await;
	let pub_key_bytes = *acc_guard.ed25519_key().as_bytes();

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(&pub_key_bytes)))
		.await?;

	println!("My public key: {}", display_key(&pub_key_bytes));

	// We're just generating 20 for now, should increase later in prod
	// Also should add functionality to make
	const OTK_NUM: usize = 20;
	acc_guard.generate_one_time_keys(OTK_NUM);

	let otks = acc_guard
		.one_time_keys()
		.values()
		.map(|key| *key.as_bytes())
		.collect();

	let key_upload_request = ProtocolMessage::UploadKeys(UploadKeys {
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

	save_state_to_keyring(&acc, &msgable_users).await?;

	start_listener(
		read,
		pub_key_bytes.clone(),
		acc.clone(),
		msgable_users.clone(),
	)
	.await;

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
				for entry in msgable_users.iter() {
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

				if msgable_users.contains_key(&target_client) {
					// TODO: Start messaging
				} else if let Ok((encryption_key, otk)) =
					fetch_encryption_key_and_otk(&target_client, URL).await
				{
					let acc_guard = acc.lock().await;
					let session = {
						acc_guard.create_outbound_session(
							SessionConfig::version_2(),
							Curve25519PublicKey::from(encryption_key),
							Curve25519PublicKey::from(otk),
						)
					};

					msgable_users.insert(
						target_client,
						PeerSession {
							x25519: encryption_key,
							session,
						},
					);

					let msg = build_message(
						acc_guard.curve25519_key().to_bytes(),
						target_client,
						&msgable_users,
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

				if let Err(e) = save_state_to_keyring(&acc, &msgable_users).await {
					eprintln!("Save state failed: {e:?}");
				} else {
					eprintln!("Saved!");
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

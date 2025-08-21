mod cli;
mod listener;
mod messaging;
mod persistence;
mod types;

use crate::{
	cli::cli,
	listener::start_listener,
	persistence::{load_state_from_keyring, save_state_to_keyring},
};
use futures_util::{SinkExt, StreamExt};
use std::{
	collections::HashMap,
	io::{self, Write},
	sync::Arc,
};
use tokio::sync::{Mutex, RwLock};
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{PeerSession, ProtocolMessage, Signed, UploadKeys, display_key, parse_hex_key};
use vodozemac::olm::{Account, Session};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	print!("Enter profile name (none for default): ");
	io::stdout().flush()?;

	// Sanitization mebe? I suppose it might not matter because this never leaves the client
	let mut profile = String::new();
	io::stdin().read_line(&mut profile)?;

	if profile == "" {
		profile = "default".to_string();
	};
	let profile = profile.trim().to_string();

	// Try to load from keyring; fall back to fresh account + empty map.
	let (acc, peers, ip_and_port): (Arc<Mutex<Account>>, Arc<RwLock<HashMap<[u8; 32], PeerSession>>>, String) =
		// Messagable users should store target client identity key, as well as secret
		// At first, the secret will be your ephemeral secret,
		// but when you get a call back or receive a key exchange request,
		// it will be replaced by the diffie hellman derived shared secret
		match load_state_from_keyring(&profile) {
			Ok(state) => {
				let acc = Account::from_pickle(state.account);
				let mut map = HashMap::new();
				for peer in state.peers {
					let session = Session::from_pickle(peer.session);
					map.insert(
						peer.identity_key,
						PeerSession {
							x25519: peer.x25519,
							session,
						},
					);
				}

				eprintln!("Prior state found. Loading...");

				(Arc::new(Mutex::new(acc)), Arc::new(RwLock::new(map)), state.ip_and_port)
			}
			Err(e) => {
				eprintln!(
					"No prior state found in keyring: {e:#}. Generating a new profile..."
				);

				print!("Enter server (IP:PORT): ");
				io::stdout().flush()?;

				let mut ip_and_port = String::new();
				io::stdin().read_line(&mut ip_and_port)?;

				(
					Arc::new(Mutex::new(Account::new())),
					Arc::new(RwLock::new(HashMap::new())),
					ip_and_port.trim().to_string(),
				)


			}
		};

	let socket = format!("ws://{}", &ip_and_port);
	let url = format!("http://{}", &ip_and_port);
	let prompt = format!("{} > ", &socket);

	let (ws_stream, _) = tokio_tungstenite::connect_async(socket).await?;
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
	// TODO: Ask server first. If we have over 50% of this OTK number on the server, we should just leave it be, but listen for server requests for more keys.
	const OTK_NUM: usize = 20;
	acc_guard.generate_one_time_keys(OTK_NUM);

	let otks: Vec<[u8; 32]> = acc_guard
		.one_time_keys()
		.values()
		.map(|key| *key.as_bytes())
		.collect();

	// println!("Publishing {} OTKs:", otks.len());
	// for &otk in &otks {
	// 	println!("{}", Curve25519PublicKey::from(otk).to_base64())
	// }

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

	save_state_to_keyring(&acc, &peers, &ip_and_port, &profile).await?;

	start_listener(
		read,
		pub_key_bytes.clone(),
		acc.clone(),
		peers.clone(),
		&ip_and_port,
		&profile,
	)
	.await;

	cli(&prompt, acc, &url, &peers, write, &ip_and_port, &profile).await?;

	Ok(())
}

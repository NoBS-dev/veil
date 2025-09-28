mod cli;
mod listener;
mod messaging;
mod state;

use crate::{cli::cli, state::State};
use futures_util::{
	SinkExt, StreamExt,
	stream::{SplitSink, SplitStream},
};
use std::{
	io::{self, Write},
	sync::Arc,
};
use tokio::{net::TcpStream, sync::Mutex};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{ProtocolMessage, Signed, UploadKeys, display_key, parse_hex_key};

pub type ReadStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;
pub type WriteStream = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	print!("Enter profile name (none for default): ");
	io::stdout().flush()?;

	// Sanitization mebe? I suppose it might not matter because this never leaves the client
	let mut profile = String::new();
	io::stdin().read_line(&mut profile)?;

	let profile: &str = state::normalized_profile(&profile);

	let mut state =
		// Messagable users should store target client identity key, as well as secret
		// At first, the secret will be your ephemeral secret,
		// but when you get a call back or receive a key exchange request,
		// it will be replaced by the diffie hellman derived shared secret
		match State::load_from_keyring(profile) {
			Ok(state) => {
				println!("Prior state found. Loading...");
				state
			}
			Err(e) => {
				eprintln!(
					"No prior state found in keyring: {e:#}. Generating a new profile..."
				);

				print!("Enter server (IP:PORT): ");
				io::stdout().flush()?;

				let mut ip_and_port = String::new();
				io::stdin().read_line(&mut ip_and_port)?;

				State::new(ip_and_port.trim(), profile)?
			}
		};

	let socket = format!("ws://{}", state.ip_and_port);
	let url = format!("http://{}", state.ip_and_port);
	let prompt = format!("{} > ", &socket);

	let (mut write, read) = tokio_tungstenite::connect_async(socket).await?.0.split();

	let pub_key_bytes = *state.account.ed25519_key().as_bytes();

	write
		.send(Message::Binary(Bytes::copy_from_slice(&pub_key_bytes)))
		.await?;

	println!("My public key: {}", display_key(&pub_key_bytes));

	// We're just generating 20 for now, should increase later in prod
	// TODO: Ask server first. If we have over 50% of this OTK number on the server, we should just leave it be, but listen for server requests for more keys.
	const OTK_NUM: usize = 20;
	let key_upload_request = generate_key_upload_request(OTK_NUM, &mut state);

	write
		.send(Message::Binary(Bytes::copy_from_slice(
			&Signed::new_archived(key_upload_request, &state.account)?,
		)))
		.await?;

	state.account.mark_keys_as_published();
	state.save_to_keyring()?;

	let state = Arc::new(Mutex::new(state));
	tokio::spawn(listener::listener(read, state.clone()));
	cli(&prompt, &url, write, state).await?;

	Ok(())
}

fn generate_key_upload_request(num_to_gen: usize, state: &mut State) -> ProtocolMessage {
	state.account.generate_one_time_keys(num_to_gen);

	let otks = state
		.account
		.one_time_keys()
		.values()
		.map(|key| *key.as_bytes())
		.collect();

	state.account.generate_fallback_key();
	let (_, fallback_key) = state.account.fallback_key().into_iter().next().unwrap();

	ProtocolMessage::UploadKeys(UploadKeys {
		encryption_key: state.account.curve25519_key().to_bytes(),
		one_time_keys: otks,
		fallback_key: fallback_key.to_bytes(),
	})
}

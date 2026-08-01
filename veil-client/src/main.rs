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
use veil_protocol::{
	Authenticate, Envelope, ProtocolMessage, UploadKeys, display_key, open_envelope,
};

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

				print!("Enter server (IP:PORT, or wss://IP:PORT for TLS): ");
				io::stdout().flush()?;

				let mut ip_and_port = String::new();
				io::stdin().read_line(&mut ip_and_port)?;

				State::new(ip_and_port.trim(), profile)?
			}
		};

	let (ws_scheme, http_scheme) = state.schemes();
	let socket = format!("{ws_scheme}://{}", state.ip_and_port);
	let url = format!("{http_scheme}://{}", state.ip_and_port);
	let prompt = format!("{} > ", &socket);

	if !state.use_tls {
		eprintln!(
			"WARNING: connecting without TLS. Messages stay end-to-end encrypted, but\n\
			 your identity key and who you talk to are readable on the wire."
		);
	}

	let (mut write, mut read) = tokio_tungstenite::connect_async(socket).await?.0.split();

	println!("My address: {}", state.address());
	println!(
		"  user   {}\n  device {}\n  key    {}",
		state.user_id,
		state.device_id,
		display_key(state.account.ed25519_key().as_bytes())
	);

	let server_identity = handshake(&mut write, &mut read, &mut state).await?;

	// We're just generating 20 for now, should increase later in prod
	// TODO: Ask server first. If we have over 50% of this OTK number on the server, we should just leave it be, but listen for server requests for more keys.
	const OTK_NUM: usize = 20;
	let key_upload_request = generate_key_upload_request(OTK_NUM, &mut state);

	write
		.send(Message::Binary(Bytes::copy_from_slice(&Envelope::seal(
			&key_upload_request,
			&state.account,
		)?)))
		.await?;

	state.account.mark_keys_as_published();
	state.save_to_keyring()?;

	let state = Arc::new(Mutex::new(state));
	tokio::spawn(listener::listener(read, state.clone(), server_identity));
	cli(&prompt, &url, write, state).await?;

	Ok(())
}

/// Answers the server's challenge, proving we hold the private half of the
/// identity we're about to be routed under, and pins the key the server signs
/// with so a substituted server is caught on the next connect.
async fn handshake(
	write: &mut WriteStream,
	read: &mut ReadStream,
	state: &mut State,
) -> anyhow::Result<[u8; 32]> {
	let Some(Ok(Message::Binary(bytes))) = read.next().await else {
		anyhow::bail!("server closed the connection before sending a challenge");
	};

	let opened = open_envelope(&bytes)?;
	let challenge = match opened.message {
		ProtocolMessage::Challenge(challenge) => challenge,
		other => anyhow::bail!("expected a challenge from the server, got {other:?}"),
	};

	match state.server_identity {
		Some(pinned) if pinned != opened.sender => anyhow::bail!(
			"server identity changed: pinned {}, but it now signs as {}. Refusing to \
			 continue — either the server was rebuilt or something is impersonating it.",
			display_key(&pinned),
			display_key(&opened.sender)
		),
		Some(_) => {}
		None => {
			println!("Pinning server identity {}", display_key(&opened.sender));
			state.server_identity = Some(opened.sender);
		}
	}

	write
		.send(Message::Binary(Bytes::copy_from_slice(&Envelope::seal(
			// The envelope proves this device holds its signing key; the binding
			// proves the device belongs to this user (§5.1-5.3). Both are needed
			// — a master key is public, so quoting one proves nothing.
			&ProtocolMessage::Authenticate(Authenticate {
				challenge,
				user: state.user_id,
				device: state.device_id,
				master_key: state.master_public_key(),
				binding: state.device_binding(),
			}),
			&state.account,
		)?)))
		.await?;

	Ok(opened.sender)
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

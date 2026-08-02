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
	Authenticate, Envelope, ProtocolMessage, ReplayGuard, UploadKeys, display_key, open_envelope,
	version::VersionRange,
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

				print!("Enter relay to tunnel through (blank for a direct connection): ");
				io::stdout().flush()?;
				let mut relay = String::new();
				io::stdin().read_line(&mut relay)?;

				let mut state = State::new(ip_and_port.trim(), profile)?;
				if !relay.trim().is_empty() {
					state.relay = Some(relay.trim().into());
				}
				state
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

	let (mut write, mut read) = match state.relay.as_deref() {
		None => {
			eprintln!(
				"Connecting directly — {} will see this machine's IP. Set a relay to avoid that.",
				state.ip_and_port
			);
			tokio_tungstenite::connect_async(socket).await?.0.split()
		}
		Some(relay) => open_relayed(relay, &state).await?,
	};

	println!("My address: {}", state.address());
	println!(
		"  user   {}\n  device {}\n  key    {}",
		state.user_id,
		state.device_id,
		display_key(state.account.ed25519_key().as_bytes())
	);

	let (server_identity, version) = handshake(&mut write, &mut read, &mut state).await?;
	println!("Speaking protocol v{version} with the server.");

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

/// Connects through a home server, which forwards to the destination without
/// reading what passes (§3.2).
///
/// Two handshakes happen, and they are separate on purpose: one with the relay,
/// because it is a service we hold an account with and its limits are per user;
/// and one with the destination *through* the tunnel, which is the session that
/// actually matters. The destination only ever sees the relay's address.
async fn open_relayed(relay: &str, state: &State) -> anyhow::Result<(WriteStream, ReadStream)> {
	let (scheme, _) = state.schemes();
	let (mut write, mut read) =
		tokio_tungstenite::connect_async(format!("{scheme}://{relay}/relay"))
			.await?
			.0
			.split();

	// The relay authenticates us like any other connection.
	relay_handshake(&mut write, &mut read, state).await?;

	write
		.send(Message::Text(state.ip_and_port.to_string().into()))
		.await?;

	println!("Tunnelling to {} via {relay}.", state.ip_and_port);
	Ok((write, read))
}

/// The relay's own challenge/response. Deliberately does not pin the relay's
/// identity the way the destination handshake does: the relay is transport, and
/// the session that carries anything sensitive is the one negotiated through it.
async fn relay_handshake(
	write: &mut WriteStream,
	read: &mut ReadStream,
	state: &State,
) -> anyhow::Result<()> {
	let Some(Ok(Message::Binary(bytes))) = read.next().await else {
		anyhow::bail!("relay closed the connection before challenging us");
	};

	let opened = open_envelope(&bytes)?;
	let challenge = match opened.message {
		ProtocolMessage::Challenge(challenge) => challenge,
		other => anyhow::bail!("expected a challenge from the relay, got {other:?}"),
	};

	let ours = VersionRange::supported();
	ours.agree(&challenge.versions)?;

	write
		.send(Message::Binary(Bytes::copy_from_slice(&Envelope::seal(
			&ProtocolMessage::Authenticate(Box::new(Authenticate {
				challenge: challenge.challenge,
				versions: ours,
				server_versions_seen: challenge.versions,
				user: state.user_id,
				device: state.device_id,
				keys: state.cross_signing_public(),
				binding: state.device_binding(),
			})),
			&state.account,
		)?)))
		.await?;

	Ok(())
}

/// Answers the server's challenge, proving we hold the private half of the
/// identity we're about to be routed under, and pins the key the server signs
/// with so a substituted server is caught on the next connect.
async fn handshake(
	write: &mut WriteStream,
	read: &mut ReadStream,
	state: &mut State,
) -> anyhow::Result<([u8; 32], u16)> {
	let Some(Ok(Message::Binary(bytes))) = read.next().await else {
		anyhow::bail!("server closed the connection before sending a challenge");
	};

	let opened = open_envelope(&bytes)?;

	// A replayed challenge is a downgrade vector: an old envelope is genuinely
	// signed, so only its freshness rules out an attacker replaying one that
	// advertises a weaker version range (§3.6).
	ReplayGuard::default().check(opened.timestamp_ms, opened.nonce)?;

	let challenge = match opened.message {
		ProtocolMessage::Challenge(challenge) => challenge,
		other => anyhow::bail!("expected a challenge from the server, got {other:?}"),
	};

	let ours = VersionRange::supported();
	let agreed = ours.agree(&challenge.versions)?;

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
			// The envelope proves this device holds its signing key; the keys
			// and binding prove the device belongs to this user (§5.4). Both are
			// needed — a master key is public, so quoting one proves nothing.
			&ProtocolMessage::Authenticate(Box::new(Authenticate {
				challenge: challenge.challenge,
				versions: ours,
				server_versions_seen: challenge.versions,
				user: state.user_id,
				device: state.device_id,
				keys: state.cross_signing_public(),
				binding: state.device_binding(),
			})),
			&state.account,
		)?)))
		.await?;

	Ok((opened.sender, agreed))
}

/// A hint for peers picking between a user's devices. Cosmetic — never a
/// security boundary, since the server can lie about it.
fn whoami_device_name() -> String {
	std::env::var("HOSTNAME")
		.or_else(|_| std::env::var("HOST"))
		.unwrap_or_else(|_| "device".to_owned())
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
		display_name: whoami_device_name(),
	})
}

mod cli;
mod communities;
mod listener;
mod messaging;
mod state;
mod tunnel;

use crate::{cli::cli, state::State};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use std::{
	io::{self, Write},
	pin::Pin,
	sync::Arc,
};
use tokio::sync::Mutex;
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{
	Authenticate, Envelope, ProtocolMessage, ReplayGuard, UploadKeys, display_key, open_envelope,
	version::VersionRange,
};

/// The two halves of a connection, whatever it is carried over.
///
/// Boxed because there are now two shapes: a direct WebSocket, and one running
/// inside a TLS session inside a relay tunnel (§3.2). The rest of the client
/// does not care which it has, and should not — that is the point of the relay
/// being transparent.
pub type ReadStream = Pin<Box<dyn Stream<Item = Result<Message, tungstenite::Error>> + Send>>;
pub type WriteStream = Pin<Box<dyn Sink<Message, Error = tungstenite::Error> + Send>>;

fn split_boxed<S>(socket: S) -> (WriteStream, ReadStream)
where
	S: Sink<Message, Error = tungstenite::Error>
		+ Stream<Item = Result<Message, tungstenite::Error>>
		+ Send
		+ 'static,
{
	let (write, read) = socket.split();
	(Box::pin(write), Box::pin(read))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	// Must happen before any TLS: rustls refuses to guess when more than one
	// provider could apply, and the failure is a panic deep inside a handshake.
	let _ = rustls::crypto::ring::default_provider().install_default();

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

	let connection = match state.relay.as_deref() {
		None => {
			eprintln!(
				"Connecting directly — {} will see this machine's IP. Set a relay to avoid that.",
				state.ip_and_port
			);
			let tcp = tokio::net::TcpStream::connect(state.ip_and_port.as_ref()).await?;

			if state.use_tls {
				let (tls, negotiated) = tunnel::tls_direct(tcp, &state.ip_and_port).await?;
				let (socket, _) =
					tokio_tungstenite::client_async(format!("ws://{}/", state.ip_and_port), tls)
						.await?;
				(split_boxed(socket), *negotiated.lock().unwrap())
			} else {
				let (socket, _) =
					tokio_tungstenite::client_async(format!("ws://{}/", state.ip_and_port), tcp)
						.await?;
				(split_boxed(socket), None)
			}
		}
		Some(relay) => open_relayed(relay, &state).await?,
	};
	let ((mut write, mut read), tls_binding) = connection;

	println!("My address: {}", state.address());
	println!(
		"  user   {}\n  device {}\n  key    {}",
		state.user_id,
		state.device_id,
		display_key(state.account.ed25519_key().as_bytes())
	);

	let (server_identity, version) =
		handshake(&mut write, &mut read, &mut state, tls_binding).await?;
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

	// Refresh every community we know about before anything can be sent to one.
	// Readership comes from the policy chain (§8.5), so a chain that has not
	// caught up means encrypting to whoever it still lists — including someone a
	// controller removed while this device was away.
	let pending_refreshes = state.known_communities.len() as u64;
	for id in state.known_communities.keys().copied().collect::<Vec<_>>() {
		let framed = Envelope::seal(&ProtocolMessage::FetchCommunity(id), &state.account)?;
		write
			.send(Message::Binary(Bytes::copy_from_slice(&framed)))
			.await?;
	}

	let state = Arc::new(Mutex::new(state));
	// Shared so the listener can acknowledge mail without waiting on the CLI.
	let write = Arc::new(Mutex::new(write));
	tokio::spawn(listener::listener(
		read,
		write.clone(),
		state.clone(),
		server_identity,
	));
	// Wait for those refreshes before accepting a command. Sending to a Sealed
	// channel derives readership from the chain, so entering the prompt first
	// meant the first `say` of a session could encrypt against whatever was on
	// disk — including a reader a controller had removed in the meantime.
	//
	// Bounded, and proceeding anyway on timeout: a host that never answers must
	// not make the client unusable, and a stale chain still cannot admit a
	// reader nobody signed for.
	if pending_refreshes > 0 {
		let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
		loop {
			if state.lock().await.applied_states >= pending_refreshes {
				break;
			}
			if std::time::Instant::now() >= deadline {
				eprintln!(
					"warning: this host has not answered for {} community/ies. Policy may be \
					 out of date, so a Sealed send could reach a reader who has since been \
					 removed.",
					pending_refreshes - state.lock().await.applied_states
				);
				break;
			}
			tokio::time::sleep(std::time::Duration::from_millis(100)).await;
		}
	}

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
type Connection = ((WriteStream, ReadStream), Option<[u8; 32]>);

async fn open_relayed(relay: &str, state: &State) -> anyhow::Result<Connection> {
	let (scheme, _) = state.schemes();

	// The relay's own transport is independent of the destination's. Deriving
	// one from the other — which is what this did — tried to speak TLS to a
	// plaintext relay whenever the destination happened to use TLS. Two
	// different hosts, two different operators, two separate decisions.
	let relay_url = if relay.starts_with("ws://") || relay.starts_with("wss://") {
		format!("{relay}/relay")
	} else {
		format!("ws://{relay}/relay")
	};

	let socket = tokio_tungstenite::connect_async(relay_url).await?.0;
	let (mut write, mut read) = socket.split();

	// The relay authenticates us like any other connection.
	relay_handshake(&mut write, &mut read, state).await?;

	// With its scheme: the relay has to reach the destination itself to prove it
	// speaks Veil, and cannot guess whether that means TLS.
	write
		.send(Message::Text(
			format!("{scheme}://{}", state.ip_and_port).into(),
		))
		.await?;
	write.flush().await?;

	// From here the relay carries bytes it cannot read (§3.2). Everything above
	// was addressed to the relay; everything below is addressed through it.
	let tunnel = tunnel::TunnelStream::new(write.reunite(read)?);
	let (tls, negotiated) = tunnel::tls_over_tunnel(tunnel, &state.ip_and_port).await?;

	let (socket, _) =
		tokio_tungstenite::client_async(format!("ws://{}/", state.ip_and_port), tls).await?;

	let binding = *negotiated.lock().unwrap();
	println!(
		"Tunnelling to {} via {relay}, end-to-end encrypted.",
		state.ip_and_port
	);
	Ok((split_boxed(socket), binding))
}

/// The relay's own challenge/response. Deliberately does not pin the relay's
/// identity the way the destination handshake does: the relay is transport, and
/// the session that carries anything sensitive is the one negotiated through it.
/// Generic over the socket halves rather than taking [`WriteStream`], because
/// this runs *before* the tunnel exists — the relay's own connection is a plain
/// WebSocket, and the two halves have to be rejoined afterwards to carry TLS.
async fn relay_handshake<W, R>(write: &mut W, read: &mut R, state: &State) -> anyhow::Result<()>
where
	W: Sink<Message, Error = tungstenite::Error> + Unpin,
	R: Stream<Item = Result<Message, tungstenite::Error>> + Unpin,
{
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
	tls_binding: Option<[u8; 32]>,
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

	// Through a relay, this is the check that makes the tunnel private: the
	// certificate we negotiated must be the one this server signed for. A relay
	// terminating the session in the middle has to present its own, and cannot
	// make the server's identity key vouch for it (§3.2).
	if let Some(negotiated) = tls_binding {
		tunnel::check_binding(Some(negotiated), &challenge.tls_binding)?;
	}
	// A server that serves TLS but signs no binding cannot be told apart from
	// one being impersonated, so this is refused rather than warned about.
	if state.use_tls && tls_binding.is_none() {
		anyhow::bail!("expected a TLS session but none was negotiated");
	}

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

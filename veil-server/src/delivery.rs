//! Server-to-server DM delivery — `DESIGN.md` §3.3–3.4.
//!
//! The **only** traffic that crosses a server boundary. Communities never
//! replicate (§3.3), and the moment this starts carrying community state,
//! Matrix's state resolution comes back and the architecture's main advantage
//! is gone. Adding a message type here should be treated as an architectural
//! change, not a feature.
//!
//! What actually crosses is one-way delivery of an immutable opaque blob into a
//! mailbox — closer to SMTP relaying than to federation. There is no shared
//! state, so there is nothing to converge and no conflicts to resolve.
//!
//! The path is Alice's client -> Alice's home server -> Bob's home server ->
//! Bob's mailbox. Alice's client never connects to Bob's server, which is what
//! keeps deposits rate-limitable: they arrive from a server with standing rather
//! than from any client that cares to open a socket (§3.4).

use crate::{ServerState, SharedStore};
use anyhow::{Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use veil_protocol::{
	Deposit, DepositResult, Envelope, ProtocolMessage, ServerAuthenticate, open_envelope,
	version::VersionRange,
};

/// How long a peer has to answer each step of the exchange.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest envelope accepted in a deposit. Bounds what a peer can make us hold
/// in memory before anything has been verified.
const MAX_DEPOSIT: usize = 1 << 20;
/// Entries drained per pass of the retry loop.
const RETRY_BATCH: usize = 32;
/// Attempts before an entry is abandoned.
///
/// Mail is not kept forever: a server that has been unreachable for days is
/// probably gone, and an unbounded queue is a disk-exhaustion vector for anyone
/// who can name a host that will never answer.
const MAX_ATTEMPTS: i64 = 12;

// ---- receiving side -------------------------------------------------------

/// Handles an inbound connection from another server.
///
/// Mirrors the client handshake deliberately — same challenge, same signed
/// envelope, same transcript binding — but with no user, device or
/// cross-signing chain, because a server has none of those. Its identity is
/// simply the key that signed the envelope (invariant 1).
pub async fn handle_deposit_socket(socket: axum::extract::ws::WebSocket, state: ServerState) {
	use axum::extract::ws::Message;

	let (mut sender, mut receiver) = socket.split();

	let peer = match authenticate_server(&mut sender, &mut receiver, &state).await {
		Ok(peer) => peer,
		Err(e) => {
			eprintln!("S2S handshake failed: {e:#}");
			return;
		}
	};
	let short = hex_prefix(&peer);
	eprintln!("S2S: server {short} connected");

	while let Some(Ok(Message::Binary(bytes))) = receiver.next().await {
		let result = accept_deposit(&state, &peer, &bytes).await;

		match &result {
			DepositResult::Accepted => {}
			DepositResult::Refused(why) => eprintln!("S2S: refused a deposit from {short}: {why}"),
			DepositResult::TryAgain(why) => eprintln!("S2S: deferring {short}: {why}"),
		}

		let framed = {
			let account = state.server_account.lock().await;
			match Envelope::seal(&ProtocolMessage::DepositResult(result), &account) {
				Ok(framed) => framed,
				Err(e) => {
					eprintln!("S2S: could not seal a result for {short}: {e:#}");
					return;
				}
			}
		};

		if sender
			.send(Message::Binary(framed.to_vec().into()))
			.await
			.is_err()
		{
			return;
		}
	}
}

/// Verifies one deposit and files it.
///
/// Every failure is classified as permanent or temporary, because the sender
/// uses that to decide whether to retry. Getting it backwards either loses mail
/// or loops forever.
async fn accept_deposit(state: &ServerState, peer: &[u8; 32], bytes: &[u8]) -> DepositResult {
	let opened = match open_envelope(bytes) {
		Ok(opened) => opened,
		Err(e) => return DepositResult::Refused(format!("outer envelope did not verify: {e}")),
	};

	// The outer envelope must come from the server that handshook on this
	// connection — the same pinning as a client connection (invariant 5), so a
	// peer cannot forward deposits signed by some other server.
	if &opened.sender != peer {
		return DepositResult::Refused("outer envelope was signed by a different server".into());
	}

	let now = state.clock.read().await.now_ms();

	if let Err(e) = state
		.replay_guard
		.lock()
		.await
		.check_at(now, opened.timestamp_ms, opened.nonce)
	{
		return DepositResult::Refused(format!("replayed deposit: {e}"));
	}

	if !state.deposit_limiter.lock().await.allow(*peer, now) {
		return DepositResult::TryAgain("over the per-server deposit budget".into());
	}

	let ProtocolMessage::Deposit(Deposit { envelope }) = opened.message else {
		return DepositResult::Refused("not a deposit".into());
	};

	if envelope.len() > MAX_DEPOSIT {
		return DepositResult::Refused("deposit is too large".into());
	}

	// The inner envelope is the sender's own, byte for byte. Verifying it here
	// is what makes the forwarding server untrusted for content: it carried
	// these bytes and could not have altered them (invariant 2).
	let inner = match open_envelope(&envelope) {
		Ok(inner) => inner,
		Err(e) => return DepositResult::Refused(format!("inner envelope did not verify: {e}")),
	};

	let ProtocolMessage::EncryptedMessage(msg) = &inner.message else {
		return DepositResult::Refused("inner frame is not a message".into());
	};

	// The signer of the inner envelope must be the device it claims to be from,
	// so a server cannot deposit mail attributed to someone else's user.
	let claimed = match sender_key_of(state, msg).await {
		Ok(key) => key,
		Err(e) => return DepositResult::Refused(format!("unknown sender: {e}")),
	};
	if let Some(expected) = claimed
		&& inner.sender != expected
	{
		return DepositResult::Refused(
			"inner envelope was not signed by the device it names".into(),
		);
	}

	// A deposit is terminal. Accepting one for a user who is not ours and
	// forwarding it onward would make every server an open relay for every
	// other, and two servers each believing the other is home would loop.
	match state.store.lock().await.is_local_user(&msg.recipient.user) {
		Ok(true) => {}
		Ok(false) => {
			return DepositResult::Refused(format!(
				"{} is not a user of this server; deposits are never forwarded on",
				msg.recipient.user
			));
		}
		Err(e) => return DepositResult::TryAgain(format!("could not check the directory: {e}")),
	}

	// Straight into the mailbox rather than to a live connection: the recipient
	// may be here now, but delivery is by acknowledgement (§12.2, invariant 11),
	// and the mailbox is the one path that survives them vanishing mid-flush.
	// The queued frame is the *sender's* envelope, so what Bob eventually opens
	// is what Alice signed.
	// Scoped, not held across the match. A guard taken in a match scrutinee
	// lives for the whole expression, so waking inside an arm — which needs the
	// store again — deadlocked the connection. The same discipline the routing
	// map has: never hold a lock across an await that might want it.
	let queued = {
		let store = state.store.lock().await;
		store.enqueue(&msg.recipient, &envelope, now)
	};

	match queued {
		Ok(()) => {
			eprintln!("S2S: accepted mail for {}", msg.recipient);
			// Mail arriving from another server is still mail, and a device
			// waiting on it should be woken the same way (§12.2).
			crate::wake_for_mail(state, &msg.recipient).await;
			DepositResult::Accepted
		}
		Err(e) => DepositResult::TryAgain(format!("could not queue: {e}")),
	}
}

/// The signing key we have on file for the device a message claims to be from.
///
/// `None` when the sender is not someone we know, which is the ordinary case for
/// an inbound DM — we hold no directory entry for a stranger on another server.
/// That is not a reason to refuse: the recipient verifies the sender against
/// cross-signing themselves (§5.4), and doing it here as well would only mean
/// refusing the first message from anyone we have not met.
async fn sender_key_of(
	state: &ServerState,
	msg: &veil_protocol::EncryptedMessage,
) -> Result<Option<[u8; 32]>> {
	let store = state.store.lock().await;
	let Some((_, devices)) = store.device_list(&msg.sender.user)? else {
		return Ok(None);
	};

	Ok(devices
		.iter()
		.find(|d| d.device_id == msg.sender.device)
		.map(|d| d.ed25519))
}

async fn authenticate_server(
	sender: &mut futures::stream::SplitSink<
		axum::extract::ws::WebSocket,
		axum::extract::ws::Message,
	>,
	receiver: &mut futures::stream::SplitStream<axum::extract::ws::WebSocket>,
	state: &ServerState,
) -> Result<[u8; 32]> {
	use axum::extract::ws::Message;

	let mut challenge = [0u8; 32];
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);

	let ours = VersionRange::supported();
	let framed = {
		let account = state.server_account.lock().await;
		Envelope::seal(
			&ProtocolMessage::Challenge(veil_protocol::Challenge {
				challenge,
				versions: ours,
				tls_binding: state.tls_binding,
			}),
			&account,
		)?
	};
	sender.send(Message::Binary(framed.to_vec().into())).await?;

	let reply = tokio::time::timeout(STEP_TIMEOUT, receiver.next())
		.await
		.map_err(|_| anyhow!("peer did not answer the challenge in time"))?;

	let Some(Ok(Message::Binary(bytes))) = reply else {
		bail!("peer did not answer with a binary frame");
	};

	let opened = open_envelope(&bytes)?;
	let now = state.clock.read().await.now_ms();
	state
		.replay_guard
		.lock()
		.await
		.check_at(now, opened.timestamp_ms, opened.nonce)?;

	let ProtocolMessage::ServerAuthenticate(auth) = opened.message else {
		bail!("peer did not answer with a server authentication");
	};

	if auth.challenge != challenge {
		bail!("peer echoed the wrong challenge");
	}

	// Downgrade defence: an old challenge is genuinely signed, so the signature
	// alone proves nothing about which range the peer was shown (§3.6).
	if auth.server_versions_seen != ours {
		bail!("peer saw a different version range than we advertised");
	}
	ours.agree(&auth.versions)?;

	Ok(opened.sender)
}

// ---- sending side ---------------------------------------------------------

/// Hands one envelope to the server that holds the recipient's mailbox.
///
/// Opens a connection per delivery. That is the honest starting point rather
/// than the efficient one — a busy pair of servers should hold one connection
/// open — but it keeps failure handling to a single path while the retry
/// semantics are what matter.
pub async fn deliver(
	host: &str,
	envelope: &[u8],
	account: &vodozemac::olm::Account,
) -> Result<DepositResult> {
	let url = if host.starts_with("ws://") || host.starts_with("wss://") {
		format!("{host}/s2s")
	} else {
		format!("ws://{host}/s2s")
	};

	let (mut socket, _) =
		tokio::time::timeout(STEP_TIMEOUT, tokio_tungstenite::connect_async(&url))
			.await
			.map_err(|_| anyhow!("{host} did not answer in time"))??;

	// The destination must prove it speaks Veil before anything is sent to it.
	// Same reasoning as the relay's check (invariant 15): without it, a client
	// naming an arbitrary host in `recipient_host` would turn every home server
	// into an open proxy pointed wherever it liked.
	let first = tokio::time::timeout(STEP_TIMEOUT, socket.next())
		.await
		.map_err(|_| anyhow!("{host} sent no opening frame in time"))?;

	let Some(Ok(WsMessage::Binary(bytes))) = first else {
		bail!("{host} did not open with a binary frame");
	};

	let opened = open_envelope(&bytes)
		.map_err(|e| anyhow!("{host}'s opening frame is not a veil envelope: {e}"))?;

	// Pinned for the rest of the exchange, so the answer has to come from the
	// same server that issued the challenge.
	let host_key = opened.sender;

	let ProtocolMessage::Challenge(challenge) = opened.message else {
		bail!("{host} did not open with a challenge");
	};

	let theirs = challenge.versions;
	let ours = VersionRange::supported();
	ours.agree(&theirs)?;

	let auth = Envelope::seal(
		&ProtocolMessage::ServerAuthenticate(ServerAuthenticate {
			challenge: challenge.challenge,
			versions: ours,
			server_versions_seen: theirs,
		}),
		account,
	)?;
	socket.send(WsMessage::Binary(auth.to_vec().into())).await?;

	let deposit = Envelope::seal(
		&ProtocolMessage::Deposit(Deposit {
			envelope: envelope.to_vec(),
		}),
		account,
	)?;
	socket
		.send(WsMessage::Binary(deposit.to_vec().into()))
		.await?;

	let reply = tokio::time::timeout(STEP_TIMEOUT, socket.next())
		.await
		.map_err(|_| anyhow!("{host} did not acknowledge the deposit in time"))?;

	let Some(Ok(WsMessage::Binary(bytes))) = reply else {
		bail!("{host} did not acknowledge the deposit");
	};

	let opened = open_envelope(&bytes)?;
	if opened.sender != host_key {
		bail!("{host} answered with a different key than it handshook with");
	}

	match opened.message {
		// The verdict is returned rather than flattened into an error, because
		// the caller has to tell "refused, stop" from "unreachable, retry" and
		// an error string is the wrong place to carry that.
		ProtocolMessage::DepositResult(result) => Ok(result),
		other => bail!("{host} answered a deposit with {other:?}"),
	}
}

/// Queues an envelope for another server, or delivers it now.
pub async fn send_onward(state: &ServerState, host: &str, envelope: &[u8]) {
	let now = state.clock.read().await.now_ms();

	// Queued first, then attempted. The other order loses mail to a crash
	// between a successful send and the write that records it — and losing mail
	// is the failure this whole path exists to prevent.
	if let Err(e) = state
		.store
		.lock()
		.await
		.enqueue_outbound(host, envelope, now)
	{
		eprintln!("S2S: could not queue mail for {host}: {e:#}");
		return;
	}

	drain(&state.store, &state.server_account, now).await;
}

/// Runs delivery for everything due, in the background.
pub fn spawn_retry_loop(state: ServerState) {
	tokio::spawn(async move {
		loop {
			tokio::time::sleep(Duration::from_secs(5)).await;
			let now = state.clock.read().await.now_ms();
			drain(&state.store, &state.server_account, now).await;
		}
	});
}

async fn drain(
	store: &SharedStore,
	account: &std::sync::Arc<tokio::sync::Mutex<vodozemac::olm::Account>>,
	now: u64,
) {
	let due = match store.lock().await.outbound_due(now, RETRY_BATCH) {
		Ok(due) => due,
		Err(e) => {
			eprintln!("S2S: could not read the outbound queue: {e:#}");
			return;
		}
	};

	for (id, host, frame, attempts) in due {
		// The account lock is held only for the two seals inside `deliver`, but
		// this holds it across the whole exchange. Acceptable because delivery
		// is a background task; if it ever blocks client handshakes, the fix is
		// a second account handle rather than a shorter critical section.
		let result = {
			let account = account.lock().await;
			deliver(&host, &frame, &account).await
		};

		let store = store.lock().await;
		match result {
			Ok(DepositResult::Accepted) => {
				eprintln!("S2S: delivered to {host}");
				let _ = store.drop_outbound(id);
			}
			// The receiving server has decided. Retrying a refusal is a loop
			// that ends only when the queue is capped, so it is dropped here.
			Ok(DepositResult::Refused(why)) => {
				eprintln!("S2S: {host} refused permanently, dropping: {why}");
				let _ = store.drop_outbound(id);
			}
			Ok(DepositResult::TryAgain(why)) if attempts + 1 < MAX_ATTEMPTS => {
				eprintln!("S2S: {host} asked us to wait ({why}); will retry");
				let _ = store.defer_outbound(id, attempts, now);
			}
			Err(e) if attempts + 1 < MAX_ATTEMPTS => {
				eprintln!("S2S: {host} unreachable ({e:#}); will retry");
				let _ = store.defer_outbound(id, attempts, now);
			}
			outcome => {
				eprintln!("S2S: giving up on {host} after {MAX_ATTEMPTS} attempts: {outcome:?}");
				let _ = store.drop_outbound(id);
			}
		}
	}
}

// ---- fetching another server's directory (§3.4) ---------------------------

/// Proves a host speaks Veil, and remembers that it does.
///
/// The same check the relay makes before tunnelling (invariant 15), for the
/// same reason: these endpoints take a hostname from a client, so without it
/// the server is a request forwarder pointed at anything a client names —
/// including addresses only it can reach. A host that cannot produce a signed
/// Veil challenge is refused, which rules out web servers and internal
/// metadata endpoints as a class rather than by blocklist.
async fn verify_speaks_veil(state: &ServerState, host: &str) -> Result<()> {
	if state.verified_hosts.read().await.contains(host) {
		return Ok(());
	}

	let url = if host.starts_with("ws://") || host.starts_with("wss://") {
		host.to_owned()
	} else {
		format!("ws://{host}/")
	};

	let (mut socket, _) =
		tokio::time::timeout(STEP_TIMEOUT, tokio_tungstenite::connect_async(&url))
			.await
			.map_err(|_| anyhow!("{host} did not answer in time"))??;

	let first = tokio::time::timeout(STEP_TIMEOUT, socket.next())
		.await
		.map_err(|_| anyhow!("{host} sent no opening frame in time"))?;

	let Some(Ok(WsMessage::Binary(bytes))) = first else {
		bail!("{host} did not open with a binary frame");
	};

	let opened = open_envelope(&bytes).map_err(|e| anyhow!("{host} is not a veil server: {e}"))?;
	if !matches!(opened.message, ProtocolMessage::Challenge(_)) {
		bail!("{host} did not open with a challenge");
	}

	state.verified_hosts.write().await.insert(host.to_owned());
	Ok(())
}

/// Fetches a path from another server on a client's behalf.
///
/// The client could make this request itself, and an earlier draft had it do
/// so — but then Bob's host learns Alice's IP the moment she looks him up,
/// which is exactly what §3.2 and §3.4 exist to prevent. Routing it through her
/// home server costs nothing in trust: the response is a device list she
/// verifies against Bob's cross-signing keys herself (§5.4), so neither server
/// can lie about it.
pub async fn fetch_remote(state: &ServerState, host: &str, path: &str) -> Result<(u16, String)> {
	verify_speaks_veil(state, host).await?;

	let base = host
		.trim_start_matches("wss://")
		.trim_start_matches("ws://")
		.trim_end_matches('/');

	let response = tokio::time::timeout(STEP_TIMEOUT, reqwest::get(format!("http://{base}{path}")))
		.await
		.map_err(|_| anyhow!("{host} did not answer in time"))??;

	let status = response.status().as_u16();
	Ok((status, response.text().await?))
}

fn hex_prefix(key: &[u8; 32]) -> String {
	key[..4].iter().map(|b| format!("{b:02x}")).collect()
}

use crate::{
	WriteStream,
	state::{PeerSession, State},
};
use anyhow::Result;
use futures_util::SinkExt;
use std::io::{self, Write};
use tungstenite::{Bytes, Message};
use veil_protocol::{
	EncryptedMessage, Envelope, ProtocolMessage,
	crosssign::CrossSigningPublic,
	identity::{Device, DeviceAddress, DeviceId, UserId},
	message::{MessageId, random_nonce},
};
use vodozemac::olm::SessionConfig;

/// Accepts `user/device`, the form `DeviceAddress` renders.
///
/// Addressing a device rather than a user is deliberate: sessions are
/// device-to-device (§5.2). Sending to a *user* means fanning out over their
/// device list, which needs cross-signing (§5.4) before it can be trusted, so
/// for now the target is named explicitly.
/// An address, and optionally the host that holds the recipient's mailbox.
///
/// Written `<user-id>/<device-id>` for someone on our own server, or
/// `<user-id>/<device-id>@host:port` for someone elsewhere (§3.4). The host is
/// **not** part of the identity — identity is self-certifying and carries no
/// hostname (§5.3), which is what makes people portable between home servers.
/// It is a routing hint, and the wrong one costs a failed delivery rather than
/// a misdirected trust decision.
struct Target {
	address: DeviceAddress,
	/// Empty for our own server.
	host: String,
}

fn parse_address(input: &str) -> Result<Target> {
	let input = input.trim();
	let (address, host) = match input.split_once('@') {
		Some((address, host)) => (address, host.trim().to_owned()),
		None => (input, String::new()),
	};

	let (user, device) = address.trim().split_once('/').ok_or_else(|| {
		anyhow::anyhow!("expected an address of the form <user-id>/<device-id>[@host]")
	})?;

	Ok(Target {
		address: DeviceAddress::new(
			UserId::parse(user)?,
			DeviceId::from_bytes(
				data_encoding::BASE32_NOPAD
					.decode(device.trim().to_ascii_uppercase().as_bytes())?
					.as_slice()
					.try_into()
					.map_err(|_| anyhow::anyhow!("device id must be 16 bytes"))?,
			),
		),
		host,
	})
}

/// Where to look a device up.
///
/// For a stranger this goes through **our own** server's `/remote` proxy rather
/// than straight to theirs (§3.4). Their host would otherwise learn our IP the
/// moment we looked them up, which is the leak the relay exists to prevent —
/// and it buys nothing, since what comes back is verified against their
/// cross-signing keys either way.
fn directory_base(url: &str, host: &str) -> String {
	if host.is_empty() {
		url.to_owned()
	} else {
		format!("{url}/remote/{host}")
	}
}

pub async fn send(write: &mut WriteStream, state: &mut State, url: &str) -> Result<()> {
	print!("Enter target device (<user-id>/<device-id>[@host]): ");
	io::stdout().flush()?;

	let Target {
		address: target,
		host: recipient_host,
	} = {
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;
		parse_address(&input)?
	};
	let directory = directory_base(url, &recipient_host);

	if !state.peers.contains_key(&target) {
		// The prekey bundle comes from the host, which is untrusted for identity
		// (§4.3). Taking it at face value would let a malicious host hand over
		// its *own* keys and sit in the middle of the session — so the device is
		// checked against the peer's cross-signing chain first, and the bundle
		// must then match what that chain vouches for.
		let (_, devices) = fetch_device_list(&target.user, &directory).await?;

		let device = devices
			.iter()
			.find(|d| d.device_id == target.device)
			.ok_or_else(|| {
				anyhow::anyhow!(
					"{} is not in {}'s verified device list — the host may be inventing it",
					target.device,
					target.user
				)
			})?;

		let (their_ed25519, their_x25519, otk) = fetch_prekey_bundle(&target, &directory).await?;

		if their_ed25519 != device.ed25519 {
			anyhow::bail!(
				"the host served a signing key for {target} that its own device list does not \
				 vouch for — refusing to open a session"
			);
		}
		if their_x25519 != device.curve25519 {
			anyhow::bail!(
				"the host served an identity key for {target} that its own device list does not \
				 vouch for — refusing to open a session"
			);
		}

		// The device provably belongs to that user. Whether we know *who* that
		// user is remains a separate question (§5.4).
		if !state.is_verified(&target.user) {
			eprintln!(
				"warning: {} is not verified. The device is genuinely theirs, but nothing yet \
				 confirms who they are — run `safety` to compare numbers.",
				target.user
			);
		}

		let session = state.account.create_outbound_session(
			SessionConfig::version_2(),
			their_x25519.into(),
			otk.into(),
		);

		state.peers.insert(
			target,
			PeerSession {
				x25519: their_x25519,
				seen_head: MessageId::ROOT,
				seen_ids: Default::default(),
				sent_ids: Default::default(),
				// Pinned here, and required to match on everything that arrives
				// from this address afterwards.
				ed25519: their_ed25519,
				session,
			},
		);

		if let Err(e) = state.save_to_keyring() {
			eprintln!("Save state failed: {e:?}");
		}
	}

	print!("Enter message: ");
	io::stdout().flush()?;
	let mut message = String::new();
	io::stdin().read_line(&mut message)?;
	let message = message.trim();

	let (msg_type, ciphertext) = {
		let peer = match state.peers.get_mut(&target) {
			Some(peer) => peer,
			None => anyhow::bail!("No session with that device."),
		};

		peer.session.encrypt(message).to_parts()
	};

	if let Err(e) = state.save_to_keyring() {
		eprintln!("Save state failed: {e:?}");
	}

	let signed_bytes = {
		let outgoing = EncryptedMessage {
			sender: state.address(),
			recipient: target,
			sender_x25519: state.account.curve25519_key().to_bytes(),
			recipient_host: recipient_host.clone(),
			nonce: random_nonce(),
			origin_ts: veil_protocol::now_ms()?,
			// Tells the peer where we were in the conversation. They can spot a
			// message they sent that we never acknowledged.
			seen_head: state
				.peers
				.get(&target)
				.map(|p| p.seen_head)
				.unwrap_or(MessageId::ROOT),
			message_type: msg_type,
			message: ciphertext,
		};

		// Remember what we sent, so when the peer echoes it back as their
		// `seen_head` we can tell it is genuinely ours.
		if let Some(peer) = state.peers.get_mut(&target) {
			peer.record_sent(outgoing.id());
		}

		Envelope::seal(&ProtocolMessage::EncryptedMessage(outgoing), &state.account)?
	};

	write
		.send(Message::Binary(Bytes::copy_from_slice(&signed_bytes)))
		.await?;

	Ok(())
}

/// Fetches a device's prekey bundle: signing key, Olm identity key, and a
/// one-time key to open a session with.
pub async fn fetch_prekey_bundle(
	target: &DeviceAddress,
	url: &str,
) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
	let url = format!("{url}/devices/{}/{}/otk", target.user, target.device);

	let body = reqwest::get(url).await?.text().await?;
	let mut lines = body.lines();

	let mut next = |what: &str| -> Result<[u8; 32]> {
		let line = lines
			.next()
			.ok_or_else(|| anyhow::anyhow!("prekey bundle is missing its {what}"))?;
		veil_protocol::parse_hex_key(line.trim())
	};

	let ed25519 = next("signing key")?;
	let x25519 = next("identity key")?;
	let otk = next("one-time key")?;

	Ok((ed25519, x25519, otk))
}

/// Fetches a peer's device list and returns only the entries that verify.
///
/// The host is untrusted for identity (§4.3), so what comes back is a claim
/// until every device chains up to the user id through their cross-signing keys
/// — and the keys themselves are checked against the `UserId`, which is derived
/// from the master key. A hostile host can withhold devices or serve junk; it
/// cannot get a device it controls accepted.
pub async fn fetch_device_list(
	user: &UserId,
	url: &str,
) -> Result<(CrossSigningPublic, Vec<Device>)> {
	#[derive(serde::Deserialize)]
	struct Response {
		keys: CrossSigningPublic,
		devices: Vec<Device>,
	}

	let response: Response = reqwest::get(format!("{url}/users/{user}/devices"))
		.await?
		.error_for_status()?
		.json()
		.await?;

	let verified = response.keys.verify_device_list(user, &response.devices)?;

	if verified.len() != response.devices.len() {
		eprintln!(
			"warning: {} of {}'s advertised devices failed verification and were discarded",
			response.devices.len() - verified.len(),
			user
		);
	}

	Ok((response.keys, verified))
}

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
fn parse_address(input: &str) -> Result<DeviceAddress> {
	let (user, device) = input
		.trim()
		.split_once('/')
		.ok_or_else(|| anyhow::anyhow!("expected an address of the form <user-id>/<device-id>"))?;

	Ok(DeviceAddress::new(
		UserId::parse(user)?,
		DeviceId::from_bytes(
			data_encoding::BASE32_NOPAD
				.decode(device.trim().to_ascii_uppercase().as_bytes())?
				.as_slice()
				.try_into()
				.map_err(|_| anyhow::anyhow!("device id must be 16 bytes"))?,
		),
	))
}

pub async fn send(write: &mut WriteStream, state: &mut State, url: &str) -> Result<()> {
	print!("Enter target device (<user-id>/<device-id>): ");
	io::stdout().flush()?;

	let target = {
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;
		parse_address(&input)?
	};

	if let std::collections::hash_map::Entry::Vacant(entry) = state.peers.entry(target) {
		let (their_ed25519, their_x25519, otk) = fetch_prekey_bundle(&target, url).await?;

		let session = state.account.create_outbound_session(
			SessionConfig::version_2(),
			their_x25519.into(),
			otk.into(),
		);

		entry.insert(PeerSession {
			x25519: their_x25519,
			seen_head: MessageId::ROOT,
			seen_ids: Default::default(),
			sent_ids: Default::default(),
			// Pinned here, and required to match on everything that arrives
			// from this address afterwards.
			ed25519: their_ed25519,
			session,
		});

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

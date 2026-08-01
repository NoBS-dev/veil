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
	identity::{DeviceAddress, DeviceId, UserId},
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
		let msg = ProtocolMessage::EncryptedMessage(EncryptedMessage {
			sender: state.address(),
			recipient: target,
			sender_x25519: state.account.curve25519_key().to_bytes(),
			message_type: msg_type,
			message: ciphertext,
		});

		Envelope::seal(&msg, &state.account)?
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

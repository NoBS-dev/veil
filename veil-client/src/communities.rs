//! Community commands — `DESIGN.md` §7, §8, and the outbound half of §17.
//!
//! **These take parameters and return events. They do not prompt and they do not
//! print.** That is what makes them callable by something other than a terminal:
//! a Qt front end has a text field, not a stdin, and a function that reads one
//! cannot be driven by a view, tested without a pipe, or translated.
//!
//! Results come back as [`ClientEvent`], the same type the receive path emits.
//! One stream of things that happened, rather than two — which is what a
//! front end wants and what the CLI in `cli.rs` renders.
//!
//! Thin on purpose. The host owns ordering and membership, and everything it
//! says about a community is independently checkable — the id is a hash of the
//! root (invariant 13), and every policy record carries its controllers'
//! signatures — so there is little for a client to do beyond asking and
//! verifying.
//!
//! **Sealed channels encrypt with Megolm** (§8.4). The reader set comes from the
//! community's *verified policy chain*, never from the host — in Sealed, read
//! access is key possession rather than an ACL, so a host able to supply the
//! reader set could add itself and have every sender dutifully encrypt to it
//! (§8.5). A Sealed channel with no `ChannelReaders` record is refused rather
//! than defaulted to the membership the host reports, because that default is
//! exactly the attack.
//!
//! Sending in the clear under a Sealed id is never a fallback. That id is what
//! tells everyone else the content is protected, so failing to encrypt has to
//! fail the send.

use crate::{WriteStream, events::ClientEvent, messaging, state::State};
use anyhow::Result;
use futures_util::SinkExt;
use std::{collections::BTreeSet, sync::Arc};
use tokio::sync::Mutex;
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{
	ChannelKey, ChannelPost, Envelope, ProtocolMessage, attachment,
	channelbody::ChannelBody,
	community::{CommunityId, CommunityRoot, Mode, PolicyRecord, Role, SignedPolicy},
	display_key,
	groupkeys::{ChannelId, GroupKeyProvider, Readership},
	identity::DeviceAddress,
	invite::Invite,
};

async fn send(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	message: ProtocolMessage,
) -> Result<()> {
	let framed = Envelope::seal(&message, &state.account)?;
	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(&framed)))
		.await?;
	Ok(())
}

/// Founds a community on the connected host.
///
/// The mode is chosen once and never again: it is hashed into the id
/// (invariant 13), so a community cannot change what it claims to be. Sealed
/// may later transition to Open through the policy chain (§7.3) — one way, and
/// not retroactive — but nothing can turn Open into Sealed, because the history
/// was already readable.
pub async fn found(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	mode: Mode,
) -> Result<Vec<ClientEvent>> {
	// One controller — this user — with a threshold of one. §12.4 wants k-of-n
	// so a community outlives whoever founded it; adding controllers is a
	// policy record, which is the next thing to build here.
	let root = CommunityRoot::found(
		mode,
		vec![state.cross_signing().master_public()],
		1,
		state.cross_signing().master_secret(),
		veil_protocol::now_ms()?,
	)?;

	let id = root.id();
	let link = invite(state, id).unwrap_or_else(|e| format!("<unavailable: {e:#}>"));

	// Recorded *and persisted* before it is sent: we built this root, so we know
	// its mode without having to ask the host. Keeping it only in memory meant
	// the next run had forgotten its own community and refused to post to it —
	// correctly, since not knowing the mode must never be treated as Open.
	state.remember_community(&root);
	state.save_to_keyring()?;

	send(
		write,
		state,
		ProtocolMessage::CreateCommunity(Box::new(root)),
	)
	.await?;

	Ok(vec![ClientEvent::Founded {
		community: id,
		invite: link,
		host_readable: mode == Mode::Open,
	}])
}

/// Joins by community id, or by an invite.
///
/// An invite is the stronger of the two, and the difference is only visible on a
/// *first* connection to a host: it names the identity key that host must
/// present, so a relay cannot quietly send a newcomer somewhere else (§3.2).
/// Joining by bare id on a host already pinned is equivalent; joining by bare id
/// on a new host is a blind pin, and the client says so when it happens.
pub async fn join(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	entered: &str,
) -> Result<Vec<ClientEvent>> {
	let id = match Invite::parse(entered) {
		Ok(invite) => {
			if invite.host_key != state.server_identity.unwrap_or(invite.host_key) {
				anyhow::bail!(
					"that invite is for a host signing as {}, but this client is connected \
					 to one signing as {}. Connect to {} instead.",
					display_key(&invite.host_key),
					display_key(&state.server_identity.unwrap_or_default()),
					invite.host
				);
			}
			invite.community
		}
		// Not an invite, so treat it as a bare id.
		Err(_) => CommunityId::parse(entered)?,
	};

	send(write, state, ProtocolMessage::JoinCommunity(id)).await?;
	Ok(Vec::new())
}

/// Prints an invite for a community on this host.
///
/// Carries the host's identity key, which is what makes it worth more than the
/// community id alone.
pub fn invite(state: &State, id: CommunityId) -> Result<String> {
	let host_key = state.server_identity.ok_or_else(|| {
		anyhow::anyhow!("this client has not yet pinned a host identity to put in an invite")
	})?;

	Ok(Invite {
		community: id,
		host: state.ip_and_port.to_string(),
		host_key,
	}
	.encode())
}

pub async fn say(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	directory: &str,
	id: CommunityId,
	channel: &str,
	body: &str,
) -> Result<Vec<ClientEvent>> {
	let mut reported = Vec::new();

	// The mode is not asked for and not taken from the host: it is inside the
	// id. Whatever the host says about this community, it cannot make an id mean
	// a mode its root did not.
	// Every message states the sender's view of policy, inside the encryption
	// where a host cannot strip it. That is what makes a withheld policy record
	// detectable rather than silent (§8.5).
	let head = state
		.community_state(&id)
		.map(|community| community.chain_head())
		.unwrap_or((0, [0u8; 32]));
	let body = ChannelBody::text(head, body).encode()?;

	let body = match state.community_mode(&id) {
		Some(Mode::Sealed) => {
			seal_for_channel(write, state, directory, &id, channel, &body, &mut reported).await?
		}
		Some(Mode::Open) => body,
		// Not knowing is not the same as Open. A community we have not verified
		// might be Sealed, and guessing wrong sends plaintext under an id that
		// promised otherwise.
		None => anyhow::bail!(
			"this device has not verified {id}. Join it first, so its mode comes from a \
			 root that hashes to its id rather than from whatever the host says."
		),
	};

	send(
		write,
		state,
		ProtocolMessage::Post(ChannelPost {
			community: id,
			channel: channel.to_owned(),
			body,
			nonce: veil_protocol::message::random_nonce(),
			origin_ts: veil_protocol::now_ms()?,
		}),
	)
	.await?;

	Ok(reported)
}

/// Encrypts for a Sealed channel, delivering key material if the readership
/// changed.
///
/// The order matters: keys go out *before* the message. A reader who receives
/// ciphertext for a session they were never given cannot ask for it later —
/// Megolm has no such request — so it would simply be unreadable to them.
async fn seal_for_channel(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	directory: &str,
	id: &CommunityId,
	channel: &str,
	plaintext: &[u8],
	reported: &mut Vec<ClientEvent>,
) -> Result<Vec<u8>> {
	let community = state.community_state(id)?;

	// From the signed chain, not from the host. This is the load-bearing line
	// in the whole Sealed path (§8.5).
	let readers = community.channel_readers.get(channel).ok_or_else(|| {
		anyhow::anyhow!(
			"{id}#{channel} has no signed reader list. Sealed read access is key \
			 possession, so there is nobody to encrypt to — and taking the membership \
			 the host reports instead would let it add itself. Run `readers` first."
		)
	})?;

	// Every reader's devices, each verified against their own cross-signing
	// keys (§5.4). A host that invents a device gets it dropped here rather
	// than handed a key.
	let mut devices = BTreeSet::new();
	for reader in readers {
		let (_, list) = messaging::fetch_device_list(reader, directory, reported).await?;
		state.remember_revocations(*reader, &list.revoked);

		for device in list.active {
			let address = DeviceAddress::new(*reader, device.device_id);
			// A retired device must not be given a key, which is the whole
			// point of retiring it (§5.6).
			if !state.is_revoked(&address) {
				devices.insert(address);
			}
		}
	}

	if devices.is_empty() {
		anyhow::bail!("no verified devices among {id}#{channel}'s readers");
	}

	let channel_id = ChannelId::new(*id, channel);
	let mut provider = state.megolm()?;

	let now = veil_protocol::now_ms()?;

	let delivery = match provider.set_readership(
		&channel_id,
		&Readership {
			devices,
			policy_sequence: community.sequence,
		},
		now,
	)? {
		// A readership change already rotates; asking again would replace a
		// session one message old and make every send cost a distribution.
		Some(delivery) => Some(delivery),
		// Otherwise the session may simply have run long enough (§8.3). Checked
		// on send rather than on a timer, so a channel nobody uses costs
		// nothing and one in use never drifts far past the limit.
		None => provider.rotate_if_due(&channel_id, now),
	};

	if let Some((cause, delivery)) = delivery {
		reported.push(ClientEvent::KeysDistributed {
			channel: format!("{id}#{channel}"),
			recipients: delivery.recipients.len(),
			cause: format!("{cause:?}"),
		});

		for recipient in &delivery.recipients {
			// Every device but this one. Our *other* devices are readers like
			// any other and must be sent the key; this device already holds the
			// session it just created, and an Olm session cannot decrypt its own
			// output anyway.
			if *recipient == state.address() {
				continue;
			}

			if let Err(e) = deliver_key(
				write,
				state,
				directory,
				&channel_id,
				*recipient,
				&delivery.payload,
				reported,
			)
			.await
			{
				// One unreachable device must not stop the rest. It will get
				// the key when it next appears, because the host queues an
				// undeliverable frame like any other.
				reported.push(ClientEvent::warn(format!(
					"Could not deliver a key to {recipient}: {e:#}"
				)));
			}
		}
	}

	let ciphertext = provider.encrypt(&channel_id, plaintext)?;
	state.store_megolm(&provider)?;
	state.save_to_keyring()?;

	Ok(ciphertext)
}

/// Sends one device the key material for a channel, Olm-encrypted.
async fn deliver_key(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	directory: &str,
	channel: &ChannelId,
	recipient: DeviceAddress,
	payload: &[u8],
	reported: &mut Vec<ClientEvent>,
) -> Result<()> {
	// Any warning raised while opening the session belongs to the caller's
	// report, not to a second channel nobody is reading.
	messaging::ensure_session(state, recipient, directory, reported).await?;

	let (message_type, message) = {
		let peer = state
			.peers
			.get_mut(&recipient)
			.ok_or_else(|| anyhow::anyhow!("no session with {recipient}"))?;
		peer.session.encrypt(payload).to_parts()
	};

	send(
		write,
		state,
		ProtocolMessage::ChannelKey(ChannelKey {
			community: channel.community,
			channel: channel.name.clone(),
			sender: state.address(),
			recipient,
			sender_x25519: state.account.curve25519_key().to_bytes(),
			message_type,
			message,
		}),
	)
	.await
}

/// Declares the community's channels, as a signed policy record.
///
/// Signed rather than host-side so a host cannot invent a channel or rename one
/// — the same reasoning as readership (§8.5), applied to the shape of the
/// community rather than to who can read it.
pub fn list_channels(state: &State, id: CommunityId) -> Vec<ClientEvent> {
	let listing = state
		.community_state(&id)
		.map(|community| {
			community
				.channels
				.iter()
				.map(|c| (c.name.clone(), c.topic.clone()))
				.collect()
		})
		.unwrap_or_default();

	vec![ClientEvent::Channels { listing }]
}

/// Declares the set, replacing whatever was there.
pub async fn declare_channels(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	id: CommunityId,
	channels: Vec<veil_protocol::community::ChannelSpec>,
) -> Result<Vec<ClientEvent>> {
	if channels.is_empty() {
		anyhow::bail!("declaring an empty set would leave the community with no channels");
	}

	let sequence = state
		.community_state(&id)
		.map(|community| community.sequence + 1)
		.unwrap_or(1);

	send(
		write,
		state,
		ProtocolMessage::SubmitPolicy(Box::new(SignedPolicy::sign(
			id,
			sequence,
			PolicyRecord::Channels { channels },
			&[(0, state.cross_signing().master_secret())],
		))),
	)
	.await?;
	Ok(Vec::new())
}

/// Says this device is here and watching (§10.3).
///
/// Membership of the subscription *is* the presence signal — there is no
/// separate status to set, and none of it enters the log.
pub async fn watch(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	id: CommunityId,
) -> Result<Vec<ClientEvent>> {
	send(
		write,
		state,
		ProtocolMessage::Ephemeral(veil_protocol::Ephemeral {
			community: id,
			channel: String::new(),
			event: veil_protocol::EphemeralEvent::Watching,
			// Stamped by the host from the authenticated connection; whatever is
			// put here is ignored.
			who: None,
		}),
	)
	.await?;
	Ok(Vec::new())
}

/// Reports a message to the community's moderators (§7.6).
///
/// The host cannot read a Sealed community's content, so what it receives is
/// this account of it — held for a moderator, who can read the channel and
/// check. Attribution is offered but not required: a Megolm session exported at
/// one message's index decrypts everything from there forward, so proving
/// authorship discloses more than the message being reported. §7.6 accepts
/// unattributed reports for exactly that reason and treats them as signal.
pub async fn report(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	id: CommunityId,
	channel: &str,
	sequence: u64,
	quoted: &str,
	reason: &str,
) -> Result<Vec<ClientEvent>> {
	let channel = channel.to_owned();
	let quoted = quoted.to_owned();
	let reason = reason.to_owned();

	send(
		write,
		state,
		ProtocolMessage::Report(Box::new(veil_protocol::Report {
			community: id,
			channel,
			sequence,
			quoted,
			reason,
			attribution: None,
		})),
	)
	.await?;

	Ok(vec![ClientEvent::info(
		"Filing without cryptographic attribution. Proving who wrote it would also \
		 reveal everything sent after it in the same session, so it is not done by \
		 default.",
	)])
}

/// Places a call to a device (§9).
///
/// Relayed by default, which is what keeps a call from handing your address to
/// whoever you are talking to. The offer goes over the Olm session — that is the
/// whole of the security, because the SDP carries the DTLS fingerprint and
/// WebRTC does the rest.
pub async fn call(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	directory: &str,
	calls: &crate::media::Calls,
	target: &str,
) -> Result<Vec<ClientEvent>> {
	let mut reported = Vec::new();
	let recipient = crate::messaging::parse_target(target)?;

	let mut call = [0u8; 16];
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut call);

	place_leg(write, state, directory, calls, call, recipient).await?;
	state.save_to_keyring()?;

	reported.push(ClientEvent::info(format!(
		"Calling {recipient}{}. Media is relayed unless both of you choose otherwise.",
		if state.relay.is_some() {
			""
		} else {
			" directly — no relay is configured, so they will see this address"
		}
	)));

	Ok(reported)
}

/// Opens one leg of a call: a session with one device, offered over the
/// authenticated channel.
///
/// Shared by the 1:1 and mesh paths, because a mesh is exactly this run once per
/// participant — a second implementation is where the two would drift apart.
pub async fn place_leg(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	directory: &str,
	calls: &crate::media::Calls,
	call: [u8; 16],
	recipient: DeviceAddress,
) -> Result<()> {
	let mut reported = Vec::new();

	// A session with the device first: the offer has to travel authenticated or
	// the fingerprint inside it means nothing.
	messaging::ensure_session(state, recipient, directory, &mut reported).await?;

	let call_media = crate::media::Call::open(state.relay.as_deref()).await?;
	call_media.session.offer().await?;
	let sdp = call_media.session.local_description_when_gathered().await?;

	let (message_type, message) = {
		let peer = state
			.peers
			.get_mut(&recipient)
			.ok_or_else(|| anyhow::anyhow!("no session with {recipient}"))?;
		peer.session.encrypt(sdp.as_bytes()).to_parts()
	};

	send(
		write,
		state,
		ProtocolMessage::CallSignal(veil_protocol::CallSignal {
			call,
			sender: state.address(),
			recipient,
			sender_x25519: state.account.curve25519_key().to_bytes(),
			message_type,
			message,
		}),
	)
	.await?;

	// Audio starts if this machine has devices. A client on a box with no sound
	// card should still be able to place a call — it simply cannot talk on it,
	// and saying so is better than failing the call.
	// Once, not twice — calling this in both arms of a check would open two
	// captures on one microphone, which is a mistake this code has already made.
	if let Ok(streams) = crate::audio::run(&call_media) {
		call_media.audio.lock().await.replace(streams);
	}

	// Keyed by call *and* leg, so a mesh holds one entry per participant rather
	// than each leg replacing the last.
	calls
		.lock()
		.await
		.insert(leg_id(call, recipient), call_media);
	Ok(())
}

/// One entry per leg, so a mesh holds a session per participant rather than
/// each leg replacing the last.
///
/// Derived from the call and the far end together: a participant is in exactly
/// one leg of a given call, so this is unique without needing a counter anyone
/// has to agree on.
pub fn leg_id(call: [u8; 16], other: DeviceAddress) -> [u8; 16] {
	let mut id = call;
	for (slot, byte) in id.iter_mut().zip(other.device.as_bytes()) {
		*slot ^= byte;
	}
	id
}

/// Places a group call as a full mesh (§9).
///
/// **No SFU and no group key**, so this needs exactly the cryptography a 1:1
/// call needs — which is none beyond what WebRTC already does. Every participant
/// holds a session with every other, which is more private than an SFU because
/// there is nothing in the middle, and does not scale for the same reason.
///
/// The roster goes to everyone first. Each participant then computes the same
/// topology from it and offers to the half of the call it is responsible for, so
/// the mesh forms without a coordinating round trip.
pub async fn group_call(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	directory: &str,
	calls: &crate::media::Calls,
	targets: &[String],
) -> Result<Vec<ClientEvent>> {
	use std::collections::BTreeSet;
	use veil_protocol::call::Mesh;

	let mut roster: BTreeSet<_> = [state.address()].into_iter().collect();
	for target in targets {
		roster.insert(crate::messaging::parse_target(target)?);
	}

	if !Mesh::viable(roster.len()) {
		anyhow::bail!(
			"a mesh carries {} people at most, and this is {}. Past that every \
			 participant uploads one stream per other participant, which the slowest \
			 connection pays for — it needs a forwarding server, which does not exist yet.",
			veil_protocol::call::MESH_LIMIT,
			roster.len()
		);
	}

	let mut reported = vec![ClientEvent::info(format!(
		"Mesh call with {} others. You will be sending {} streams.",
		roster.len() - 1,
		Mesh::upload_streams(&roster)
	))];

	let mut call = [0u8; 16];
	rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut call);
	let participants: Vec<_> = roster.iter().copied().collect();

	// Everyone learns the roster before anyone offers, so the topology is
	// agreed before it is acted on.
	for recipient in roster.iter().filter(|p| **p != state.address()) {
		send(
			write,
			state,
			ProtocolMessage::CallRoster(veil_protocol::CallRoster {
				call,
				sender: state.address(),
				recipient: *recipient,
				participants: participants.clone(),
			}),
		)
		.await?;
	}

	// Then offer to the half of the mesh this device is responsible for. The
	// others will offer to us.
	for target in Mesh::offers_from(&state.address(), &roster) {
		match place_leg(write, state, directory, calls, call, target).await {
			Ok(()) => {}
			// One unreachable participant should not sink the call — the rest
			// of the mesh is unaffected.
			Err(e) => reported.push(ClientEvent::warn(format!(
				"Could not reach {target}: {e:#}"
			))),
		}
	}

	Ok(reported)
}

/// Uploads an encrypted backup of this identity (§12.5).
///
/// **One recovery key covers identity and history**, because splitting them
/// would only give somebody two things to lose. The blob holds the
/// cross-signing secrets and the Megolm sessions, and the host stores something
/// it cannot open — a host that could would be able to impersonate its user and
/// read every Sealed community they are in.
///
/// The key is generated here and shown once. It is random rather than derived
/// from a passphrase, and that is load-bearing: the blob is fetchable by user
/// id, so whoever holds it can attack it offline at their leisure.
pub async fn backup(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<Vec<ClientEvent>> {
	use veil_protocol::keybackup::{BackupPayload, RecoveryKey, seal};

	let key = RecoveryKey::generate();

	// Round-tripped rather than cloned: `CrossSigningSecrets` is deliberately
	// not `Clone`, so copying the master key is something a caller has to ask
	// for in as many words. A backup is the one place that is legitimate.
	let payload = BackupPayload {
		cross_signing: serde_json::from_str(&serde_json::to_string(state.cross_signing())?)?,
		sessions: state.megolm_exports()?,
	};

	let sealed = seal(&key, &payload)?;
	send(
		write,
		state,
		ProtocolMessage::StoreBackup(serde_json::to_vec(&sealed)?),
	)
	.await?;

	Ok(vec![
		ClientEvent::info(format!("Recovery key: {}", key.display())),
		ClientEvent::info(
			"Write that down now — it is shown once and is not recoverable. It restores \
			 both your identity and your history, on a device that has nothing else.",
		),
	])
}

/// Restores an identity from a backup (§12.5).
///
/// Runs on a device with nothing, which is the case it exists for — so it
/// fetches by user id without authenticating, and the recovery key is the only
/// thing standing between the blob and whoever has it.
pub async fn restore(
	state: &mut State,
	user: &str,
	recovery_key: &str,
) -> Result<Vec<ClientEvent>> {
	use veil_protocol::keybackup::{RecoveryKey, open};

	let user = veil_protocol::identity::UserId::parse(user)?;
	let key = RecoveryKey::parse(recovery_key)?;

	let (scheme, _) = state.schemes();
	let _ = scheme;
	let blob = messaging::directory_client()?
		.get(format!("http://{}/backup/{user}", state.ip_and_port))
		.send()
		.await?
		.error_for_status()?
		.bytes()
		.await?;

	let payload = open(&key, &serde_json::from_slice(&blob)?)?;

	if payload.cross_signing.user_id() != user {
		anyhow::bail!(
			"that backup belongs to {}, not {user} — the host served the wrong one",
			payload.cross_signing.user_id()
		);
	}

	let sessions = payload.sessions.len();
	state.adopt_identity(payload)?;
	state.save_to_keyring()?;

	Ok(vec![ClientEvent::info(format!(
		"Restored {user} with {sessions} session(s). This device has a new device id, so \
		 peers will see it as a new device of yours and history it was never given stays \
		 unreadable."
	))])
}

/// Retires one of this user's own devices (§5.6).
///
/// **The case this exists for is a device already out of your hands**, so it
/// cannot involve asking that device to do anything. The self-signing key signs
/// it — not the master, which stays wherever it is kept (invariant 9) — and the
/// signature covers the retired flag, so a host can neither do this for you nor
/// undo it.
///
/// What it does not do is reach the device. Anything it already holds, it keeps;
/// retiring stops it being *given* anything further and stops peers opening new
/// sessions with it. For a Sealed channel, take it out of the reader list too,
/// which rotates the key.
pub async fn revoke(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	device: veil_protocol::identity::DeviceId,
	device_key: [u8; 32],
) -> Result<Vec<ClientEvent>> {
	if device == state.device_id {
		anyhow::bail!(
			"that is this device. Retiring the one you are using would leave you unable \
			 to retire anything else — use another device, or remove the profile."
		);
	}

	let signature = state.cross_signing().revoke_device(&device, &device_key);

	send(
		write,
		state,
		ProtocolMessage::RevokeDevice(veil_protocol::RevokeDevice {
			device,
			device_ed25519: device_key,
			signature,
		}),
	)
	.await?;

	state
		.revoked_devices
		.insert(veil_protocol::identity::DeviceAddress::new(
			state.user_id,
			device,
		));
	state.save_to_keyring()?;

	Ok(vec![ClientEvent::info(format!(
		"{device} is retired. It keeps whatever it already had — for a Sealed channel, \
		 take it out of the reader list as well, which rotates the key."
	))])
}

/// Claims a human-usable name on this host (§11.6).
pub async fn alias(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	name: &str,
) -> Result<Vec<ClientEvent>> {
	send(write, state, ProtocolMessage::ClaimAlias(name.to_owned())).await?;

	Ok(vec![ClientEvent::info(
		"An alias is server-controlled and re-assignable. It is a convenience, not \
		 your identity — share the contact link instead when it matters.",
	)])
}

/// Prints this device's contact link.
///
/// The safe way to be found: it carries the whole identity, so nothing is looked
/// up and nothing can be substituted (§11.6).
pub fn contact(state: &State) -> Result<Vec<ClientEvent>> {
	Ok(vec![ClientEvent::ContactLink {
		link: crate::contacts::Contact {
			user: state.user_id,
			host: state.ip_and_port.to_string(),
		}
		.encode(),
	}])
}

/// Takes a contact link, or resolves `name@host`.
///
/// The two are not equivalent and the client says which it did. A link carries
/// the identity, so nothing is looked up and nothing can be substituted. A typed
/// address is answered by a server, and anything a server tells you it can lie
/// about — so that answer is pinned, and safety numbers remain the real
/// verification (§11.6).
pub async fn lookup(state: &mut State, entered: &str) -> Result<Vec<ClientEvent>> {
	let (contact, from_link) = match crate::contacts::Contact::parse(entered) {
		Ok(contact) => (contact, true),
		Err(_) => (crate::contacts::resolve(state, entered).await?, false),
	};

	state.save_to_keyring()?;

	Ok(vec![ClientEvent::Resolved {
		user: contact.user,
		host: contact.host,
		from_link,
	}])
}

/// Searches this device's own history (§10.4).
///
/// **Client-side only, and there is no middle setting.** Giving a host the keys
/// to build an index does not make search a bit less private — it makes the
/// community Open while still being labelled Sealed, which §7.3 forbids because
/// it is invisible to members.
///
/// The limits are real and worth stating: a device searches what it has, and a
/// new device is blank until it restores. That is a permanent gap versus Open,
/// and one of the better honest arguments for choosing Open.
pub fn search(state: &State, query: &str) -> Result<Vec<ClientEvent>> {
	if query.is_empty() {
		anyhow::bail!("nothing to search for");
	}

	let history = crate::history::History::open(
		&crate::state::history_path(&state.profile),
		&state.history_key,
	)?;

	Ok(vec![ClientEvent::SearchResults {
		hits: history
			.search(query, 20)?
			.into_iter()
			.map(|hit| crate::events::SearchHit {
				community: hit.community,
				channel: hit.channel,
				sender: hit.sender,
				sequence: hit.sequence,
				text: hit.text,
			})
			.collect(),
	}])
}

/// Reads the moderation queue (§7.6).
pub async fn queue(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	id: CommunityId,
) -> Result<Vec<ClientEvent>> {
	send(write, state, ProtocolMessage::FetchReports(id)).await?;
	Ok(Vec::new())
}

/// Posts a file to a channel (§10.2).
///
/// **Encryption follows the community's tier and is not offered as a choice.**
/// A per-file toggle would be a silent downgrade that one member makes for
/// everyone: somebody posts something sensitive relying on Sealed, and somebody
/// else uploads a screenshot of it in the clear because that was faster. The
/// person bearing the cost is not the person choosing.
pub async fn attach(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	directory: &str,
	id: CommunityId,
	channel: &str,
	path: &str,
) -> Result<Vec<ClientEvent>> {
	let mut reported = Vec::new();

	let contents = std::fs::read(path)?;
	let filename = std::path::Path::new(path)
		.file_name()
		.map(|n| n.to_string_lossy().into_owned())
		.unwrap_or_else(|| "attachment".to_owned());

	let (attachment, stored) = match state.community_mode(&id) {
		Some(Mode::Sealed) => {
			let (attachment, ciphertext) = attachment::seal(&filename, &contents)?;
			(attachment, ciphertext)
		}
		Some(Mode::Open) => (
			attachment::open_tier(&filename, &contents),
			contents.clone(),
		),
		None => anyhow::bail!(
			"this device has not verified {id}. Join it first — uploading before the mode \
			 is known risks handing a Sealed community's host a readable file."
		),
	};

	// The blob first, so the message never references something that is not
	// there. A reference to a missing blob is a broken message; a blob nobody
	// references is garbage the host can collect.
	send(write, state, ProtocolMessage::UploadBlob(stored)).await?;
	reported.push(ClientEvent::Attached {
		filename: filename.clone(),
		size: attachment.size,
		encrypted: attachment.key.is_some(),
	});

	// The reference travels in the message body, so in a Sealed community the
	// key is inside the Megolm envelope and never reaches the host.
	let head = state
		.community_state(&id)
		.map(|community| community.chain_head())
		.unwrap_or((0, [0u8; 32]));
	let body = ChannelBody::file(head, attachment.clone()).encode()?;
	let body = match state.community_mode(&id) {
		Some(Mode::Sealed) => {
			seal_for_channel(write, state, directory, &id, channel, &body, &mut reported).await?
		}
		_ => body,
	};

	send(
		write,
		state,
		ProtocolMessage::Post(ChannelPost {
			community: id,
			channel: channel.to_owned(),
			body,
			nonce: veil_protocol::message::random_nonce(),
			origin_ts: veil_protocol::now_ms()?,
		}),
	)
	.await?;

	Ok(reported)
}

/// Discards a message's content (§10.5).
///
/// **"Deleted for everyone" would be a lie**, and the client says so rather than
/// printing it. The host's copy goes and well-behaved clients drop theirs on
/// receipt; member exports and offline clients keep what they have. Every
/// messaging system provides exactly this and most imply more — here, where
/// members are *encouraged* to keep copies (§12.3), implying more would be worse.
pub async fn delete(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	id: CommunityId,
	channel: &str,
	sequence: u64,
) -> Result<Vec<ClientEvent>> {
	send(
		write,
		state,
		ProtocolMessage::DeleteMessage {
			community: id,
			channel: channel.to_owned(),
			sequence,
		},
	)
	.await?;

	Ok(vec![ClientEvent::info(
		"This removes it from the host and from anyone online. It cannot reach a copy \
		 someone already kept.",
	)])
}

/// Assigns a member's role, as a signed policy record (§8.5).
///
/// Only *reading* needs cryptographic enforcement — everything this grants is
/// something the host can simply refuse. It still lives in the signed chain
/// rather than a host-side table, so there is one source of truth and a host
/// cannot grant itself moderation.
///
/// **Banning is not the same as revoking read access.** A banned member keeps
/// every Megolm key they already hold; that cannot be taken back. To stop them
/// reading what comes next, take them out of the channel's reader list with
/// `readers`, which rotates the session — an expensive operation in a large
/// community, and deliberately a separate act so it is not done by accident.
pub async fn role(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	id: CommunityId,
	user: veil_protocol::identity::UserId,
	role: Role,
) -> Result<Vec<ClientEvent>> {
	let mut reported = Vec::new();

	if role == Role::Banned
		&& let Ok(community) = state.community_state(&id)
		&& community
			.channel_readers
			.values()
			.any(|readers| readers.contains(&user))
	{
		reported.push(ClientEvent::info(format!(
			"note: {user} still holds keys for channels they can read. A ban stops them \
			 posting, not reading — run `readers` to drop them and rotate."
		)));
	}

	let sequence = state
		.community_state(&id)
		.map(|community| community.sequence + 1)
		.unwrap_or(1);

	send(
		write,
		state,
		ProtocolMessage::SubmitPolicy(Box::new(SignedPolicy::sign(
			id,
			sequence,
			PolicyRecord::MemberRole { user, role },
			&[(0, state.cross_signing().master_secret())],
		))),
	)
	.await?;

	Ok(reported)
}

/// Sets who may read a channel, as a signed policy record (§8.5).
///
/// A controller signs this, and it is the *only* thing senders consult when
/// deciding who receives Megolm keys — which is why it has to be signed rather
/// than served.
pub async fn readers(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	id: CommunityId,
	channel: &str,
	readers: Vec<veil_protocol::identity::UserId>,
) -> Result<Vec<ClientEvent>> {
	let channel = channel.to_owned();

	// The next free sequence, from the chain we have verified. A record that
	// does not advance is refused by every replayer, so guessing low simply
	// fails rather than overwriting anything.
	let sequence = state
		.community_state(&id)
		.map(|community| community.sequence + 1)
		.unwrap_or(1);

	let policy = SignedPolicy::sign(
		id,
		sequence,
		PolicyRecord::ChannelReaders { channel, readers },
		&[(0, state.cross_signing().master_secret())],
	);

	send(
		write,
		state,
		ProtocolMessage::SubmitPolicy(Box::new(policy)),
	)
	.await?;
	Ok(Vec::new())
}

pub async fn history(
	write: &Arc<Mutex<WriteStream>>,
	state: &State,
	id: CommunityId,
	channel: &str,
) -> Result<Vec<ClientEvent>> {
	send(
		write,
		state,
		ProtocolMessage::Backfill {
			community: id,
			channel: channel.to_owned(),
			after: 0,
		},
	)
	.await?;
	Ok(Vec::new())
}

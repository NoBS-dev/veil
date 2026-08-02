//! Client commands for communities — `DESIGN.md` §7, §8.
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

use crate::{WriteStream, messaging, state::State};
use anyhow::Result;
use futures_util::SinkExt;
use std::{
	collections::BTreeSet,
	io::{self, Write as _},
	sync::Arc,
};
use tokio::sync::Mutex;
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{
	ChannelKey, ChannelPost, Envelope, ProtocolMessage,
	community::{CommunityId, CommunityRoot, Mode, PolicyRecord, Role, SignedPolicy},
	groupkeys::{ChannelId, GroupKeyProvider, Readership},
	identity::DeviceAddress,
};

fn ask(question: &str) -> Result<String> {
	print!("{question}");
	io::stdout().flush()?;
	let mut input = String::new();
	io::stdin().read_line(&mut input)?;
	Ok(input.trim().to_owned())
}

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
pub async fn found(write: &Arc<Mutex<WriteStream>>, state: &mut State) -> Result<()> {
	let mode = match ask("Mode — (s)ealed end-to-end, or (o)pen server-readable: ")?
		.to_lowercase()
		.as_str()
	{
		"s" | "sealed" => Mode::Sealed,
		"o" | "open" => Mode::Open,
		other => anyhow::bail!("'{other}' is not a mode"),
	};

	if mode == Mode::Open {
		println!(
			"Open: the host can read everything sent here. That is what makes search,\n\
			 moderation and bots possible, and it is the right default for a large\n\
			 community — but say so plainly to anyone joining."
		);
	}

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

	println!("Community id: {}", root.id());
	println!("Share that, with this host's address, as an invite.");

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
	.await
}

pub async fn join(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	send(write, state, ProtocolMessage::JoinCommunity(id)).await
}

pub async fn say(
	write: &Arc<Mutex<WriteStream>>,
	state: &mut State,
	directory: &str,
) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	let channel = ask("Channel: ")?;
	let body = ask("Message: ")?;

	// The mode is not asked for and not taken from the host: it is inside the
	// id. Whatever the host says about this community, it cannot make an id mean
	// a mode its root did not.
	let body = match state.community_mode(&id) {
		Some(Mode::Sealed) => {
			seal_for_channel(write, state, directory, &id, &channel, body.as_bytes()).await?
		}
		Some(Mode::Open) => body.into_bytes(),
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
			channel,
			body,
			nonce: veil_protocol::message::random_nonce(),
			origin_ts: veil_protocol::now_ms()?,
		}),
	)
	.await
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
		let (_, list) = messaging::fetch_device_list(reader, directory).await?;
		for device in list {
			devices.insert(DeviceAddress::new(*reader, device.device_id));
		}
	}

	if devices.is_empty() {
		anyhow::bail!("no verified devices among {id}#{channel}'s readers");
	}

	let channel_id = ChannelId::new(*id, channel);
	let mut provider = state.megolm()?;

	let delivery = provider.set_readership(
		&channel_id,
		&Readership {
			devices,
			policy_sequence: community.sequence,
		},
	)?;

	if let Some((cause, delivery)) = delivery {
		println!(
			"Distributing {}#{channel} keys to {} device(s) ({cause:?}).",
			id,
			delivery.recipients.len()
		);

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
			)
			.await
			{
				// One unreachable device must not stop the rest. It will get
				// the key when it next appears, because the host queues an
				// undeliverable frame like any other.
				eprintln!("Could not deliver a key to {recipient}: {e:#}");
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
) -> Result<()> {
	messaging::ensure_session(state, recipient, directory).await?;

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
pub async fn role(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	let user = veil_protocol::identity::UserId::parse(&ask("User id: ")?)?;

	let role = match ask("Role — (b)anned, (m)ember, (mod)erator: ")?
		.to_lowercase()
		.as_str()
	{
		"b" | "banned" => Role::Banned,
		"m" | "member" => Role::Member,
		"mod" | "moderator" => Role::Moderator,
		other => anyhow::bail!("'{other}' is not a role"),
	};

	if role == Role::Banned
		&& let Ok(community) = state.community_state(&id)
		&& community
			.channel_readers
			.values()
			.any(|readers| readers.contains(&user))
	{
		println!(
			"note: {user} still holds keys for channels they can read. A ban stops them \
			 posting, not reading — run `readers` to drop them and rotate."
		);
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
	.await
}

/// Sets who may read a channel, as a signed policy record (§8.5).
///
/// A controller signs this, and it is the *only* thing senders consult when
/// deciding who receives Megolm keys — which is why it has to be signed rather
/// than served.
pub async fn readers(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	let channel = ask("Channel: ")?;

	let mut readers = Vec::new();
	loop {
		let entry = ask("Reader user id (blank when done): ")?;
		if entry.is_empty() {
			break;
		}
		readers.push(veil_protocol::identity::UserId::parse(&entry)?);
	}

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
	.await
}

pub async fn history(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	let channel = ask("Channel: ")?;

	send(
		write,
		state,
		ProtocolMessage::Backfill {
			community: id,
			channel,
			after: 0,
		},
	)
	.await
}

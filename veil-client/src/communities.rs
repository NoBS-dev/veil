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
	ChannelKey, ChannelPost, Envelope, ProtocolMessage, attachment,
	channelbody::ChannelBody,
	community::{CommunityId, CommunityRoot, Mode, PolicyRecord, Role, SignedPolicy},
	display_key,
	groupkeys::{ChannelId, GroupKeyProvider, Readership},
	identity::DeviceAddress,
	invite::Invite,
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
	match invite(state, root.id()) {
		Ok(invite) => println!("Invite: {invite}"),
		Err(e) => eprintln!("Could not build an invite: {e:#}"),
	}

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

/// Joins by community id, or by an invite.
///
/// An invite is the stronger of the two, and the difference is only visible on a
/// *first* connection to a host: it names the identity key that host must
/// present, so a relay cannot quietly send a newcomer somewhere else (§3.2).
/// Joining by bare id on a host already pinned is equivalent; joining by bare id
/// on a new host is a blind pin, and the client says so when it happens.
pub async fn join(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let entered = ask("Community id, or an invite: ")?;

	let id = match Invite::parse(&entered) {
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
		Err(_) => CommunityId::parse(&entered)?,
	};

	send(write, state, ProtocolMessage::JoinCommunity(id)).await
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
) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	let channel = ask("Channel: ")?;
	let body = ask("Message: ")?;

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
			seal_for_channel(write, state, directory, &id, &channel, &body).await?
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

/// Declares the community's channels, as a signed policy record.
///
/// Signed rather than host-side so a host cannot invent a channel or rename one
/// — the same reasoning as readership (§8.5), applied to the shape of the
/// community rather than to who can read it.
pub async fn channels(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;

	if let Ok(community) = state.community_state(&id) {
		if community.channels.is_empty() {
			println!("No channels declared yet — any name is currently accepted.");
		} else {
			for channel in &community.channels {
				println!("  #{} — {}", channel.name, channel.topic);
			}
		}
	}

	let mut channels = Vec::new();
	loop {
		let name = ask("Channel name (blank when done): ")?;
		if name.is_empty() {
			break;
		}
		let topic = ask("  topic: ")?;
		channels.push(veil_protocol::community::ChannelSpec { name, topic });
	}

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
	.await
}

/// Says this device is here and watching (§10.3).
///
/// Membership of the subscription *is* the presence signal — there is no
/// separate status to set, and none of it enters the log.
pub async fn watch(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;

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
	.await
}

/// Reports a message to the community's moderators (§7.6).
///
/// The host cannot read a Sealed community's content, so what it receives is
/// this account of it — held for a moderator, who can read the channel and
/// check. Attribution is offered but not required: a Megolm session exported at
/// one message's index decrypts everything from there forward, so proving
/// authorship discloses more than the message being reported. §7.6 accepts
/// unattributed reports for exactly that reason and treats them as signal.
pub async fn report(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	let channel = ask("Channel: ")?;
	let sequence: u64 = ask("Message number: ")?.parse()?;
	let quoted = ask("What was said: ")?;
	let reason = ask("Why you are reporting it: ")?;

	println!(
		"Filing without cryptographic attribution. Proving who wrote it would also \
		 reveal everything sent after it in the same session, so it is not done by \
		 default."
	);

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
	.await
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
pub fn search(state: &State) -> Result<()> {
	let query = ask("Search for: ")?;
	if query.is_empty() {
		anyhow::bail!("nothing to search for");
	}

	let history = crate::history::History::open(
		&crate::state::history_path(&state.profile),
		&state.history_key,
	)?;

	let hits = history.search(&query, 20)?;
	if hits.is_empty() {
		println!("Nothing found. This device searches only what it has received.");
		return Ok(());
	}

	for hit in hits {
		match (hit.community, hit.sequence) {
			(Some(community), Some(sequence)) => {
				println!("[{community}#{} {sequence}] {}", hit.channel, hit.text)
			}
			_ => println!("[{}] {}", hit.sender, hit.text),
		}
	}

	Ok(())
}

/// Reads the moderation queue (§7.6).
pub async fn queue(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	send(write, state, ProtocolMessage::FetchReports(id)).await
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
) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	let channel = ask("Channel: ")?;
	let path = ask("File path: ")?;

	let contents = std::fs::read(&path)?;
	let filename = std::path::Path::new(&path)
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
	println!(
		"Uploading {filename} ({} bytes{}).",
		attachment.size,
		if attachment.key.is_some() {
			", encrypted"
		} else {
			", readable by the host"
		}
	);

	// The reference travels in the message body, so in a Sealed community the
	// key is inside the Megolm envelope and never reaches the host.
	let head = state
		.community_state(&id)
		.map(|community| community.chain_head())
		.unwrap_or((0, [0u8; 32]));
	let body = ChannelBody::file(head, attachment.clone()).encode()?;
	let body = match state.community_mode(&id) {
		Some(Mode::Sealed) => {
			seal_for_channel(write, state, directory, &id, &channel, &body).await?
		}
		_ => body,
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

/// Discards a message's content (§10.5).
///
/// **"Deleted for everyone" would be a lie**, and the client says so rather than
/// printing it. The host's copy goes and well-behaved clients drop theirs on
/// receipt; member exports and offline clients keep what they have. Every
/// messaging system provides exactly this and most imply more — here, where
/// members are *encouraged* to keep copies (§12.3), implying more would be worse.
pub async fn delete(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	let channel = ask("Channel: ")?;
	let sequence: u64 = ask("Message number: ")?.parse()?;

	println!(
		"This removes it from the host and from anyone online. It cannot reach a copy \
		 someone already kept."
	);

	send(
		write,
		state,
		ProtocolMessage::DeleteMessage {
			community: id,
			channel,
			sequence,
		},
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

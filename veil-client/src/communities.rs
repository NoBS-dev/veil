//! Client commands for communities — `DESIGN.md` §7, §8.
//!
//! Thin on purpose. The host owns ordering and membership, and everything it
//! says about a community is independently checkable — the id is a hash of the
//! root (invariant 13), and every policy record carries its controllers'
//! signatures — so there is little for a client to do beyond asking and
//! verifying.
//!
//! **Sealed content is not encrypted here yet.** `groupkeys.rs` has the Megolm
//! provider and it is tested, but wiring it in needs the reader set from the
//! policy chain and a device list per reader, which is the next piece of work
//! rather than this one. Until then this refuses to post to a Sealed community
//! rather than sending plaintext into one — sending in the clear under a Sealed
//! id would be the worst possible failure, because the id is exactly what tells
//! everyone else the content is protected.

use crate::{WriteStream, state::State};
use anyhow::Result;
use futures_util::SinkExt;
use std::{
	io::{self, Write as _},
	sync::Arc,
};
use tokio::sync::Mutex;
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{
	ChannelPost, Envelope, ProtocolMessage,
	community::{CommunityId, CommunityRoot, Mode},
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

	// Recorded before it is sent: we built this root, so we know its mode
	// without having to ask the host what it is.
	state.remember_community(&root);

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

pub async fn say(write: &Arc<Mutex<WriteStream>>, state: &State) -> Result<()> {
	let id = CommunityId::parse(&ask("Community id: ")?)?;
	let channel = ask("Channel: ")?;
	let body = ask("Message: ")?;

	// The mode is not asked for and not taken from the host: it is inside the
	// id. Whatever the host says about this community, it cannot make an id
	// mean a mode its root did not.
	if state.community_mode(&id) == Some(Mode::Sealed) {
		anyhow::bail!(
			"this is a Sealed community and Megolm is not wired into the client yet. \
			 Refusing rather than sending plaintext under an id that promises otherwise."
		);
	}

	send(
		write,
		state,
		ProtocolMessage::Post(ChannelPost {
			community: id,
			channel,
			body: body.into_bytes(),
			nonce: veil_protocol::message::random_nonce(),
			origin_ts: veil_protocol::now_ms()?,
		}),
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

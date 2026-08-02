//! Communities and channels on a host — `DESIGN.md` §7, §8.
//!
//! **A community lives on exactly one host and never replicates** (§3.3). That
//! single sentence is what this file is allowed to assume, and it is why there
//! is no state resolution anywhere in it: this host's tables *are* the
//! community, not a cached view of somebody else's. Nothing here may ever cross
//! a server boundary — the moment community state does, Matrix's convergence
//! problem comes back and the architecture's main advantage is gone.
//!
//! **Ordering is the host's.** A member sends one message and the host gives it
//! a position; a member cannot claim one. That is what makes history
//! tamper-*evident* without needing it to be tamper-proof: the host maintains a
//! hash chain, so deleting or reordering a message breaks the chain for every
//! client that saw the original. A single host could still serve two clients
//! different histories from the start — detection, not prevention, is the
//! honest guarantee (§10.1).
//!
//! **The mode is inside the community id** (invariant 13), so a host cannot
//! serve Sealed content under an Open id or the reverse. The host treats the
//! body as opaque bytes either way; what differs is whether the *client*
//! encrypted it. Nothing here inspects a body, so nothing here needs to know.

use crate::{CLIENTS, ServerState, route_to};
use anyhow::{Result, bail};
use veil_protocol::{
	ChannelDelivery, ChannelPost, CommunityView, Envelope, ProtocolMessage,
	community::{CommunityId, CommunityRoot, CommunityState, SignedPolicy},
	identity::{DeviceAddress, UserId},
};

/// Largest body a host will file for a channel.
const MAX_BODY: usize = 1 << 20;
/// Messages returned by one backfill request.
const BACKFILL_LIMIT: usize = 200;

/// Registers a community.
///
/// Two checks, and the first is the load-bearing one: the id is recomputed from
/// the root rather than taken from the client. `CommunityId` hashes the root
/// record with the mode inside it (invariant 13), so a founder cannot register
/// a community under an id whose mode differs from the one they signed.
pub async fn create(state: &ServerState, sender: &DeviceAddress, root: CommunityRoot) -> Response {
	if root.founder != sender.user {
		return Response::refused(
			root.id(),
			"a community can only be founded by the user founding it",
		);
	}

	// Verified against the founder's own master key, which is what the user id
	// is derived from — so this cannot be satisfied by quoting someone else's.
	let founder_master = match founder_master_key(state, &root.founder).await {
		Ok(key) => key,
		Err(e) => return Response::refused(root.id(), &format!("unknown founder: {e}")),
	};

	if let Err(e) = root.verify(&founder_master) {
		return Response::refused(root.id(), &format!("root does not verify: {e}"));
	}

	let id = root.id();
	let json = match serde_json::to_string(&root) {
		Ok(json) => json,
		Err(e) => return Response::refused(id, &format!("could not store the root: {e}")),
	};

	let now = state.clock.read().await.now_ms();
	let store = state.store.lock().await;

	match store.create_community(&id, &json, &root.mode.to_string(), now) {
		Ok(true) => {
			// The founder is a member from the start; a community whose founder
			// has to ask to join is a community nobody can bootstrap.
			let _ = store.add_member(&id, &root.founder, now);
			Response::ok(id, "created")
		}
		// Not an error: the id is a hash of the root, so a second registration
		// of the same id is the same community by definition.
		Ok(false) => Response::ok(id, "already registered"),
		Err(e) => Response::refused(id, &format!("could not store: {e}")),
	}
}

/// Admits a user.
///
/// Open admission for now. §11.5 has the gates a host may put in front of this
/// — invite, captcha, email, phone — and they belong here, in front of the
/// membership write, rather than anywhere further in.
pub async fn join(state: &ServerState, sender: &DeviceAddress, id: CommunityId) -> Response {
	let now = state.clock.read().await.now_ms();
	let store = state.store.lock().await;

	match store.community_root(&id) {
		Ok(None) => return Response::refused(id, "this host does not serve that community"),
		Err(e) => return Response::refused(id, &format!("could not read the community: {e}")),
		Ok(Some(_)) => {}
	}

	match store.add_member(&id, &sender.user, now) {
		Ok(()) => Response::ok(id, "joined"),
		Err(e) => Response::refused(id, &format!("could not record membership: {e}")),
	}
}

/// The community as this host holds it.
///
/// Everything returned is independently checkable: the id is a hash of the root,
/// and every policy record carries its controllers' signatures. A host that
/// edits either is caught by the client, not trusted not to.
pub async fn view(state: &ServerState, id: CommunityId) -> Result<CommunityView> {
	let store = state.store.lock().await;

	let Some(root) = store.community_root(&id)? else {
		bail!("this host does not serve that community");
	};

	Ok(CommunityView {
		root,
		policy_chain: store.policy_chain(&id)?,
		members: store.members(&id)?,
	})
}

/// Files a message and fans it out.
///
/// The sender is the device that authenticated on this connection, not a field
/// in the message — the same rule as a DM (invariant 1). Position is assigned
/// here.
pub async fn post(state: &ServerState, sender: &DeviceAddress, post: ChannelPost) -> Response {
	if post.body.len() > MAX_BODY {
		return Response::refused(post.community, "message is too large");
	}
	if post.channel.is_empty() || post.channel.len() > 128 {
		return Response::refused(post.community, "channel name is out of range");
	}

	let now = state.clock.read().await.now_ms();

	let (delivery, members) = {
		let store = state.store.lock().await;

		// Membership is checked before anything is written. In Sealed this
		// governs fan-out rather than readability — a non-member who obtained a
		// Megolm key could still read what they were given — but it is what
		// stops a stranger writing into a channel.
		match store.is_member(&post.community, &sender.user) {
			Ok(true) => {}
			Ok(false) => {
				return Response::refused(post.community, "you are not a member of that community");
			}
			Err(e) => return Response::refused(post.community, &format!("membership: {e}")),
		}

		let (sequence, prev_hash) = match store.channel_head(&post.community, &post.channel) {
			Ok(head) => head,
			Err(e) => return Response::refused(post.community, &format!("channel head: {e}")),
		};

		let delivery = ChannelDelivery {
			community: post.community,
			channel: post.channel.clone(),
			sender: *sender,
			body: post.body,
			nonce: post.nonce,
			// The sender's clock is recorded, not believed. Ordering is
			// `sequence`; this is only an input to the message id.
			origin_ts: post.origin_ts,
			sequence,
			prev_hash,
		};

		if let Err(e) = store.append_channel_message(&delivery) {
			return Response::refused(post.community, &format!("could not file: {e}"));
		}

		let members = store.members(&post.community).unwrap_or_default();
		(delivery, members)
	};

	let _ = now;
	fan_out(state, &delivery, &members).await;
	Response::ok(
		delivery.community,
		&format!("posted at {}", delivery.sequence),
	)
}

/// Sends a delivery to every connected device of every member.
///
/// Best effort by design. A channel is not a mailbox: a member who was away
/// asks for what they missed by sequence (`Backfill`), which is cheaper than
/// queueing a copy per member per message and is the only thing that scales to
/// a large community (§13.1).
async fn fan_out(state: &ServerState, delivery: &ChannelDelivery, members: &[UserId]) {
	let framed = {
		let account = state.server_account.lock().await;
		match Envelope::seal(
			&ProtocolMessage::Delivery(Box::new(delivery.clone())),
			&account,
		) {
			Ok(framed) => framed.to_vec(),
			Err(e) => {
				eprintln!("Could not seal a channel delivery: {e:#}");
				return;
			}
		}
	};

	// Snapshot the addresses under the lock, then send outside it — the same
	// rule as DM routing (§13.3): one slow member must not stall the rest.
	let addresses: Vec<DeviceAddress> = {
		let clients = CLIENTS.read().await;
		clients
			.keys()
			.filter(|address| members.contains(&address.user))
			.copied()
			.collect()
	};

	for address in addresses {
		let _ = route_to(&address, framed.clone()).await;
	}
}

/// Sends every connected member the community's current state.
///
/// Called when policy changes. Without it, only the controller who submitted a
/// record would know about it — so every other sender would keep deriving
/// readership from a stale chain and keep encrypting to a device that had just
/// been removed, which makes removal cosmetic for anyone but the remover.
///
/// This narrows the window; it does not close it. A host can still *withhold*
/// the newest record from a member, and that member cannot tell. Sequence
/// numbers stop the chain being rewound, so the host's only move is to hide the
/// tip — see §8.5.
pub async fn broadcast_state(state: &ServerState, id: CommunityId) {
	let Ok(view) = view(state, id).await else {
		return;
	};

	let framed = {
		let account = state.server_account.lock().await;
		match Envelope::seal(&ProtocolMessage::CommunityState(Box::new(view)), &account) {
			Ok(framed) => framed.to_vec(),
			Err(e) => {
				eprintln!("Could not seal a community state: {e:#}");
				return;
			}
		}
	};

	let members = state.store.lock().await.members(&id).unwrap_or_default();
	let addresses: Vec<DeviceAddress> = {
		let clients = CLIENTS.read().await;
		clients
			.keys()
			.filter(|address| members.contains(&address.user))
			.copied()
			.collect()
	};

	for address in addresses {
		let _ = route_to(&address, framed.clone()).await;
	}
}

/// Answers a request for missed history.
pub async fn backfill(
	state: &ServerState,
	sender: &DeviceAddress,
	id: CommunityId,
	channel: &str,
	after: u64,
) -> Result<Vec<ChannelDelivery>> {
	let store = state.store.lock().await;

	if !store.is_member(&id, &sender.user)? {
		bail!("you are not a member of that community");
	}

	store.channel_since(&id, channel, after, BACKFILL_LIMIT)
}

/// Adds a policy record to the chain (§7.4).
///
/// The host replays the whole chain and applies the new record to it, which is
/// what enforces k *distinct* controllers and a strictly advancing sequence
/// (invariant 16). The host is not the authority here — clients verify the same
/// chain themselves — but it must not serve a chain it knows to be invalid.
pub async fn submit_policy(state: &ServerState, policy: SignedPolicy) -> Response {
	let id = policy.community;
	let store = state.store.lock().await;

	let Ok(Some(root_json)) = store.community_root(&id) else {
		return Response::refused(id, "this host does not serve that community");
	};

	let root: CommunityRoot = match serde_json::from_str(&root_json) {
		Ok(root) => root,
		Err(e) => return Response::refused(id, &format!("stored root is unreadable: {e}")),
	};

	// Replayed from the root every time rather than kept in memory: the check
	// that matters is that the *whole* chain still validates with this record
	// appended, not that this record looks reasonable on its own.
	//
	// The founder's signature is not re-checked — it was checked when the
	// community was registered, and the root cannot have changed since, because
	// its hash is the id. Controllers authorise policy, not the founder.
	let mut community = match CommunityState::without_founder_check(root) {
		Ok(state) => state,
		Err(e) => return Response::refused(id, &format!("stored root is unusable: {e}")),
	};

	let chain = store.policy_chain(&id).unwrap_or_default();
	for entry in &chain {
		if let Ok(previous) = serde_json::from_str::<SignedPolicy>(entry)
			&& community.apply(&previous).is_err()
		{
			return Response::refused(id, "stored policy chain no longer validates");
		}
	}

	if let Err(e) = community.apply(&policy) {
		return Response::refused(id, &format!("policy rejected: {e}"));
	}

	let json = match serde_json::to_string(&policy) {
		Ok(json) => json,
		Err(e) => return Response::refused(id, &format!("could not store: {e}")),
	};

	match store.append_policy(&id, policy.sequence, &json) {
		Ok(()) => Response::ok(id, "policy applied"),
		Err(e) => Response::refused(id, &format!("could not store: {e}")),
	}
}

/// A host's answer to a community request.
pub struct Response {
	pub community: CommunityId,
	pub ok: bool,
	pub detail: String,
}

impl Response {
	fn ok(community: CommunityId, detail: &str) -> Self {
		Self {
			community,
			ok: true,
			detail: detail.to_owned(),
		}
	}

	fn refused(community: CommunityId, detail: &str) -> Self {
		Self {
			community,
			ok: false,
			detail: detail.to_owned(),
		}
	}

	pub fn into_message(self) -> ProtocolMessage {
		ProtocolMessage::CommunityResult {
			community: self.community,
			ok: self.ok,
			detail: self.detail,
		}
	}
}

/// The master key a user id is derived from, as this host has it on file.
async fn founder_master_key(state: &ServerState, user: &UserId) -> Result<[u8; 32]> {
	let store = state.store.lock().await;
	let Some((keys, _)) = store.device_list(user)? else {
		bail!("{user} has no devices published here");
	};
	Ok(keys.master)
}

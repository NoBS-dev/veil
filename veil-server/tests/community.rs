//! Communities and channels over a transport — `DESIGN.md` §7, §8.
//!
//! The primitives (`community.rs`, `groupkeys.rs`) were correct and tested in
//! isolation; nothing carried them over a wire. These are the first tests where
//! a community exists on a host and a message reaches a channel.
//!
//! The properties worth defending here are not the happy path. They are: a host
//! cannot serve a community under an id that does not hash to its root; a
//! stranger cannot write into or read a channel; a member cannot claim a
//! position in history; and a Sealed community's host stores bytes it cannot
//! read.

mod harness;

use harness::{Server, TestClient};
use std::time::Duration;
use veil_protocol::{
	ChannelPost, ProtocolMessage,
	community::{CommunityId, CommunityRoot, Mode, PolicyRecord, SignedPolicy},
};

const BEAT: Duration = Duration::from_millis(1500);
/// How long to wait for something that *should* arrive.
///
/// Generous on purpose. These tests run alongside every other test binary, each
/// spawning its own servers and clients, so a fixed short wait is a guess about
/// machine load rather than about the protocol — and it was wrong often enough
/// to make the suite flaky. Waiting for a condition with a deadline costs
/// nothing when things are fast.
const PATIENCE: Duration = Duration::from_secs(20);

/// Founds a community on a host, returning its id.
async fn found(founder: &mut TestClient, mode: Mode) -> CommunityId {
	let controller = founder.cross_signing.master_public();
	let root = CommunityRoot::found(
		mode,
		vec![controller],
		1,
		founder.cross_signing.master_secret(),
		harness::now_ms(),
	)
	.unwrap();
	let id = root.id();

	founder
		.send(&ProtocolMessage::CreateCommunity(Box::new(root)))
		.await
		.unwrap();

	let result = expect_result(founder).await;
	assert!(result.1, "founding should succeed: {}", result.2);
	id
}

/// Reads until the host reports the outcome of a community request.
async fn expect_result(client: &mut TestClient) -> (CommunityId, bool, String) {
	let deadline = tokio::time::Instant::now() + PATIENCE;

	loop {
		match client.recv(BEAT).await {
			Some(ProtocolMessage::CommunityResult {
				community,
				ok,
				detail,
			}) => return (community, ok, detail),
			Some(_) => continue,
			// Nothing yet is not nothing ever: keep waiting until the deadline,
			// so a slow machine does not read as a broken server.
			None if tokio::time::Instant::now() < deadline => continue,
			None => panic!("the host said nothing about a community request"),
		}
	}
}

/// Reads until a channel delivery arrives, waiting up to `patience`.
///
/// Two callers with opposite needs: draining wants to give up quickly on
/// nothing, and expecting wants to wait. Passing the limit in keeps them from
/// being the same compromise.
async fn delivery_within(
	client: &mut TestClient,
	patience: Duration,
) -> Option<veil_protocol::ChannelDelivery> {
	let deadline = tokio::time::Instant::now() + patience;

	loop {
		match client.recv(BEAT).await {
			Some(ProtocolMessage::Delivery(delivery)) => return Some(*delivery),
			Some(_) => continue,
			None if tokio::time::Instant::now() < deadline => continue,
			None => return None,
		}
	}
}

/// A delivery that is expected to arrive.
async fn next_delivery(client: &mut TestClient) -> Option<veil_protocol::ChannelDelivery> {
	delivery_within(client, PATIENCE).await
}

fn post(community: CommunityId, channel: &str, body: &[u8]) -> ProtocolMessage {
	ProtocolMessage::Post(ChannelPost {
		community,
		channel: channel.to_owned(),
		body: body.to_vec(),
		nonce: harness::nonce(),
		origin_ts: harness::now_ms(),
	})
}

#[tokio::test]
async fn a_message_reaches_a_channel() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	bob.send(&ProtocolMessage::JoinCommunity(id)).await.unwrap();
	assert!(expect_result(&mut bob).await.1, "bob should be admitted");
	tokio::time::sleep(BEAT).await;

	alice
		.send(&post(id, "general", b"hello channel"))
		.await
		.unwrap();

	let delivery = next_delivery(&mut bob)
		.await
		.expect("bob should receive it");
	assert_eq!(delivery.body, b"hello channel");
	assert_eq!(delivery.sender, alice.address());
	assert_eq!(delivery.sequence, 1);
	assert_eq!(
		delivery.prev_hash, [0u8; 32],
		"the first message chains onto nothing"
	);

	server.stop().await;
}

/// Membership is what the host enforces. A stranger cannot write into a
/// channel, whatever the mode.
#[tokio::test]
async fn a_stranger_cannot_post_to_a_channel() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;

	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(5).await.unwrap();
	mallory
		.send(&post(id, "general", b"i do not belong here"))
		.await
		.unwrap();

	let (_, ok, detail) = expect_result(&mut mallory).await;
	assert!(!ok, "a stranger's post should be refused");
	assert!(detail.contains("not a member"), "got: {detail}");

	// And the control: nothing was filed, so a member sees an empty channel.
	alice
		.send(&ProtocolMessage::Backfill {
			community: id,
			channel: "general".into(),
			after: 0,
		})
		.await
		.unwrap();
	assert!(
		delivery_within(&mut alice, Duration::ZERO).await.is_none(),
		"the refused message must not have been filed"
	);

	server.stop().await;
}

/// Nor read one. Backfill is the only way to see history, and it checks
/// membership.
#[tokio::test]
async fn a_stranger_cannot_backfill_a_channel() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;
	alice
		.send(&post(id, "general", b"members only"))
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(5).await.unwrap();
	mallory
		.send(&ProtocolMessage::Backfill {
			community: id,
			channel: "general".into(),
			after: 0,
		})
		.await
		.unwrap();

	let (_, ok, detail) = expect_result(&mut mallory).await;
	assert!(!ok, "a stranger's backfill should be refused: {detail}");

	// The control: a member gets the same request answered.
	alice
		.send(&ProtocolMessage::Backfill {
			community: id,
			channel: "general".into(),
			after: 0,
		})
		.await
		.unwrap();
	assert_eq!(
		next_delivery(&mut alice)
			.await
			.expect("a member should see it")
			.body,
		b"members only",
		"the history exists; only the stranger is refused"
	);

	server.stop().await;
}

/// §10.1: ordering is the host's. A member sends one message and the host gives
/// it a position, so nobody can claim one — which is the whole reason this
/// design needs no state resolution.
#[tokio::test]
async fn the_host_assigns_position_and_chains_history() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;

	for n in 1..=3 {
		alice
			.send(&post(id, "general", format!("message {n}").as_bytes()))
			.await
			.unwrap();
		tokio::time::sleep(Duration::from_millis(300)).await;
	}
	tokio::time::sleep(BEAT).await;

	alice
		.send(&ProtocolMessage::Backfill {
			community: id,
			channel: "general".into(),
			after: 0,
		})
		.await
		.unwrap();

	let mut history = Vec::new();
	while let Some(delivery) = next_delivery(&mut alice).await {
		history.push(delivery);
		if history.len() == 3 {
			break;
		}
	}
	assert_eq!(history.len(), 3, "all three should be in history");

	// Sequences are consecutive and start at one.
	assert_eq!(
		history.iter().map(|d| d.sequence).collect::<Vec<_>>(),
		vec![1, 2, 3]
	);

	// And each message chains onto the one before it, so removing or reordering
	// any of them is detectable by anyone who saw the original.
	assert_eq!(history[0].prev_hash, [0u8; 32]);
	assert_eq!(history[1].prev_hash, history[0].chain_hash());
	assert_eq!(history[2].prev_hash, history[1].chain_hash());

	server.stop().await;
}

/// Invariant 13: the mode is inside the id, so a host cannot serve a different
/// mode under the same identity — and a founder cannot register one either.
#[tokio::test]
async fn a_community_id_is_bound_to_its_mode() {
	let founder = veil_protocol::crosssign::CrossSigningSecrets::new();
	let sealed = CommunityRoot::found(
		Mode::Sealed,
		vec![founder.master_public()],
		1,
		founder.master_secret(),
		harness::now_ms(),
	)
	.unwrap();

	// Identical in every other respect, including the founder and the moment it
	// was created.
	let open = CommunityRoot {
		mode: Mode::Open,
		..sealed.clone()
	};

	assert_ne!(
		sealed.id(),
		open.id(),
		"the same community in two modes must not share an id"
	);
}

/// A Sealed community's host files bytes it cannot read.
///
/// The test is deliberately blunt: the plaintext must not appear anywhere in the
/// host's own database. A host that could read Sealed content would make the
/// tier meaningless.
#[tokio::test]
async fn a_sealed_channel_stores_nothing_the_host_can_read() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Sealed).await;

	// What a Sealed client sends: Megolm ciphertext, not text.
	let secret = b"the host must never see this";
	let ciphertext = harness::sealed_body(secret);
	alice.send(&post(id, "general", &ciphertext)).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// Both files: the store runs in WAL mode, so a recent write is in the
	// write-ahead log rather than the main database. Reading only the latter
	// found no ciphertext at all — and the control below is what caught that,
	// since without it this test would have "passed" against a host that stored
	// nothing.
	let mut raw = std::fs::read(&server.db).unwrap();
	if let Ok(wal) = std::fs::read(format!("{}-wal", server.db)) {
		raw.extend_from_slice(&wal);
	}
	assert!(
		!raw.windows(secret.len()).any(|w| w == secret),
		"the plaintext of a Sealed message must not be in the host's database"
	);
	// The control: the ciphertext *is* there, so the message really was filed
	// and the assertion above is not passing because nothing was stored.
	assert!(
		raw.windows(ciphertext.len()).any(|w| w == ciphertext),
		"the ciphertext should have been filed"
	);

	server.stop().await;
}

/// Invariant 16: policy needs k *distinct* controllers, and a host must not
/// serve a chain it knows to be invalid.
#[tokio::test]
async fn policy_below_the_threshold_is_refused() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// Two controllers, both needed.
	let second = veil_protocol::crosssign::CrossSigningSecrets::new();
	let root = CommunityRoot::found(
		Mode::Sealed,
		vec![alice.cross_signing.master_public(), second.master_public()],
		2,
		alice.cross_signing.master_secret(),
		harness::now_ms(),
	)
	.unwrap();
	let id = root.id();
	alice
		.send(&ProtocolMessage::CreateCommunity(Box::new(root.clone())))
		.await
		.unwrap();
	assert!(expect_result(&mut alice).await.1);

	// One controller signing alone.
	let record = PolicyRecord::ChannelReaders {
		channel: "general".into(),
		readers: vec![alice.user()],
	};
	let under_signed = SignedPolicy::sign(
		id,
		1,
		record.clone(),
		&[(0, alice.cross_signing.master_secret())],
	);

	alice
		.send(&ProtocolMessage::SubmitPolicy(Box::new(under_signed)))
		.await
		.unwrap();
	let (_, ok, detail) = expect_result(&mut alice).await;
	assert!(!ok, "one of two controllers must not be enough: {detail}");

	// The control: with both, the same record is accepted.
	let properly_signed = SignedPolicy::sign(
		id,
		1,
		record,
		&[
			(0, alice.cross_signing.master_secret()),
			(1, second.master_secret()),
		],
	);
	alice
		.send(&ProtocolMessage::SubmitPolicy(Box::new(properly_signed)))
		.await
		.unwrap();
	let (_, ok, detail) = expect_result(&mut alice).await;
	assert!(ok, "two of two should be accepted: {detail}");

	server.stop().await;
}

/// §8.5: posting is a host-enforced permission, read from the signed chain.
///
/// The whole point of the split is that only *reading* needs cryptography —
/// everything else is an action the host can refuse. This is that refusal.
#[tokio::test]
async fn a_banned_member_cannot_post_or_backfill() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;

	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(5).await.unwrap();
	mallory
		.send(&ProtocolMessage::JoinCommunity(id))
		.await
		.unwrap();
	assert!(expect_result(&mut mallory).await.1);
	tokio::time::sleep(BEAT).await;

	// The control comes first: while an ordinary member, she can post.
	mallory
		.send(&post(id, "general", b"before the ban"))
		.await
		.unwrap();
	let (_, ok, detail) = expect_result(&mut mallory).await;
	assert!(ok, "an ordinary member should be able to post: {detail}");

	ban(&mut alice, id, mallory.user()).await;

	mallory
		.send(&post(id, "general", b"after the ban"))
		.await
		.unwrap();
	let (_, ok, detail) = expect_result(&mut mallory).await;
	assert!(!ok, "a banned member must not post");
	assert!(detail.contains("banned"), "got: {detail}");

	mallory
		.send(&ProtocolMessage::Backfill {
			community: id,
			channel: "general".into(),
			after: 0,
		})
		.await
		.unwrap();
	let (_, ok, _) = expect_result(&mut mallory).await;
	assert!(!ok, "a banned member must not be handed more history");

	server.stop().await;
}

/// A ban is a role in the chain rather than a deletion from the member list,
/// which is what makes it survive the member leaving and coming back.
#[tokio::test]
async fn a_ban_survives_rejoining() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;

	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(5).await.unwrap();
	mallory
		.send(&ProtocolMessage::JoinCommunity(id))
		.await
		.unwrap();
	assert!(expect_result(&mut mallory).await.1);
	tokio::time::sleep(BEAT).await;

	ban(&mut alice, id, mallory.user()).await;

	// Rejoining is the obvious way to try to shed a ban.
	mallory
		.send(&ProtocolMessage::JoinCommunity(id))
		.await
		.unwrap();
	let (_, ok, detail) = expect_result(&mut mallory).await;
	assert!(!ok, "rejoining must not clear a ban: {detail}");

	server.stop().await;
}

/// Signs a ban as the founding controller.
async fn ban(
	controller: &mut TestClient,
	id: CommunityId,
	subject: veil_protocol::identity::UserId,
) {
	let record = PolicyRecord::MemberRole {
		user: subject,
		role: veil_protocol::community::Role::Banned,
	};
	controller
		.send(&ProtocolMessage::SubmitPolicy(Box::new(
			SignedPolicy::sign(
				id,
				1,
				record,
				&[(0, controller.cross_signing.master_secret())],
			),
		)))
		.await
		.unwrap();

	let (_, ok, detail) = expect_result(controller).await;
	assert!(ok, "the ban should be accepted: {detail}");
	tokio::time::sleep(BEAT).await;
}

/// §10.5: deletion is tombstoning, and the chain survives it.
///
/// This is the property the whole design of §10 was arranged to get for free:
/// the chain links message *ids*, and an id hashes the original content, so
/// blanking a body leaves identity and position untouched. Deleting the row
/// would break the chain for everyone.
#[tokio::test]
async fn deleting_a_message_tombstones_it_and_the_chain_still_holds() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;

	for n in 1..=3 {
		alice
			.send(&post(id, "general", format!("message {n}").as_bytes()))
			.await
			.unwrap();
		tokio::time::sleep(Duration::from_millis(300)).await;
	}
	tokio::time::sleep(BEAT).await;

	let before = history(&mut alice, id).await;
	assert_eq!(before.len(), 3);
	let doomed_id = before[1].id();

	alice
		.send(&ProtocolMessage::DeleteMessage {
			community: id,
			channel: "general".into(),
			sequence: 2,
		})
		.await
		.unwrap();
	let (_, ok, detail) = expect_result(&mut alice).await;
	assert!(
		ok,
		"an author should be able to delete their own message: {detail}"
	);
	tokio::time::sleep(BEAT).await;

	let after = history(&mut alice, id).await;
	assert_eq!(after.len(), 3, "the entry stays; only its content goes");
	assert!(
		after[1].tombstoned,
		"the middle message should be a tombstone"
	);
	assert!(after[1].body.is_empty(), "its content should be gone");
	assert_eq!(
		after[1].id(),
		doomed_id,
		"a tombstone keeps the identity it had, which is what the chain links"
	);

	// The chain still verifies across the gap, end to end.
	assert_eq!(after[0].prev_hash, [0u8; 32]);
	assert_eq!(after[1].prev_hash, after[0].chain_hash());
	assert_eq!(
		after[2].prev_hash,
		after[1].chain_hash(),
		"the link after a tombstone must still verify"
	);

	// And the host's own copy is genuinely gone.
	let mut raw = std::fs::read(&server.db).unwrap();
	if let Ok(wal) = std::fs::read(format!("{}-wal", server.db)) {
		raw.extend_from_slice(&wal);
	}
	assert!(
		!raw.windows(b"message 2".len()).any(|w| w == b"message 2"),
		"the deleted content must not remain in the host's database"
	);
	assert!(
		raw.windows(b"message 3".len()).any(|w| w == b"message 3"),
		"and its neighbours must be untouched"
	);

	server.stop().await;
}

/// Deleting is the author's or a moderator's, and nobody else's.
#[tokio::test]
async fn an_ordinary_member_cannot_delete_someone_elses_message() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;
	alice
		.send(&post(id, "general", b"alice wrote this"))
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(5).await.unwrap();
	mallory
		.send(&ProtocolMessage::JoinCommunity(id))
		.await
		.unwrap();
	assert!(expect_result(&mut mallory).await.1);

	mallory
		.send(&ProtocolMessage::DeleteMessage {
			community: id,
			channel: "general".into(),
			sequence: 1,
		})
		.await
		.unwrap();
	let (_, ok, detail) = expect_result(&mut mallory).await;
	assert!(
		!ok,
		"an ordinary member must not delete someone else's message"
	);
	assert!(detail.contains("only delete your own"), "got: {detail}");

	// The control: it is still there, and still readable.
	let history = history(&mut alice, id).await;
	assert_eq!(history[0].body, b"alice wrote this");
	assert!(!history[0].tombstoned);

	server.stop().await;
}

/// A moderator can, which is the difference §8.5 draws between the two.
#[tokio::test]
async fn a_moderator_can_delete_anyone_s_message() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	bob.send(&ProtocolMessage::JoinCommunity(id)).await.unwrap();
	assert!(expect_result(&mut bob).await.1);
	tokio::time::sleep(BEAT).await;

	bob.send(&post(id, "general", b"bob wrote this"))
		.await
		.unwrap();
	let (_, ok, _) = expect_result(&mut bob).await;
	assert!(ok);
	tokio::time::sleep(BEAT).await;

	// Alice founded it, so she moderates by construction.
	alice
		.send(&ProtocolMessage::DeleteMessage {
			community: id,
			channel: "general".into(),
			sequence: 1,
		})
		.await
		.unwrap();
	let (_, ok, detail) = expect_result(&mut alice).await;
	assert!(ok, "a moderator should be able to delete: {detail}");
	tokio::time::sleep(BEAT).await;

	let history = history(&mut alice, id).await;
	assert!(history[0].tombstoned);

	server.stop().await;
}

/// §7.6: a Sealed host cannot read what is reported, so it holds the reporter's
/// account for a moderator rather than judging it.
#[tokio::test]
async fn a_report_is_held_for_a_moderator() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Sealed).await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	bob.send(&ProtocolMessage::JoinCommunity(id)).await.unwrap();
	assert!(expect_result(&mut bob).await.1);
	tokio::time::sleep(BEAT).await;

	// A report with no attribution is still accepted — §7.6 treats it as signal
	// for review, because requiring proof costs the reporter more privacy than
	// the report is worth.
	bob.send(&ProtocolMessage::Report(Box::new(veil_protocol::Report {
		community: id,
		channel: "general".into(),
		sequence: 1,
		quoted: "something worth reporting".into(),
		reason: "abuse".into(),
		attribution: None,
	})))
	.await
	.unwrap();

	let (_, ok, detail) = expect_result(&mut bob).await;
	assert!(
		ok,
		"an unattributed report must still be accepted: {detail}"
	);
	assert!(detail.contains("moderator will review"), "got: {detail}");

	server.stop().await;
}

/// Only members may report, which is the one thing a host can check — and what
/// stops anyone at all filling a moderation queue.
#[tokio::test]
async fn a_stranger_cannot_report() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Sealed).await;

	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(5).await.unwrap();

	let report = veil_protocol::Report {
		community: id,
		channel: "general".into(),
		sequence: 1,
		quoted: "fabricated".into(),
		reason: "noise".into(),
		attribution: None,
	};
	mallory
		.send(&ProtocolMessage::Report(Box::new(report.clone())))
		.await
		.unwrap();
	let (_, ok, detail) = expect_result(&mut mallory).await;
	assert!(!ok, "a stranger must not be able to report: {detail}");

	// The control: the identical report from a member is accepted, so the
	// refusal above is about membership and not about the report itself.
	mallory
		.send(&ProtocolMessage::JoinCommunity(id))
		.await
		.unwrap();
	assert!(expect_result(&mut mallory).await.1);
	mallory
		.send(&ProtocolMessage::Report(Box::new(report)))
		.await
		.unwrap();
	assert!(expect_result(&mut mallory).await.1, "a member may report");

	server.stop().await;
}

/// The queue is a moderator's, and nobody else's.
#[tokio::test]
async fn only_a_moderator_can_read_the_report_queue() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Sealed).await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	bob.send(&ProtocolMessage::JoinCommunity(id)).await.unwrap();
	assert!(expect_result(&mut bob).await.1);
	tokio::time::sleep(BEAT).await;

	bob.send(&ProtocolMessage::Report(Box::new(veil_protocol::Report {
		community: id,
		channel: "general".into(),
		sequence: 1,
		quoted: "something worth reporting".into(),
		reason: "abuse".into(),
		attribution: None,
	})))
	.await
	.unwrap();
	assert!(expect_result(&mut bob).await.1);
	tokio::time::sleep(BEAT).await;

	// Bob reported it, and still may not read the queue.
	bob.send(&ProtocolMessage::FetchReports(id)).await.unwrap();
	let (_, ok, detail) = expect_result(&mut bob).await;
	assert!(!ok, "an ordinary member must not read the queue: {detail}");

	// Alice founded it, so she moderates by construction.
	alice
		.send(&ProtocolMessage::FetchReports(id))
		.await
		.unwrap();
	let entries = loop {
		match alice.recv(BEAT).await {
			Some(ProtocolMessage::ReportQueue { entries, .. }) => break entries,
			Some(_) => continue,
			None => panic!("a moderator should have been given the queue"),
		}
	};

	assert_eq!(entries.len(), 1);
	assert_eq!(entries[0].2, "abuse");
	assert!(!entries[0].3, "this one was filed without attribution");

	server.stop().await;
}

/// Everything in a channel, oldest first.
///
/// Drains first: posting fans the message straight back to the sender, so those
/// live deliveries are still queued and would otherwise be counted alongside the
/// backfill — which read as six messages where three were sent.
async fn history(client: &mut TestClient, id: CommunityId) -> Vec<veil_protocol::ChannelDelivery> {
	while delivery_within(client, Duration::ZERO).await.is_some() {}

	client
		.send(&ProtocolMessage::Backfill {
			community: id,
			channel: "general".into(),
			after: 0,
		})
		.await
		.unwrap();

	let mut history = Vec::new();
	// The first is worth waiting for; the rest follow immediately behind it.
	if let Some(first) = next_delivery(client).await {
		history.push(first);
		while let Some(delivery) = delivery_within(client, Duration::ZERO).await {
			history.push(delivery);
		}
	}
	history
}

/// Communities are the host's authoritative state (§3.3), so they must survive
/// a restart like anything else.
#[tokio::test]
async fn a_community_and_its_history_survive_a_restart() {
	let server = Server::start().await;
	let db = server.db.clone();
	let address = server.address();

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice, Mode::Open).await;
	alice
		.send(&post(id, "general", b"before the restart"))
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	server.stop_keeping_data().await;
	tokio::time::sleep(BEAT).await;
	let restarted = Server::start_at(&address, Some(db.clone())).await;

	let mut alice = alice
		.disconnect()
		.connect(&restarted.ws_url())
		.await
		.unwrap();
	alice
		.send(&ProtocolMessage::Backfill {
			community: id,
			channel: "general".into(),
			after: 0,
		})
		.await
		.unwrap();

	let delivery = next_delivery(&mut alice)
		.await
		.expect("history should survive a restart");
	assert_eq!(delivery.body, b"before the restart");

	restarted.stop_keeping_data().await;
	Server::discard(&db);
}

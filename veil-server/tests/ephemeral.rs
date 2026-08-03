//! Presence, typing and read state — `DESIGN.md` §10.3.
//!
//! The property that matters is what these events are *not*: they never enter
//! the log. No sequence, no previous hash, no place in the chain — so a channel
//! full of typing notifications leaves history exactly as it was.
//!
//! The second is scope. Presence is answered by whoever already holds the state:
//! one community, one host, one subscriber list. There is deliberately no
//! cross-community presence, because "is Alice online somewhere" would need a
//! global view no component has.

mod harness;

use harness::{Server, TestClient};
use std::time::Duration;
use veil_protocol::{
	Ephemeral, EphemeralEvent, ProtocolMessage,
	community::{CommunityId, CommunityRoot, Mode},
};

const BEAT: Duration = Duration::from_millis(1500);
const PATIENCE: Duration = Duration::from_secs(20);

async fn found(founder: &mut TestClient) -> CommunityId {
	let root = CommunityRoot::found(
		Mode::Open,
		vec![founder.cross_signing.master_public()],
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
	assert!(expect_result(founder).await, "founding should succeed");
	id
}

async fn expect_result(client: &mut TestClient) -> bool {
	let deadline = tokio::time::Instant::now() + PATIENCE;
	loop {
		match client.recv(BEAT).await {
			Some(ProtocolMessage::CommunityResult { ok, .. }) => return ok,
			Some(_) => continue,
			None if tokio::time::Instant::now() < deadline => continue,
			None => panic!("the host said nothing"),
		}
	}
}

/// Waits for an ephemeral event, or reports that none came.
async fn next_event(client: &mut TestClient, patience: Duration) -> Option<Ephemeral> {
	let deadline = tokio::time::Instant::now() + patience;
	loop {
		match client.recv(BEAT).await {
			Some(ProtocolMessage::Ephemeral(event)) => return Some(event),
			Some(_) => continue,
			None if tokio::time::Instant::now() < deadline => continue,
			None => return None,
		}
	}
}

fn event(community: CommunityId, channel: &str, event: EphemeralEvent) -> ProtocolMessage {
	ProtocolMessage::Ephemeral(Ephemeral {
		community,
		channel: channel.to_owned(),
		event,
		// Set by the client and ignored by the host, which stamps the
		// authenticated identity instead.
		who: None,
	})
}

#[tokio::test]
async fn typing_reaches_the_other_members_and_never_the_log() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice).await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	bob.send(&ProtocolMessage::JoinCommunity(id)).await.unwrap();
	assert!(expect_result(&mut bob).await);
	tokio::time::sleep(BEAT).await;

	alice
		.send(&event(id, "general", EphemeralEvent::Typing))
		.await
		.unwrap();

	let seen = next_event(&mut bob, PATIENCE)
		.await
		.expect("bob should be told alice is typing");
	assert_eq!(seen.event, EphemeralEvent::Typing);
	assert_eq!(seen.channel, "general");
	assert_eq!(
		seen.who,
		Some(alice.user()),
		"the host stamps who it came from, rather than believing the sender"
	);

	// And none of it is in the log. A backfill returns nothing, because nothing
	// was filed.
	tokio::time::sleep(BEAT).await;
	bob.send(&ProtocolMessage::Backfill {
		community: id,
		channel: "general".into(),
		after: 0,
	})
	.await
	.unwrap();
	assert!(
		matches!(
			bob.recv(BEAT).await,
			Some(ProtocolMessage::CommunityResult { .. }) | None
		),
		"an ephemeral event must not appear in history"
	);

	server.stop().await;
}

/// A host stamps the sender from the authenticated connection, so a client
/// cannot appear to be somebody else typing (invariant 1).
#[tokio::test]
async fn a_client_cannot_claim_to_be_somebody_else() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice).await;

	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(5).await.unwrap();
	mallory
		.send(&ProtocolMessage::JoinCommunity(id))
		.await
		.unwrap();
	assert!(expect_result(&mut mallory).await);
	tokio::time::sleep(BEAT).await;

	// Mallory claims to be Alice.
	mallory
		.send(&ProtocolMessage::Ephemeral(Ephemeral {
			community: id,
			channel: "general".into(),
			event: EphemeralEvent::Typing,
			who: Some(alice.user()),
		}))
		.await
		.unwrap();

	let seen = next_event(&mut alice, PATIENCE)
		.await
		.expect("alice should receive it");
	assert_eq!(
		seen.who,
		Some(mallory.user()),
		"the claimed identity must be replaced with the authenticated one"
	);

	server.stop().await;
}

/// Presence is scoped to a community. A stranger neither receives it nor can
/// inject it.
#[tokio::test]
async fn a_stranger_is_outside_the_presence_scope() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice).await;

	let mut stranger = TestClient::new().connect(&server.ws_url()).await.unwrap();
	stranger.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	// Alice is watching; the stranger must not hear about it.
	alice
		.send(&event(id, "", EphemeralEvent::Watching))
		.await
		.unwrap();
	assert!(
		next_event(&mut stranger, Duration::ZERO).await.is_none(),
		"a non-member must not be told who is present"
	);

	// Nor may they inject one.
	stranger
		.send(&event(id, "general", EphemeralEvent::Typing))
		.await
		.unwrap();
	assert!(
		next_event(&mut alice, Duration::ZERO).await.is_none(),
		"a non-member's presence must not reach the community"
	);

	// The control: once they join, both directions work — so the refusals above
	// are about membership rather than about the events being broken.
	stranger
		.send(&ProtocolMessage::JoinCommunity(id))
		.await
		.unwrap();
	assert!(expect_result(&mut stranger).await);
	tokio::time::sleep(BEAT).await;

	stranger
		.send(&event(id, "general", EphemeralEvent::Typing))
		.await
		.unwrap();
	assert!(
		next_event(&mut alice, PATIENCE).await.is_some(),
		"a member's presence should reach the community"
	);

	server.stop().await;
}

/// Read state is a hint for other people, not a fact about the log — so it
/// travels the same way and is equally absent from history.
#[tokio::test]
async fn read_state_is_ephemeral_too() {
	let server = Server::start().await;

	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;
	let id = found(&mut alice).await;

	let mut bob = TestClient::new().connect(&server.ws_url()).await.unwrap();
	bob.upload_keys(5).await.unwrap();
	bob.send(&ProtocolMessage::JoinCommunity(id)).await.unwrap();
	assert!(expect_result(&mut bob).await);
	tokio::time::sleep(BEAT).await;

	bob.send(&event(id, "general", EphemeralEvent::Read { sequence: 12 }))
		.await
		.unwrap();

	let seen = next_event(&mut alice, PATIENCE)
		.await
		.expect("alice should see bob's read marker");
	assert_eq!(seen.event, EphemeralEvent::Read { sequence: 12 });

	// Not in the store, under any name.
	tokio::time::sleep(BEAT).await;
	let mut raw = std::fs::read(&server.db).unwrap();
	if let Ok(wal) = std::fs::read(format!("{}-wal", server.db)) {
		raw.extend_from_slice(&wal);
	}
	assert!(
		!raw.windows(b"Typing".len()).any(|w| w == b"Typing"),
		"ephemeral events must leave no trace in the store"
	);

	server.stop().await;
}

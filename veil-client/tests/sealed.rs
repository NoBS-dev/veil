//! Sealed communities end to end — `DESIGN.md` §7, §8.4, §8.5.
//!
//! The server tests prove a host files bytes it cannot read. These prove the
//! other half: that two clients can actually *use* a Sealed channel — which
//! needs the reader set to come from signed policy, a Megolm session to be
//! established and delivered per device, and the whole thing to survive the
//! recipient having been offline when the key was issued.
//!
//! The property that matters most here is the one that is easiest to lose in a
//! refactor: **a client that cannot encrypt must refuse to post, never fall
//! back to plaintext.** The mode is inside the community id, so that id is
//! exactly what tells everyone else the content is protected.

mod harness;

use harness::Fixture;
use std::time::Duration;

const LINGER: Duration = Duration::from_secs(5);

/// Drives the whole setup: two users, a Sealed community, a signed reader list.
struct Sealed {
	fixture: Fixture,
	community: String,
	alice_user: String,
	bob_user: String,
}

impl Sealed {
	async fn arrange() -> Self {
		let fixture = Fixture::start().await;
		let server = format!("127.0.0.1:{}", fixture.port);

		// Bob registers first, so his devices are published before Alice names
		// him as a reader — a reader with no verified devices is nobody to
		// encrypt to.
		let bob_output = fixture.run_client(&format!("bob\n{server}\n\n")).await;
		let bob_user = user_of(&bob_output);

		let alice_output = fixture
			.run_client_lingering(
				&format!("alice\n{server}\n\nfound\ns\n"),
				Duration::from_secs(3),
			)
			.await;
		let alice_user = user_of(&alice_output);
		let community = community_of(&alice_output);

		fixture
			.run_client_lingering(&format!("bob\njoin\n{community}\n"), LINGER)
			.await;

		Self {
			fixture,
			community,
			alice_user,
			bob_user,
		}
	}

	/// Signs a `ChannelReaders` record naming both users (§8.5).
	async fn grant_readers(&self) -> String {
		self.fixture
			.run_client_lingering(
				&format!(
					"alice\nreaders\n{}\ngeneral\n{}\n{}\n\n",
					self.community, self.alice_user, self.bob_user
				),
				LINGER,
			)
			.await
	}

	async fn alice_says(&self, text: &str) -> String {
		self.fixture
			.run_client_lingering(
				&format!("alice\nsay\n{}\ngeneral\n{text}\n", self.community),
				LINGER,
			)
			.await
	}

	async fn bob_reads(&self) -> String {
		self.fixture
			.run_client_lingering(
				&format!("bob\nhistory\n{}\ngeneral\n", self.community),
				LINGER,
			)
			.await
	}
}

fn user_of(output: &str) -> String {
	Fixture::address_from(output)
		.split('/')
		.next()
		.expect("an address has a user part")
		.to_owned()
}

fn community_of(output: &str) -> String {
	let start = output
		.find("Community id: ")
		.unwrap_or_else(|| panic!("client should print a community id, got:\n{output}"))
		+ "Community id: ".len();
	output[start..]
		.lines()
		.next()
		.expect("an id on that line")
		.trim()
		.to_owned()
}

#[tokio::test]
async fn a_reader_can_decrypt_a_sealed_channel() {
	let sealed = Sealed::arrange().await;
	sealed.grant_readers().await;

	let alice = sealed.alice_says("the sealed secret").await;
	assert!(
		alice.contains("Distributing"),
		"alice should have established and delivered a session: {alice}"
	);

	// Bob was offline when the key was issued, so it reached him as queued
	// mail — the case that leaves a device permanently unable to read a channel
	// if the mail path only understands DMs.
	let bob = sealed.bob_reads().await;
	assert!(
		bob.contains("key accepted"),
		"bob should have taken the key from his mailbox: {bob}"
	);
	assert!(
		bob.contains("the sealed secret"),
		"bob should have decrypted the message: {bob}"
	);

	// And the host, which carried all of it, holds no plaintext.
	let mut raw = std::fs::read(sealed.fixture.db_path()).unwrap();
	if let Ok(wal) = std::fs::read(format!("{}-wal", sealed.fixture.db_path())) {
		raw.extend_from_slice(&wal);
	}
	assert!(
		!raw.windows(b"the sealed secret".len())
			.any(|w| w == b"the sealed secret"),
		"the host must not hold the plaintext of a Sealed message"
	);

	sealed.fixture.stop().await;
}

/// The sender must be able to read its own channel.
///
/// Megolm is one-way, so this is not automatic: without an inbound copy of its
/// own session, everything a sender posted would come back unreadable to it.
#[tokio::test]
async fn a_sender_can_read_its_own_sealed_messages() {
	let sealed = Sealed::arrange().await;
	sealed.grant_readers().await;
	sealed.alice_says("what i said").await;

	let alice = sealed
		.fixture
		.run_client_lingering(
			&format!("alice\nhistory\n{}\ngeneral\n", sealed.community),
			LINGER,
		)
		.await;

	assert!(
		alice.contains("what i said"),
		"a sender must be able to read its own channel: {alice}"
	);
	assert!(
		!alice.contains("unreadable"),
		"and not see its own message as unreadable: {alice}"
	);

	sealed.fixture.stop().await;
}

/// §8.5: read access is key possession, so the reader set must come from signed
/// policy. Without a `ChannelReaders` record there is nobody to encrypt to —
/// and defaulting to the membership the host reports is precisely the attack,
/// since the host could add itself.
#[tokio::test]
async fn a_sealed_channel_without_a_signed_reader_list_refuses_to_send() {
	let sealed = Sealed::arrange().await;
	// Deliberately no `grant_readers`.

	let alice = sealed.alice_says("should never be sent").await;

	assert!(
		alice.contains("no signed reader list"),
		"posting without signed readers should be refused: {alice}"
	);

	// The refusal must be a refusal, not a fallback: nothing reached the host.
	let bob = sealed.bob_reads().await;
	assert!(
		!bob.contains("should never be sent"),
		"nothing may be sent in the clear under a Sealed id: {bob}"
	);

	let mut raw = std::fs::read(sealed.fixture.db_path()).unwrap();
	if let Ok(wal) = std::fs::read(format!("{}-wal", sealed.fixture.db_path())) {
		raw.extend_from_slice(&wal);
	}
	assert!(
		!raw.windows(b"should never be sent".len())
			.any(|w| w == b"should never be sent"),
		"the plaintext must not have reached the host either"
	);

	sealed.fixture.stop().await;
}

/// A community this device has not verified might be Sealed. Guessing Open
/// would send plaintext under an id that promised otherwise, so not knowing has
/// to be its own answer.
#[tokio::test]
async fn posting_to_an_unverified_community_is_refused() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	// A syntactically valid id this client has never seen.
	let invented = "AAAAAAAAAAAAAAAAAAAAAAAAAA";

	let output = fixture
		.run_client_lingering(
			&format!("stranger\n{server}\n\nsay\n{invented}\ngeneral\nhello\n"),
			Duration::from_secs(3),
		)
		.await;

	assert!(
		output.contains("has not verified"),
		"an unknown community must not be treated as Open: {output}"
	);

	fixture.stop().await;
}

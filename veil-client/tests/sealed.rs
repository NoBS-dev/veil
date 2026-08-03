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
	server: String,
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
			server,
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

	/// Signs a new reader list, replacing the previous one.
	async fn set_readers_to(&self, readers: &[String]) -> String {
		let mut input = format!("alice\nreaders\n{}\ngeneral\n", self.community);
		for reader in readers {
			input.push_str(reader);
			input.push('\n');
		}
		input.push('\n');

		self.fixture.run_client_lingering(&input, LINGER).await
	}

	async fn alice_says(&self, text: &str) -> String {
		self.fixture
			.run_client_lingering(
				&format!("alice\nsay\n{}\ngeneral\n{text}\n", self.community),
				LINGER,
			)
			.await
	}

	/// Registers another user and joins them to the community.
	async fn add_member(&self, profile: &str) -> String {
		let output = self
			.fixture
			.run_client(&format!("{profile}\n{}\n\n", self.server))
			.await;
		let user = user_of(&output);

		self.fixture
			.run_client_lingering(&format!("{profile}\njoin\n{}\n", self.community), LINGER)
			.await;
		user
	}

	async fn read_as(&self, profile: &str) -> String {
		self.fixture
			.run_client_lingering(
				&format!("{profile}\nhistory\n{}\ngeneral\n", self.community),
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

/// §8.3: removing a reader must rotate the key, and the removed reader keeps
/// what they could already read but nothing after.
///
/// Rotation is mandatory on removal — without it the removed device keeps
/// decrypting everything sent afterwards, which makes removal cosmetic. The
/// converse matters too: they do *not* lose history they legitimately held, and
/// pretending otherwise would be a promise the design cannot keep, since they
/// may have kept a copy.
#[tokio::test]
async fn removing_a_reader_locks_them_out_of_what_follows() {
	let sealed = Sealed::arrange().await;
	sealed.grant_readers().await;

	sealed.alice_says("before the removal").await;
	let before = sealed.bob_reads().await;
	assert!(
		before.contains("before the removal"),
		"bob should read what he was a reader for: {before}"
	);

	// Alice signs a new reader list without Bob.
	sealed
		.set_readers_to(std::slice::from_ref(&sealed.alice_user))
		.await;
	sealed.alice_says("after the removal").await;

	let after = sealed.bob_reads().await;
	assert!(
		after.contains("before the removal"),
		"removal is not retroactive; bob keeps what he already had: {after}"
	);
	assert!(
		!after.contains("after the removal"),
		"a removed reader must not decrypt what follows: {after}"
	);

	// The control. Without it this test would pass just as happily if the
	// second message had never been sent, or had been sent to nobody — which
	// would prove nothing about rotation.
	let alice = sealed
		.fixture
		.run_client_lingering(
			&format!("alice\nhistory\n{}\ngeneral\n", sealed.community),
			LINGER,
		)
		.await;
	assert!(
		alice.contains("after the removal"),
		"the message was sent and is readable by a current reader: {alice}"
	);

	sealed.fixture.stop().await;
}

/// The case the broadcast exists for: removal must bind senders *other* than
/// the controller who signed it.
///
/// Alice removes Carol; Bob then sends. Bob derives readership from his own copy
/// of the chain (§8.5), so if that copy never caught up he would keep encrypting
/// to Carol and the removal would be cosmetic for everyone except Alice.
#[tokio::test]
async fn a_removal_binds_other_senders_too() {
	let sealed = Sealed::arrange().await;
	let carol = sealed.add_member("carol").await;

	// All three can read.
	sealed
		.set_readers_to(&[
			sealed.alice_user.clone(),
			sealed.bob_user.clone(),
			carol.clone(),
		])
		.await;
	sealed.alice_says("everyone can see this").await;

	let before = sealed.read_as("carol").await;
	assert!(
		before.contains("everyone can see this"),
		"carol should start as a reader: {before}"
	);

	// Alice removes Carol. Bob is the one who sends next.
	sealed
		.set_readers_to(&[sealed.alice_user.clone(), sealed.bob_user.clone()])
		.await;
	let bob = sealed
		.fixture
		.run_client_lingering(
			&format!(
				"bob\nsay\n{}\ngeneral\nbob speaks after the removal\n",
				sealed.community
			),
			LINGER,
		)
		.await;
	assert!(
		bob.contains("Distributing"),
		"bob should have established his own session for the new readership: {bob}"
	);

	let after = sealed.read_as("carol").await;
	assert!(
		!after.contains("bob speaks after the removal"),
		"a removal must bind every sender, not only the controller who signed it: {after}"
	);

	// Control: Bob's message did get sent, and a current reader can read it.
	let alice = sealed
		.fixture
		.run_client_lingering(
			&format!("alice\nhistory\n{}\ngeneral\n", sealed.community),
			LINGER,
		)
		.await;
	assert!(
		alice.contains("bob speaks after the removal"),
		"the message was sent and is readable by a current reader: {alice}"
	);

	sealed.fixture.stop().await;
}

/// The broadcast, tested where it is the only thing that can help: a member who
/// stays connected across a policy change.
///
/// Bob connects and waits. Alice removes Carol. Bob then sends *without ever
/// reconnecting*, so his connect-time refresh cannot save him — the only way he
/// learns Carol is gone is the host pushing the new chain to every member.
#[tokio::test]
async fn a_connected_member_learns_of_a_removal_without_reconnecting() {
	let sealed = Sealed::arrange().await;
	let carol = sealed.add_member("carol").await;
	sealed
		.set_readers_to(&[
			sealed.alice_user.clone(),
			sealed.bob_user.clone(),
			carol.clone(),
		])
		.await;

	// Bob connects and idles while Alice changes policy underneath him, then
	// sends on the same connection.
	let community = sealed.community.clone();
	let script = [
		("bob\n".to_owned(), Duration::from_secs(12)),
		(
			format!("say\n{community}\ngeneral\nsent while connected\n"),
			Duration::from_secs(6),
		),
	];
	let bob_session = sealed.fixture.run_client_staged(&script);

	let alice_removal = async {
		tokio::time::sleep(Duration::from_secs(5)).await;
		sealed
			.set_readers_to(&[sealed.alice_user.clone(), sealed.bob_user.clone()])
			.await
	};

	let (bob, _) = tokio::join!(bob_session, alice_removal);
	// Two records, not just "verified" — bob's *connect-time* refresh already
	// prints that, so it would pass whether or not the broadcast ever arrived.
	// The second record is the removal, and only the broadcast can have carried
	// it to a session that never reconnected.
	assert!(
		bob.contains("2 policy record(s)"),
		"bob should have been pushed the new chain while connected: {bob}"
	);

	let carol_view = sealed.read_as("carol").await;
	assert!(
		!carol_view.contains("sent while connected"),
		"a member who never reconnected must still honour the removal.\n\
		 carol saw:\n{carol_view}\nbob's session was:\n{bob}"
	);

	let alice = sealed
		.fixture
		.run_client_lingering(
			&format!("alice\nhistory\n{}\ngeneral\n", sealed.community),
			LINGER,
		)
		.await;
	assert!(
		alice.contains("sent while connected"),
		"the message was sent and a current reader can read it: {alice}"
	);

	sealed.fixture.stop().await;
}

/// §10.2: an attachment in a Sealed community is encrypted client-side, and the
/// key travels inside the Megolm-encrypted body — so it never reaches the host.
#[tokio::test]
async fn a_sealed_attachment_keeps_its_key_away_from_the_host() {
	let sealed = Sealed::arrange().await;
	sealed.grant_readers().await;

	let secret = b"the contents of a private document";
	let path = std::env::temp_dir().join(format!("veil-attach-{}.txt", std::process::id()));
	std::fs::write(&path, secret).unwrap();

	let alice = sealed
		.fixture
		.run_client_lingering(
			&format!(
				"alice\nattach\n{}\ngeneral\n{}\n",
				sealed.community,
				path.display()
			),
			LINGER,
		)
		.await;
	assert!(
		alice.contains("encrypted"),
		"a Sealed attachment must be encrypted before upload: {alice}"
	);

	// Bob sees it as an attachment, which means the reference decrypted.
	let bob = sealed.bob_reads().await;
	assert!(
		bob.contains("<file") && bob.contains("encrypted"),
		"bob should see an attachment reference: {bob}"
	);

	// The host holds neither the file nor its key.
	let mut raw = std::fs::read(sealed.fixture.db_path()).unwrap();
	if let Ok(wal) = std::fs::read(format!("{}-wal", sealed.fixture.db_path())) {
		raw.extend_from_slice(&wal);
	}
	assert!(
		!raw.windows(secret.len()).any(|w| w == secret),
		"the host must not hold a Sealed attachment's contents"
	);
	assert!(
		!raw.windows(b"\"key\"".len()).any(|w| w == b"\"key\""),
		"nor the reference carrying its key, which travels inside the Megolm body"
	);

	let _ = std::fs::remove_file(&path);
	sealed.fixture.stop().await;
}

/// The gap §8.5 left open, now visible: a sender working from stale policy is
/// reported to whoever reads the message.
///
/// A host can decline to serve the newest policy record — sequence numbers stop
/// the chain being rewound, not truncated — so a sender could keep encrypting to
/// a device a controller had already removed. Nothing served by one host can
/// prevent that. What every message now carries is the sender's view of policy,
/// inside the encryption where the host cannot strip it, so the discrepancy
/// surfaces instead of passing silently.
#[tokio::test]
async fn a_message_carries_the_senders_view_of_policy() {
	let sealed = Sealed::arrange().await;
	sealed.grant_readers().await;

	// Alice and Bob agree on policy here, so nothing should be flagged. This is
	// the control: a warning that fires always would say nothing.
	sealed.alice_says("while we agree").await;
	let quiet = sealed.bob_reads().await;
	assert!(
		quiet.contains("while we agree"),
		"the message should arrive: {quiet}"
	);
	assert!(
		!quiet.contains("withholding") && !quiet.contains("since removed"),
		"agreeing peers must not be warned about anything: {quiet}"
	);

	// Now policy advances *after* that message was written. Reading it back, Bob
	// is ahead of the head it carries — which is precisely what he would see
	// from a sender whose host had withheld the newest record.
	sealed
		.set_readers_to(&[sealed.alice_user.clone(), sealed.bob_user.clone()])
		.await;

	let bob = sealed.bob_reads().await;
	assert!(
		bob.contains("while we agree"),
		"the message should still arrive: {bob}"
	);
	assert!(
		bob.contains("since removed"),
		"a message written under older policy must be flagged, not passed silently: {bob}"
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

//! Tests against the real `veil-client` binary.
//!
//! These need somewhere to keep profiles that is not the OS keyring, which is
//! what `VEIL_STATE_DIR` is for. That indirection was added to make this
//! possible and turned out to be needed for headless use anyway — a client that
//! requires a Secret Service cannot run in a container either.

mod harness;

use harness::Fixture;
use std::time::{Duration, Instant};

#[tokio::test]
async fn two_clients_exchange_a_message() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	// Bob registers and leaves.
	let bob_output = fixture.run_client(&format!("bob\n{server}\n\n")).await;
	let bob = Fixture::address_from(&bob_output);

	// Alice sends to him while he is away.
	let alice_output = fixture
		.run_client_lingering(
			&format!("alice\n{server}\n\nmsg\n{bob}\nhello over the wire\n"),
			Duration::from_secs(4),
		)
		.await;
	assert!(
		alice_output.contains("My address:"),
		"alice should have connected: {alice_output}"
	);

	// Bob returns and reads it.
	let bob_again = fixture
		.run_client_lingering("bob\n", Duration::from_secs(4))
		.await;
	assert!(
		bob_again.contains("hello over the wire"),
		"bob should have received the message, got: {bob_again}"
	);

	fixture.stop().await;
}

/// A profile is written once and reused, so the same identity comes back.
#[tokio::test]
async fn a_profile_persists_across_runs() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let first = fixture.run_client(&format!("carol\n{server}\n\n")).await;
	let second = fixture.run_client("carol\n").await;

	assert_eq!(
		Fixture::address_from(&first),
		Fixture::address_from(&second),
		"the same profile must produce the same identity"
	);
	assert!(
		second.contains("Prior state found"),
		"the second run should have loaded the stored profile"
	);

	fixture.stop().await;
}

/// The audit finding: a client must not open a session with a device the peer's
/// own cross-signing does not vouch for, however the host answers.
#[tokio::test]
async fn a_client_refuses_a_device_the_peer_never_enrolled() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let bob_output = fixture.run_client(&format!("dave\n{server}\n\n")).await;
	let bob = Fixture::address_from(&bob_output);
	let user = bob.split('/').next().unwrap();

	// Same user, a device id they never published.
	let invented = format!("{user}/AAAAAAAAAAAAAAAAAAAAAAAAAA");
	let output = fixture
		.run_client(&format!(
			"erin\n{server}\n\nmsg\n{invented}\nshould not send\n"
		))
		.await;

	assert!(
		output.contains("not in") && output.contains("verified device list"),
		"the client should refuse an unvouched device, got: {output}"
	);

	fixture.stop().await;
}

/// Verification is per person, and the client says which of the two questions
/// it is answering (§5.4).
#[tokio::test]
async fn an_unverified_peer_is_flagged_when_sending() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let bob_output = fixture.run_client(&format!("frank\n{server}\n\n")).await;
	let bob = Fixture::address_from(&bob_output);

	let output = fixture
		.run_client(&format!("grace\n{server}\n\nmsg\n{bob}\nhi\n"))
		.await;

	assert!(
		output.contains("is not verified"),
		"sending to an unverified person should say so: {output}"
	);
	assert!(
		output.contains("device is genuinely theirs"),
		"and should distinguish that from the device being fake: {output}"
	);

	fixture.stop().await;
}

/// A client whose stdin closes must exit rather than spinning. This was a real
/// bug: `read_line` returns `Ok(0)` at EOF, which `?` does not catch, so the
/// loop ran flat out printing the command list.
#[tokio::test]
async fn a_client_exits_when_its_input_closes() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let started = Instant::now();
	let output = fixture.run_client(&format!("heidi\n{server}\n\n")).await;
	let elapsed = started.elapsed();

	assert!(
		elapsed < Duration::from_secs(40),
		"the client should exit promptly on EOF, took {elapsed:?}"
	);
	assert!(
		output.contains("Input closed"),
		"the client should say why it stopped: {output}"
	);
	assert!(
		output.len() < 100_000,
		"a spinning loop would have produced far more than {} bytes of output",
		output.len()
	);

	fixture.stop().await;
}

//! Invites and first contact — `DESIGN.md` §3.2.
//!
//! Pinning protects every connection after the first. On the first there is
//! nothing to compare against, so a relay could send a newcomer to a *different
//! genuine Veil host* — and because that host is real, every check afterwards
//! would pass, against the wrong server.
//!
//! Nothing about the connection can close that, because the newcomer has no
//! prior knowledge. The fix comes from outside it: invites travel as links and
//! QR codes, so the invite carries the host's identity key and the client
//! refuses a host that does not sign with it.

mod harness;

use harness::Fixture;
use std::time::Duration;

const LINGER: Duration = Duration::from_secs(3);

/// Founds a community and returns the invite the client printed for it.
async fn invite_from(fixture: &Fixture, server: &str) -> String {
	let output = fixture
		.run_client_lingering(&format!("host\n{server}\n\nfound\no\n"), LINGER)
		.await;

	let start = output
		.find("Invite: ")
		.unwrap_or_else(|| panic!("the client should print an invite, got:\n{output}"))
		+ "Invite: ".len();
	output[start..]
		.lines()
		.next()
		.expect("an invite on that line")
		.trim()
		.to_owned()
}

#[tokio::test]
async fn an_invite_names_the_host_that_issued_it() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);
	let invite = invite_from(&fixture, &server).await;

	let output = fixture
		.run_client_lingering(&format!("guest\n{invite}\n\n"), LINGER)
		.await;

	assert!(
		output.contains("matches the invite"),
		"an honest invite should be confirmed against the host: {output}"
	);
	assert!(
		output.contains("Speaking protocol"),
		"and the connection should proceed: {output}"
	);

	fixture.stop().await;
}

/// The attack: something between the client and the host substitutes a
/// different destination. It is a real Veil server, so it completes a real
/// handshake — and would be pinned as though it were the intended one.
#[tokio::test]
async fn an_invite_pointed_at_a_different_host_is_refused() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);
	let elsewhere = fixture.start_server().await;

	let invite = invite_from(&fixture, &server).await;
	// Same community, same key, different destination.
	let diverted = invite.replace(&server, &elsewhere);
	assert_ne!(diverted, invite, "the test should have changed the host");

	let output = fixture
		.run_client_lingering(&format!("diverted\n{diverted}\n\n"), LINGER)
		.await;

	assert!(
		output.contains("but the invite named"),
		"a host that does not match the invite must be refused: {output}"
	);
	assert!(
		!output.contains("Speaking protocol"),
		"and nothing should be spoken to it: {output}"
	);

	fixture.stop().await;
}

/// Connecting without an invite still works — it is the weaker position, and
/// the client says so rather than implying the two are equivalent.
#[tokio::test]
async fn connecting_without_an_invite_says_what_it_is_trusting() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let output = fixture
		.run_client_lingering(&format!("bare\n{server}\n\n"), LINGER)
		.await;

	assert!(
		output.contains("on trust") && output.contains("An invite would have"),
		"a blind pin should be named as one: {output}"
	);
	assert!(
		output.contains("Speaking protocol"),
		"but it must still work — §3.5 wants a stranded user to have a way through: {output}"
	);

	fixture.stop().await;
}

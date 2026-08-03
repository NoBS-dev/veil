//! Finding people, end to end — `DESIGN.md` §11.6.
//!
//! The three layers have to stay distinct, and the tests are about the seam
//! between them: a link carries the whole identity so nothing can be
//! substituted, while a typed address is resolved by a server that could lie —
//! so what it returns is pinned, and a change is never absorbed silently.

mod harness;

use harness::Fixture;
use std::time::Duration;

const LINGER: Duration = Duration::from_secs(3);

#[allow(dead_code)]
fn field(output: &str, prefix: &str) -> String {
	let start = output
		.find(prefix)
		.unwrap_or_else(|| panic!("expected {prefix:?} in:\n{output}"))
		+ prefix.len();
	output[start..]
		.lines()
		.next()
		.expect("a value on that line")
		.trim()
		.to_owned()
}

#[tokio::test]
async fn an_alias_resolves_to_the_identity_that_claimed_it() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let claimed = fixture
		.run_client_lingering(&format!("alice\n{server}\n\nalias\nalice\n"), LINGER)
		.await;
	let alice = Fixture::address_from(&claimed)
		.split('/')
		.next()
		.unwrap()
		.to_owned();

	let looked_up = fixture
		.run_client_lingering(
			&format!("bob\n{server}\n\nlookup\nalice@{server}\n"),
			LINGER,
		)
		.await;

	assert!(
		looked_up.contains(&alice),
		"the alias should resolve to alice's identity: {looked_up}"
	);
	assert!(
		looked_up.contains("a name is not an identity"),
		"and should say what it is worth: {looked_up}"
	);

	fixture.stop().await;
}

/// Two names resolve to two people, which is the ordinary case the pin sits
/// behind.
///
/// The pin *changing* cannot be produced from here: a claim is first come first
/// served, so a host will not hand the same alias to somebody else on request.
/// Reassignment is an operator action this server does not expose, and faking it
/// through two different addresses would only prove that two addresses pin
/// separately. The pin itself is tested directly in `state.rs`.
#[tokio::test]
async fn separate_aliases_resolve_to_separate_people() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let alice_out = fixture
		.run_client_lingering(&format!("alice\n{server}\n\nalias\nalice\n"), LINGER)
		.await;
	let carol_out = fixture
		.run_client_lingering(&format!("carol\n{server}\n\nalias\ncarol\n"), LINGER)
		.await;

	let alice = Fixture::address_from(&alice_out)
		.split('/')
		.next()
		.unwrap()
		.to_owned();
	let carol = Fixture::address_from(&carol_out)
		.split('/')
		.next()
		.unwrap()
		.to_owned();
	assert_ne!(alice, carol);

	let looked_up = fixture
		.run_client_lingering(
			&format!("bob\n{server}\n\nlookup\nalice@{server}\nlookup\ncarol@{server}\n"),
			LINGER,
		)
		.await;

	assert!(
		looked_up.contains(&alice),
		"alice should resolve: {looked_up}"
	);
	assert!(
		looked_up.contains(&carol),
		"carol should resolve: {looked_up}"
	);

	fixture.stop().await;
}

/// An alias is first come, first served — a second claimant does not take it.
///
/// Without this the name is not even a stable convenience: whoever claimed it
/// most recently would own it, and every client that had pinned the previous
/// holder would see the change as a possible impersonation.
#[tokio::test]
async fn a_claimed_alias_is_not_taken_by_the_next_claimant() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let first = fixture
		.run_client_lingering(&format!("early\n{server}\n\nalias\ncontested\n"), LINGER)
		.await;
	let owner = Fixture::address_from(&first)
		.split('/')
		.next()
		.unwrap()
		.to_owned();

	let second = fixture
		.run_client_lingering(&format!("late\n{server}\n\nalias\ncontested\n"), LINGER)
		.await;
	let latecomer = Fixture::address_from(&second)
		.split('/')
		.next()
		.unwrap()
		.to_owned();
	assert_ne!(owner, latecomer);

	let looked_up = fixture
		.run_client_lingering(
			&format!("onlooker\n{server}\n\nlookup\ncontested@{server}\n"),
			LINGER,
		)
		.await;

	assert!(
		looked_up.contains(&owner),
		"the first claimant should still hold it: {looked_up}"
	);
	assert!(
		!looked_up.contains(&latecomer),
		"a second claim must not take an alias: {looked_up}"
	);

	fixture.stop().await;
}

/// A contact link needs no lookup, so there is nothing for a host to falsify.
#[tokio::test]
async fn a_contact_link_needs_no_lookup() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let output = fixture
		.run_client_lingering(&format!("dave\n{server}\n\ncontact\n"), LINGER)
		.await;

	let link = field(&output, "veil-user:");
	let user = Fixture::address_from(&output)
		.split('/')
		.next()
		.unwrap()
		.to_owned();

	assert!(
		link.starts_with(&user),
		"the link should carry the identity itself, not a name: veil-user:{link}"
	);

	// And taking that link asks nobody anything, which is the property.
	let taken = fixture
		.run_client_lingering(
			&format!("erin\n{server}\n\nlookup\nveil-user:{link}\n"),
			LINGER,
		)
		.await;
	assert!(
		taken.contains("no server was asked"),
		"a link must resolve without a lookup: {taken}"
	);
	assert!(
		taken.contains(&user),
		"and yield the identity it carries: {taken}"
	);

	fixture.stop().await;
}

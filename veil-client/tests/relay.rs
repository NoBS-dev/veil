//! Nested TLS through a relay, end to end — `DESIGN.md` §3.2.
//!
//! ```text
//! client ──TLS──► home server ──TCP──► community host
//!        └──────────── TLS ─────────────────┘
//! ```
//!
//! This is the test the relay's framing check leans on. `veil-server`'s relay
//! tests prove the refusals — a tunnel to a web server, a tunnel carrying
//! something that is not TLS — but a refusal test passes just as happily
//! against a relay that refuses everything. This is the control: a real client
//! reaching a real host through a real relay, with a genuine TLS session
//! running end to end inside the tunnel.
//!
//! The destination uses a **self-signed** certificate on purpose. §1.3 requires
//! that one person on a domestic connection can host a community, and demanding
//! a certificate authority would quietly make that impossible. What keeps it
//! safe is the binding: the host signs a hash of its own certificate into the
//! challenge, so a relay that terminated the inner session with a certificate of
//! its own would be caught.

mod harness;

use harness::Fixture;
use std::time::Duration;

#[tokio::test]
async fn a_message_survives_a_nested_tls_tunnel() {
	let fixture = Fixture::start().await;
	let (destination, _) = fixture.start_tls_server().await;
	let relay = fixture.start_server().await;

	// Bob lives on the destination and connects to it directly.
	let bob_output = fixture
		.run_client(&format!("bob-tunnel\nwss://{destination}\n\n"))
		.await;
	let bob = Fixture::address_from(&bob_output);

	// Alice reaches the same host through the relay. From the host's point of
	// view she is an ordinary client; from the relay's, opaque bytes.
	let alice = fixture
		.run_client_lingering(
			&format!(
				"alice-tunnel\nwss://{destination}\n{relay}\nmsg\n{bob}\nthrough the tunnel\n"
			),
			Duration::from_secs(5),
		)
		.await;

	assert!(
		alice.contains("end-to-end encrypted"),
		"alice should have built a nested TLS session: {alice}"
	);
	assert!(
		!alice.contains("terminating TLS in the middle"),
		"the destination's own certificate must satisfy its own binding: {alice}"
	);

	let bob_again = fixture
		.run_client_lingering("bob-tunnel\n", Duration::from_secs(5))
		.await;
	assert!(
		bob_again.contains("through the tunnel"),
		"the message should have crossed the tunnel, got: {bob_again}"
	);

	fixture.stop().await;
}

/// The attack the binding exists to stop: the relay terminates the inner TLS
/// session and reads everything.
///
/// The relay here is correct at every layer the client could otherwise check.
/// It authenticates the user, it forwards to the host that was actually asked
/// for, and the Veil handshake the client completes is with the genuine
/// destination — signed by the destination's own key. The only thing wrong is
/// that the relay is inside the TLS session.
///
/// That is caught because the destination signs a hash of *its* certificate into
/// the challenge, and the relay had to present one of its own.
#[tokio::test]
async fn a_relay_that_terminates_the_inner_tls_is_caught() {
	let fixture = Fixture::start().await;
	let (destination, _) = fixture.start_tls_server().await;
	let relay = fixture.start_mitm_relay(&destination).await;

	let output = fixture
		.run_client_lingering(
			&format!("mitm\nwss://{destination}\n{relay}\n"),
			Duration::from_secs(4),
		)
		.await;

	assert!(
		output.contains("terminating TLS in the middle"),
		"a relay inside the TLS session must be caught, got: {output}"
	);
	assert!(
		!output.contains("Speaking protocol"),
		"the session must be refused before any protocol traffic: {output}"
	);

	fixture.stop().await;
}

/// The control for the test above: the same client, the same self-signed
/// destination, through an *honest* relay. Without this, "the client refused"
/// would be satisfied by a client that refused every relayed connection.
#[tokio::test]
async fn an_honest_relay_to_the_same_host_is_accepted() {
	let fixture = Fixture::start().await;
	let (destination, _) = fixture.start_tls_server().await;
	let relay = fixture.start_server().await;

	let output = fixture
		.run_client_lingering(
			&format!("honest\nwss://{destination}\n{relay}\n"),
			Duration::from_secs(4),
		)
		.await;

	assert!(
		output.contains("Speaking protocol"),
		"an honest relay must carry the session through: {output}"
	);
	assert!(
		!output.contains("terminating TLS in the middle"),
		"the destination's own certificate satisfies its own binding: {output}"
	);

	fixture.stop().await;
}

/// A relayed connection to a plaintext host cannot be private, and saying so is
/// better than tunnelling to it and implying otherwise.
#[tokio::test]
async fn a_relayed_connection_to_a_plaintext_host_is_refused() {
	let fixture = Fixture::start().await;
	let destination = fixture.start_server().await;
	let relay = fixture.start_server().await;

	let output = fixture
		.run_client_lingering(
			&format!("plaintext-dest\nwss://{destination}\n{relay}\n"),
			Duration::from_secs(3),
		)
		.await;

	assert!(
		!output.contains("My address:") || output.contains("cannot be private"),
		"a relayed tunnel to a plaintext host should not silently proceed: {output}"
	);

	fixture.stop().await;
}

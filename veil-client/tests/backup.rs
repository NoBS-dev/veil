//! Key backup and restore — `DESIGN.md` §12.5.
//!
//! Losing every device at once is the case this exists for, so restoring runs on
//! a device that has nothing: the credentials it would authenticate with are
//! inside the backup. That is why the blob is fetchable by user id, and why the
//! recovery key has to be random rather than derived from a passphrase —
//! whoever holds the blob can attack it offline at their leisure.

mod harness;

use harness::Fixture;
use std::time::Duration;

const LINGER: Duration = Duration::from_secs(3);

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
async fn an_identity_survives_losing_every_device() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let made = fixture
		.run_client_lingering(&format!("alice\n{server}\n\nbackup\n"), LINGER)
		.await;
	let user = Fixture::address_from(&made)
		.split('/')
		.next()
		.unwrap()
		.to_owned();
	let recovery = field(&made, "Recovery key: ");
	assert!(
		recovery.contains('-'),
		"the key should be grouped for writing down: {recovery}"
	);

	// A different profile is a device that has nothing — which is what a person
	// who lost everything actually has.
	let restored = fixture
		.run_client_lingering(
			&format!("newdevice\n{server}\n\nrestore\n{user}\n{recovery}\n"),
			LINGER,
		)
		.await;

	assert!(
		restored.contains(&format!("Restored {user}")),
		"the identity should come back: {restored}"
	);
	assert!(
		restored.contains("new device id"),
		"and should say it is a new device rather than the old one: {restored}"
	);

	fixture.stop().await;
}

/// The recovery key is the only thing between the blob and whoever fetches it.
#[tokio::test]
async fn the_wrong_recovery_key_restores_nothing() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let made = fixture
		.run_client_lingering(&format!("bob\n{server}\n\nbackup\n"), LINGER)
		.await;
	let user = Fixture::address_from(&made)
		.split('/')
		.next()
		.unwrap()
		.to_owned();

	// A well-formed key that is not the right one.
	let wrong = "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA";
	let attempt = fixture
		.run_client_lingering(
			&format!("thief\n{server}\n\nrestore\n{user}\n{wrong}\n"),
			LINGER,
		)
		.await;

	assert!(
		!attempt.contains(&format!("Restored {user}")),
		"a wrong key must not restore the identity: {attempt}"
	);

	fixture.stop().await;
}

/// The host stores something it cannot open. A host that could would be able to
/// impersonate its user and read every Sealed community they are in.
#[tokio::test]
async fn the_host_cannot_read_what_it_stores() {
	let fixture = Fixture::start().await;
	let server = format!("127.0.0.1:{}", fixture.port);

	let made = fixture
		.run_client_lingering(&format!("carol\n{server}\n\nbackup\n"), LINGER)
		.await;
	let recovery = field(&made, "Recovery key: ");

	let mut raw = std::fs::read(fixture.db_path()).unwrap();
	if let Ok(wal) = std::fs::read(format!("{}-wal", fixture.db_path())) {
		raw.extend_from_slice(&wal);
	}

	// The recovery key never reaches the host at all, and neither does anything
	// it protects.
	let bare: String = recovery.chars().filter(|c| *c != '-').collect();
	assert!(
		!raw.windows(bare.len()).any(|w| w == bare.as_bytes()),
		"the recovery key must never reach the host"
	);
	// `cross_signing` is `BackupPayload`'s own field name, so it appears only if
	// the payload were stored unsealed. Checking for "master" instead would find
	// the *public* key directory, which legitimately has a field by that name —
	// a test that passed on that would be measuring the wrong table.
	assert!(
		!raw.windows(b"cross_signing".len())
			.any(|w| w == b"cross_signing"),
		"the backup payload must be sealed, not stored as it is"
	);

	fixture.stop().await;
}

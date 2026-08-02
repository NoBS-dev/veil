//! Server-to-server DM delivery — `DESIGN.md` §3.3–3.4.
//!
//! Every other test in this suite puts both parties on one server, which means
//! the premise the whole architecture rests on — that you can reach anyone
//! without federation — had never actually been run. These are the first tests
//! where a message crosses a server boundary.
//!
//! Two servers, two clients, one on each. Alice hands her message to her own
//! server; it opens a connection to Bob's and deposits; Bob collects it from
//! his own mailbox and never speaks to Alice's server at all.

mod harness;

use harness::{Server, TestClient, prekey_bundle};
use std::time::Duration;
use veil_protocol::{
	Deposit, DepositResult, Envelope, ProtocolMessage, ServerAuthenticate,
	identity::{DeviceAddress, DeviceId},
	open_envelope,
	version::VersionRange,
};

const BEAT: Duration = Duration::from_millis(1500);
/// Delivery is retried on a timer, so a failed first attempt needs longer.
const RETRY_BEAT: Duration = Duration::from_secs(8);

/// Registers a client against a server and leaves, so the server holds their
/// keys and knows them as a local user.
async fn resident(server: &Server, otks: usize) -> (harness::PendingClient, DeviceAddress) {
	let identity = TestClient::new();
	let address = identity.address();
	let mut session = identity.connect(&server.ws_url()).await.unwrap();
	session.upload_keys(otks).await.unwrap();
	tokio::time::sleep(BEAT).await;
	(session.disconnect(), address)
}

#[tokio::test]
async fn a_message_crosses_a_server_boundary() {
	let alice_home = Server::start().await;
	let bob_home = Server::start().await;

	let (bob, bob_address) = resident(&bob_home, 10).await;

	// Alice looks Bob up through *her own* server's proxy, which is what keeps
	// her IP away from his host (§3.4). The bundle still has to match what his
	// cross-signing vouches for, and that check is the client's, not ours.
	let (_, bob_x25519, otk) = prekey_bundle(&bob_home.http_url(), &bob_address)
		.await
		.unwrap();

	let mut alice = TestClient::new()
		.connect(&alice_home.ws_url())
		.await
		.unwrap();
	alice.upload_keys(10).await.unwrap();
	alice
		.send_to_host(
			bob_address,
			&bob_home.address(),
			bob_x25519,
			otk,
			"across the boundary",
		)
		.await
		.unwrap();
	tokio::time::sleep(RETRY_BEAT).await;

	// Bob collects from his own server. He has never spoken to Alice's.
	let mut bob = bob.connect(&bob_home.ws_url()).await.unwrap();
	let mail = bob.collect_mail(BEAT).await;
	assert_eq!(mail, vec!["across the boundary".to_owned()]);

	alice_home.stop().await;
	bob_home.stop().await;
}

/// §3.4: the sending server owns delivery, and retries if the destination is
/// down. Before this, a message to an unreachable server was simply lost.
#[tokio::test]
async fn mail_waits_for_a_server_that_is_down() {
	let alice_home = Server::start().await;
	let bob_home = Server::start().await;
	let bob_db = bob_home.db.clone();
	let bob_url = bob_home.address();

	let (bob, bob_address) = resident(&bob_home, 10).await;
	let (_, bob_x25519, otk) = prekey_bundle(&bob_home.http_url(), &bob_address)
		.await
		.unwrap();

	// Bob's server goes away, keeping its database.
	bob_home.stop_keeping_data().await;
	tokio::time::sleep(BEAT).await;

	let mut alice = TestClient::new()
		.connect(&alice_home.ws_url())
		.await
		.unwrap();
	alice.upload_keys(10).await.unwrap();
	alice
		.send_to_host(
			bob_address,
			&bob_url,
			bob_x25519,
			otk,
			"sent to a dead host",
		)
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	// It comes back on the same address and database.
	let bob_home = Server::start_at(&bob_url, Some(bob_db.clone())).await;
	tokio::time::sleep(RETRY_BEAT).await;

	let mut bob = bob.connect(&bob_home.ws_url()).await.unwrap();
	let mail = bob.collect_mail(RETRY_BEAT).await;
	assert_eq!(
		mail,
		vec!["sent to a dead host".to_owned()],
		"mail for an unreachable server must be retried, not dropped"
	);

	alice_home.stop().await;
	bob_home.stop_keeping_data().await;
	Server::discard(&bob_db);
}

/// A deposit is terminal (§3.3). A server that accepted mail for a stranger and
/// forwarded it onward would be an open relay, and two servers each believing
/// the other is home would loop between them.
#[tokio::test]
async fn a_deposit_for_a_stranger_is_refused_not_forwarded() {
	let server = Server::start().await;

	// A user this server has never seen.
	let stranger = DeviceAddress::new(TestClient::new().user(), DeviceId::generate());

	let result = deposit_to(&server, stranger, "not yours to hold").await;

	assert!(
		matches!(result, DepositResult::Refused(ref why) if why.contains("not a user of this server")),
		"expected a permanent refusal, got {result:?}"
	);

	server.stop().await;
}

/// The forwarding server carries bytes; it does not get to author them. An
/// altered envelope fails the *sender's* signature, which the forwarder cannot
/// produce (invariant 2).
#[tokio::test]
async fn a_tampered_deposit_is_refused() {
	let server = Server::start().await;
	let (_, resident_address) = resident(&server, 5).await;

	let mut peer = ServerPeer::connect(&server).await;
	let inner = peer.compose_inner(resident_address, "the original");

	// Flip a byte of the sender's envelope, as a hostile forwarder would.
	let mut tampered = inner.clone();
	let last = tampered.len() - 1;
	tampered[last] ^= 1;

	let result = peer.deposit(tampered).await;
	assert!(
		matches!(result, DepositResult::Refused(ref why) if why.contains("inner envelope")),
		"a modified envelope must not be filed, got {result:?}"
	);

	server.stop().await;
}

/// The same pinning as a client connection (invariant 5): a server may only
/// deposit envelopes it signed itself, not ones signed by some other server.
#[tokio::test]
async fn a_deposit_signed_by_a_different_server_is_refused() {
	let server = Server::start().await;
	let (_, resident_address) = resident(&server, 5).await;

	let mut peer = ServerPeer::connect(&server).await;
	let inner = peer.compose_inner(resident_address, "signed by someone else");

	// A second server's key seals the deposit, but the first server's
	// connection carries it.
	let impostor = vodozemac::olm::Account::new();
	let framed = Envelope::seal(
		&ProtocolMessage::Deposit(Deposit { envelope: inner }),
		&impostor,
	)
	.unwrap()
	.to_vec();

	let result = peer.send_raw_deposit(framed).await;
	assert!(
		matches!(result, DepositResult::Refused(ref why) if why.contains("different server")),
		"a deposit signed by another key must be refused, got {result:?}"
	);

	server.stop().await;
}

/// A client must not be able to deposit into a mailbox directly. That is the
/// unrate-limitable spam vector §3.4 exists to close: deposits arrive from a
/// server with standing, never from any client that opens a socket.
#[tokio::test]
async fn a_client_cannot_deposit_on_the_client_endpoint() {
	let server = Server::start().await;
	let (victim, victim_address) = resident(&server, 5).await;

	// The *same* envelope is used twice, which is what makes this test mean
	// anything. Offered on the client connection it must be ignored; offered on
	// the deposit endpoint it is accepted. Without the second half, an empty
	// mailbox would prove only that the frame was malformed.
	let inner = harness::compose_offline(victim_address, "deposited by a client");

	let mut mallory = TestClient::new().connect(&server.ws_url()).await.unwrap();
	mallory.upload_keys(5).await.unwrap();
	mallory
		.send(&ProtocolMessage::Deposit(Deposit {
			envelope: inner.clone(),
		}))
		.await
		.unwrap();
	tokio::time::sleep(BEAT).await;

	{
		let mut victim = victim.connect(&server.ws_url()).await.unwrap();
		assert!(
			victim.peek_mail(BEAT).await.is_empty(),
			"a client's deposit must never reach a mailbox"
		);
		victim.disconnect();
	}
	tokio::time::sleep(BEAT).await;

	// The control: the identical envelope, through the endpoint meant for it.
	let mut peer = ServerPeer::connect(&server).await;
	assert_eq!(
		peer.deposit(inner).await,
		DepositResult::Accepted,
		"the same envelope must be accepted server-to-server, or the test above \
		 proves only that it was malformed"
	);

	server.stop().await;
}

// ---- a minimal server-shaped peer -----------------------------------------

/// Speaks the deposit side of §3.4 directly, so a test can present exactly the
/// frame it wants rather than going through a second real server.
struct ServerPeer {
	socket: tokio_tungstenite::WebSocketStream<
		tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
	>,
	account: vodozemac::olm::Account,
}

impl ServerPeer {
	async fn connect(server: &Server) -> Self {
		use futures::{SinkExt, StreamExt};
		use tokio_tungstenite::tungstenite::Message;

		let account = vodozemac::olm::Account::new();
		let (mut socket, _) = tokio_tungstenite::connect_async(format!(
			"{}/s2s",
			server.ws_url().trim_end_matches('/')
		))
		.await
		.unwrap();

		let Some(Ok(Message::Binary(bytes))) = socket.next().await else {
			panic!("server did not open with a challenge");
		};
		let opened = open_envelope(&bytes).unwrap();
		let ProtocolMessage::Challenge(challenge) = opened.message else {
			panic!("server did not open with a challenge");
		};

		let auth = Envelope::seal(
			&ProtocolMessage::ServerAuthenticate(ServerAuthenticate {
				challenge: challenge.challenge,
				versions: VersionRange::supported(),
				server_versions_seen: challenge.versions,
			}),
			&account,
		)
		.unwrap();
		socket
			.send(Message::Binary(auth.to_vec().into()))
			.await
			.unwrap();

		Self { socket, account }
	}

	/// A sender's envelope, as a real client would have signed it.
	///
	/// Composed offline: the deposit path never needs the sender to be
	/// connected anywhere, which is the whole point of store-and-forward.
	fn compose_inner(&mut self, recipient: DeviceAddress, text: &str) -> Vec<u8> {
		harness::compose_offline(recipient, text)
	}

	async fn deposit(&mut self, envelope: Vec<u8>) -> DepositResult {
		let framed = Envelope::seal(
			&ProtocolMessage::Deposit(Deposit { envelope }),
			&self.account,
		)
		.unwrap()
		.to_vec();
		self.send_raw_deposit(framed).await
	}

	async fn send_raw_deposit(&mut self, framed: Vec<u8>) -> DepositResult {
		use futures::{SinkExt, StreamExt};
		use tokio_tungstenite::tungstenite::Message;

		self.socket
			.send(Message::Binary(framed.into()))
			.await
			.unwrap();

		let reply = tokio::time::timeout(BEAT, self.socket.next())
			.await
			.expect("server should answer a deposit");

		let Some(Ok(Message::Binary(bytes))) = reply else {
			panic!("server did not answer with a binary frame");
		};
		let opened = open_envelope(&bytes).unwrap();
		let ProtocolMessage::DepositResult(result) = opened.message else {
			panic!("server did not answer with a deposit result");
		};
		result
	}
}

/// Deposits one message through a throwaway server identity.
async fn deposit_to(server: &Server, recipient: DeviceAddress, text: &str) -> DepositResult {
	let mut peer = ServerPeer::connect(server).await;
	let inner = peer.compose_inner(recipient, text);
	peer.deposit(inner).await
}

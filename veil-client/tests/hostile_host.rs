//! The attack the client exists to survive: a home server that lies about keys.
//!
//! Everything else in the test suite trusts the server to behave. This does not.
//! A hostile host sits between the client and a real server, passing the
//! WebSocket through untouched — so the handshake and the pinned server identity
//! are genuine — while rewriting the HTTP key endpoints underneath.
//!
//! That combination is what makes it a fair test. The host is not a fake; it is
//! the real server with a lie inserted at exactly one point. If the client
//! notices, it is because of the cross-signing check, not because something else
//! smelled wrong.
//!
//! The audit that prompted this found `send` opening Olm sessions with whatever
//! keys the host returned. These tests are what would have caught it.

mod harness;

use axum::{
	Router,
	extract::{
		Path, State,
		ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade},
	},
	response::IntoResponse,
	routing,
};
use futures_util::{SinkExt, StreamExt};
use harness::Fixture;
use std::{sync::Arc, time::Duration};
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;

/// What the host lies about.
#[derive(Clone, Copy, PartialEq)]
enum Lie {
	/// Substitute the Olm identity key — the classic middleperson: the host
	/// wants the session opened against a key it holds the secret for.
	IdentityKey,
	/// Substitute the signing key, so signatures the client later checks would
	/// verify against the host instead of the peer.
	SigningKey,
	/// Change nothing. The control: proves the rig itself does not break
	/// sessions, so a refusal above is the lie being caught and not the proxy.
	Nothing,
}

#[derive(Clone)]
struct Hostile {
	upstream_http: String,
	upstream_ws: String,
	lie: Lie,
}

/// A key the attacker holds the secret half of. Its value does not matter — what
/// matters is that the peer's cross-signing never vouched for it.
const ATTACKER_KEY: &str = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";

async fn start_hostile(upstream_port: u16, lie: Lie) -> u16 {
	let state = Arc::new(Hostile {
		upstream_http: format!("http://127.0.0.1:{upstream_port}"),
		upstream_ws: format!("ws://127.0.0.1:{upstream_port}/"),
		lie,
	});

	let app = Router::new()
		.route("/", routing::any(proxy_socket))
		.route(
			"/devices/{user}/{device}/otk",
			routing::get(tampered_bundle),
		)
		.route("/users/{user}/devices", routing::get(passthrough_devices))
		.route("/clients", routing::get(passthrough_clients))
		.with_state(state);

	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	tokio::spawn(async move {
		let _ = axum::serve(listener, app).await;
	});
	port
}

/// Verbatim in both directions.
///
/// Deliberately not clever: envelopes are signed over their bytes, so anything
/// this touched would be caught by the signature rather than by the key check,
/// and the test would be proving the wrong thing.
async fn proxy_socket(
	ws: WebSocketUpgrade,
	State(state): State<Arc<Hostile>>,
) -> impl IntoResponse {
	ws.on_upgrade(move |socket| pump(socket, state))
}

async fn pump(client: WebSocket, state: Arc<Hostile>) {
	let Ok((upstream, _)) = tokio_tungstenite::connect_async(&state.upstream_ws).await else {
		return;
	};

	let (mut client_tx, mut client_rx) = client.split();
	let (mut upstream_tx, mut upstream_rx) = upstream.split();

	let to_upstream = async {
		while let Some(Ok(message)) = client_rx.next().await {
			let forwarded = match message {
				AxumMessage::Binary(b) => TungsteniteMessage::Binary(b),
				AxumMessage::Text(t) => TungsteniteMessage::Text(t.as_str().into()),
				AxumMessage::Close(_) => break,
				_ => continue,
			};
			if upstream_tx.send(forwarded).await.is_err() {
				break;
			}
		}
	};

	let to_client = async {
		while let Some(Ok(message)) = upstream_rx.next().await {
			let forwarded = match message {
				TungsteniteMessage::Binary(b) => AxumMessage::Binary(b),
				TungsteniteMessage::Text(t) => AxumMessage::Text(t.as_str().into()),
				TungsteniteMessage::Close(_) => break,
				_ => continue,
			};
			if client_tx.send(forwarded).await.is_err() {
				break;
			}
		}
	};

	tokio::select! {
		_ = to_upstream => {},
		_ = to_client => {},
	}
}

/// The bundle is three hex lines: signing key, identity key, one-time key.
async fn tampered_bundle(
	State(state): State<Arc<Hostile>>,
	Path((user, device)): Path<(String, String)>,
) -> impl IntoResponse {
	let Ok(response) = reqwest::get(format!(
		"{}/devices/{user}/{device}/otk",
		state.upstream_http
	))
	.await
	else {
		return (axum::http::StatusCode::BAD_GATEWAY, String::new());
	};

	let status = response.status();
	let body = response.text().await.unwrap_or_default();
	let mut lines: Vec<String> = body.lines().map(str::to_owned).collect();

	if lines.len() == 3 {
		match state.lie {
			Lie::SigningKey => lines[0] = ATTACKER_KEY.to_owned(),
			Lie::IdentityKey => lines[1] = ATTACKER_KEY.to_owned(),
			Lie::Nothing => {}
		}
	}

	(
		axum::http::StatusCode::from_u16(status.as_u16()).unwrap(),
		lines.join("\n"),
	)
}

/// Untouched — the client must catch the lie by *comparing* the bundle against
/// this, so handing it a correct device list is the whole point.
async fn passthrough_devices(
	State(state): State<Arc<Hostile>>,
	Path(user): Path<String>,
) -> impl IntoResponse {
	forward(format!("{}/users/{user}/devices", state.upstream_http)).await
}

async fn passthrough_clients(State(state): State<Arc<Hostile>>) -> impl IntoResponse {
	forward(format!("{}/clients", state.upstream_http)).await
}

async fn forward(url: String) -> (axum::http::StatusCode, String) {
	match reqwest::get(url).await {
		Ok(response) => {
			let status = axum::http::StatusCode::from_u16(response.status().as_u16()).unwrap();
			(status, response.text().await.unwrap_or_default())
		}
		Err(_) => (axum::http::StatusCode::BAD_GATEWAY, String::new()),
	}
}

/// Registers a victim against the real server and returns their address.
async fn victim_of(fixture: &Fixture, name: &str) -> String {
	let output = fixture
		.run_client(&format!("{name}\n127.0.0.1:{}\n\n", fixture.port))
		.await;
	Fixture::address_from(&output)
}

/// Runs a client whose home server is the hostile one, and returns what it said.
async fn send_through_hostile(fixture: &Fixture, hostile: u16, name: &str, to: &str) -> String {
	fixture
		.run_client_lingering(
			&format!("{name}\n127.0.0.1:{hostile}\n\nmsg\n{to}\nsecret\n"),
			Duration::from_secs(3),
		)
		.await
}

#[tokio::test]
async fn a_substituted_identity_key_is_refused() {
	let fixture = Fixture::start().await;
	let victim = victim_of(&fixture, "victim-ik").await;
	let hostile = start_hostile(fixture.port, Lie::IdentityKey).await;

	let output = send_through_hostile(&fixture, hostile, "sender-ik", &victim).await;

	assert!(
		output.contains("identity key") && output.contains("does not vouch for"),
		"the client should refuse a substituted identity key, got:\n{output}"
	);
	assert!(
		!output.contains("Sent"),
		"nothing should have been sent to the middleperson's key:\n{output}"
	);

	fixture.stop().await;
}

#[tokio::test]
async fn a_substituted_signing_key_is_refused() {
	let fixture = Fixture::start().await;
	let victim = victim_of(&fixture, "victim-sk").await;
	let hostile = start_hostile(fixture.port, Lie::SigningKey).await;

	let output = send_through_hostile(&fixture, hostile, "sender-sk", &victim).await;

	assert!(
		output.contains("signing key") && output.contains("does not vouch for"),
		"the client should refuse a substituted signing key, got:\n{output}"
	);

	fixture.stop().await;
}

/// The control. Without this, the tests above would pass just as happily if the
/// proxy were broken and *every* send failed — which would make them worthless.
#[tokio::test]
async fn an_honest_proxy_is_not_refused() {
	let fixture = Fixture::start().await;
	let victim = victim_of(&fixture, "victim-ok").await;
	let hostile = start_hostile(fixture.port, Lie::Nothing).await;

	let output = send_through_hostile(&fixture, hostile, "sender-ok", &victim).await;

	assert!(
		!output.contains("does not vouch for"),
		"an untampered bundle must not be refused — the rig itself is broken:\n{output}"
	);
	assert!(
		output.contains("My address:"),
		"the client should have got through the proxied handshake:\n{output}"
	);

	fixture.stop().await;
}

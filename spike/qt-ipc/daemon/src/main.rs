//! Spike for DESIGN.md §17: `veil-daemon` — a thin wrapper over what would be
//! `veil-client-core`, speaking a local socket.
//!
//! The point being tested is that this binary shares **nothing** with the GUI
//! build: no headers, no linking, no cargo invoked from cmake. It runs the real
//! crypto stack (vodozemac) and a real SQLite message store, so the identity
//! and the history the GUI shows are genuinely produced here.

mod store;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
	path::Path,
	sync::Arc,
	time::{SystemTime, UNIX_EPOCH},
};
use store::{Store, Stored};
use tokio::{
	io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
	net::{UnixListener, UnixStream},
	sync::Mutex,
	time::{Duration, sleep},
};
use vodozemac::olm::Account;

const CHANNELS: [&str; 4] = ["general", "design", "protocol", "random"];

fn runtime_dir() -> String {
	std::env::var("VEIL_SPIKE_SOCKET")
		.ok()
		.and_then(|s| {
			Path::new(&s)
				.parent()
				.map(|p| p.to_string_lossy().into_owned())
		})
		.unwrap_or_else(|| "/tmp/veil-spike".to_owned())
}

fn socket_path() -> String {
	std::env::var("VEIL_SPIKE_SOCKET").unwrap_or_else(|_| format!("{}/veil.sock", runtime_dir()))
}

fn clock() -> String {
	let secs = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	format!("{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60)
}

#[derive(Deserialize, Debug)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
	Hello,
	Send { channel: String, text: String },
	SelectChannel { channel: String },
}

#[derive(Serialize)]
struct Member {
	name: String,
	colour: String,
	online: bool,
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event {
	Ready {
		identity: String,
		otk_count: usize,
		channels: Vec<String>,
		members: Vec<Member>,
	},
	/// A whole channel at once, in response to a switch.
	History {
		channel: String,
		messages: Vec<Stored>,
	},
	/// A single new message arriving in a channel.
	Message {
		channel: String,
		#[serde(flatten)]
		message: Stored,
	},
}

const PEOPLE: [(&str, &str); 4] = [
	("alice", "#f0b232"),
	("bob", "#3ba55d"),
	("carol", "#eb459e"),
	("dave", "#5865f2"),
];

/// Seeded history, so each channel has genuinely different content to switch
/// between rather than one shared list.
const SEED: [(&str, usize, &str); 16] = [
	("general", 0, "morning — did the sealed-tier backup thing land?"),
	("general", 1, "yeah, filtered exports per member"),
	("general", 0, "so the community survives even if I disappear?"),
	("general", 1, "that's the idea. admin channels still need k-of-n"),
	("general", 2, "nice"),
	("protocol", 3, "megolm rotation is churn x devices, not membership"),
	("protocol", 1, "which is why big communities default to open"),
	("protocol", 3, "right, keeps the cliff off the critical path"),
	("protocol", 0, "and seen_head catches equivocation?"),
	("protocol", 1, "yep — two members' attested heads can't both reconcile"),
	("design", 2, "widgets shell for docking, qml island for messages"),
	("design", 3, "no ffi at all, daemon talks over a unix socket"),
	("design", 2, "gui binary is 124kb because it has no rust in it"),
	("random", 0, "anyone else's clock drifting in the container"),
	("random", 3, "sntp offset, §13.4 — daemon reads it, never sets it"),
	("random", 0, "of course there's a section for it"),
];

fn seed_if_empty(store: &Store) -> Result<()> {
	if !store.is_empty()? {
		return Ok(());
	}
	for (channel, who, body) in SEED {
		let (name, colour) = PEOPLE[who];
		store.append(channel, name, colour, body, &clock(), false)?;
	}
	eprintln!("[daemon] seeded {} messages", SEED.len());
	Ok(())
}

async fn handle(stream: UnixStream, account: Arc<Mutex<Account>>, store: Arc<Mutex<Store>>) -> Result<()> {
	let (read_half, mut write_half) = stream.into_split();

	// One task owns the write half; everyone else sends events to it. This is
	// the shape a real daemon wants anyway — pushes and replies interleave
	// without contending for the socket.
	let (events, mut rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
	tokio::spawn(async move {
		while let Some(event) = rx.recv().await {
			let Ok(mut line) = serde_json::to_vec(&event) else {
				continue;
			};
			line.push(b'\n');
			if write_half.write_all(&line).await.is_err() {
				return;
			}
			let _ = write_half.flush().await;
		}
	});

	// A peer talking, occasionally, into a rotating channel. Stands in for
	// messages arriving from the relay — nothing polls for these.
	let chatter = events.clone();
	let chatter_store = store.clone();
	tokio::spawn(async move {
		let lines = [
			"still here, still encrypted",
			"pushed that without anyone asking for it",
			"this arrived while you were reading another channel",
		];
		for (n, body) in lines.into_iter().enumerate() {
			sleep(Duration::from_secs(6)).await;
			let channel = CHANNELS[n % CHANNELS.len()];
			let (name, colour) = PEOPLE[(n + 1) % PEOPLE.len()];
			let stored = {
				let store = chatter_store.lock().await;
				match store.append(channel, name, colour, body, &clock(), false) {
					Ok(s) => s,
					Err(_) => return,
				}
			};
			if chatter
				.send(Event::Message {
					channel: channel.to_owned(),
					message: stored,
				})
				.is_err()
			{
				return;
			}
		}
	});

	let mut lines = BufReader::new(read_half).lines();
	while let Some(line) = lines.next_line().await? {
		if line.trim().is_empty() {
			continue;
		}

		let request: Request = match serde_json::from_str(&line) {
			Ok(request) => request,
			Err(e) => {
				eprintln!("[daemon] undecodable request {line:?}: {e}");
				continue;
			}
		};
		eprintln!("[daemon] request: {request:?}");

		let event = match request {
			Request::Hello => {
				let mut account = account.lock().await;
				account.generate_one_time_keys(20);
				Event::Ready {
					identity: account
						.ed25519_key()
						.as_bytes()
						.iter()
						.map(|b| format!("{b:02x}"))
						.collect(),
					otk_count: account.one_time_keys().len(),
					channels: CHANNELS.iter().map(|c| (*c).to_owned()).collect(),
					members: PEOPLE
						.iter()
						.enumerate()
						.map(|(i, (name, colour))| Member {
							name: (*name).to_owned(),
							colour: (*colour).to_owned(),
							online: i != 2,
						})
						.collect(),
				}
			}

			Request::SelectChannel { channel } => {
				let store = store.lock().await;
				let messages = store.history(&channel)?;
				eprintln!(
					"[daemon] #{channel}: {} stored messages",
					store.channel_count(&channel)?
				);
				Event::History { channel, messages }
			}

			// Echoed back after storing, so the round trip and the assigned seq
			// are both visible.
			Request::Send { channel, text } => {
				let store = store.lock().await;
				let stored = store.append(&channel, "you", "#00a8fc", &text, &clock(), true)?;
				Event::Message {
					channel,
					message: stored,
				}
			}
		};

		events.send(event)?;
	}
	Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
	let socket = socket_path();
	let _ = std::fs::remove_file(&socket);
	std::fs::create_dir_all(Path::new(&socket).parent().unwrap())?;

	let db_path = format!("{}/messages.db", runtime_dir());
	let store = Store::open(&db_path)?;
	seed_if_empty(&store)?;
	eprintln!("[daemon] store at {db_path}");
	let store = Arc::new(Mutex::new(store));

	let account = Arc::new(Mutex::new(Account::new()));
	let listener = UnixListener::bind(&socket)?;
	eprintln!("[daemon] listening on {socket}");

	loop {
		let (stream, _) = listener.accept().await?;
		eprintln!("[daemon] client connected");
		let account = account.clone();
		let store = store.clone();
		tokio::spawn(async move {
			if let Err(e) = handle(stream, account, store).await {
				eprintln!("[daemon] connection ended: {e:#}");
			}
		});
	}
}

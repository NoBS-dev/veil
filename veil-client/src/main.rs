// NOTE: If you are adding a new feature, MAKE SURE that you are persisting the state after if you want that stuff to be saved.

use anyhow::{Context, Result};
use constcat::concat;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::{
	io::{self, Write},
	sync::Arc,
};
use tokio::sync::Mutex;
use tungstenite::{Bytes, protocol::Message};
use veil_protocol::{
	EncryptedMessage, PeerSession, ProtocolMessage, Signed, UploadKeys, display_key, parse_hex_key,
	process_data,
};
use vodozemac::{
	Curve25519PublicKey,
	olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle},
};

#[derive(Serialize, Deserialize)]
struct PersistedPeer {
	identity_key: [u8; 32],
	x25519: [u8; 32],
	session: SessionPickle,
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
	account: AccountPickle,
	peers: Vec<PersistedPeer>,
	version: u32,
}

// TODO: Let user specify ip/port
const IP_AND_PORT: &str = "localhost:3000";
const SOCKET: &str = concat!("ws://", IP_AND_PORT);
const URL: &str = concat!("http://", IP_AND_PORT);
const PROMPT: &str = concat!(SOCKET, " > ");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	// Try to load from keyring; fall back to fresh account + empty map.
	let (acc, msgable_users): (Arc<Mutex<Account>>, Arc<DashMap<[u8; 32], PeerSession>>) =
		// Messagable users should store target client identity key, as well as secret
		// At first, the secret will be your ephemeral secret,
		// but when you get a call back or receive a key exchange request,
		// it will be replaced by the diffie hellman derived shared secret
		match load_state_keyring() {
			Ok(state) => {
				let account = Account::from_pickle(state.account);
				let map = Arc::new(DashMap::new());
				for p in state.peers {
					let session = Session::from_pickle(p.session);
					map.insert(
						p.identity_key,
						PeerSession {
							x25519: p.x25519,
							session,
						},
					);
				}

				eprintln!("Prior state found. Loading...");

				(Arc::new(Mutex::new(account)), map)
			}
			Err(e) => {
				eprintln!(
					"[state] No prior state in keyring (or failed to load): {e:#}. Generating a new profile..."
				);
				(
					Arc::new(Mutex::new(Account::new())),
					Arc::new(DashMap::new()),
				)
			}
		};

	let msgable_users_clone = msgable_users.clone();
	let acc_clone = acc.clone();

	let (ws_stream, _) = tokio_tungstenite::connect_async(SOCKET).await?;
	let (write, mut read) = ws_stream.split();
	let write = Arc::new(Mutex::new(write));
	// let write_clone = write.clone();

	let mut acc_guard = acc.lock().await;
	let pub_key_bytes = *acc_guard.ed25519_key().as_bytes();
	let pub_key_bytes_clone = pub_key_bytes;
	// let signing_key_clone = acc_guard.identity_keys().ed25519.clone();

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(&pub_key_bytes)))
		.await?;

	println!("My public key: {}", display_key(&pub_key_bytes));

	// We're just generating 20 for now, should increase later in prod
	const OTK_NUM: usize = 20;
	acc_guard.generate_one_time_keys(OTK_NUM);

	let otks = acc_guard
		.one_time_keys().values().map(|key| *key.as_bytes())
		.collect();

	let key_upload_request = ProtocolMessage::UploadKeys(UploadKeys {
		encryption_key: acc_guard.curve25519_key().to_bytes(),
		one_time_keys: otks,
	});

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(
			&Signed::new_archived(key_upload_request, &acc_guard)?,
		)))
		.await?;

	acc_guard.mark_keys_as_published();

	drop(acc_guard);

	save_state(&acc, &msgable_users).await?;

	// Listener
	tokio::spawn(async move {
		while let Some(msg) = read.next().await {
			match msg {
				Ok(Message::Binary(data)) => {
					if let Ok((sender_pub_key, data)) =
						process_data(&data, &pub_key_bytes_clone).await
					{
						match data {
							ProtocolMessage::UploadKeys(resp) => {
								println!("Received an OTK: {resp:?}");

								let session = acc_clone.lock().await.create_outbound_session(
									SessionConfig::version_2(),
									Curve25519PublicKey::from(resp.encryption_key),
									Curve25519PublicKey::from(resp.one_time_keys[0]),
								);

								msgable_users_clone.insert(
									sender_pub_key,
									PeerSession {
										x25519: resp.encryption_key,
										session,
									},
								);

								if let Err(e) = save_state(&acc_clone, &msgable_users_clone).await {
									eprintln!("Save state failed: {e:?}");
								} else {
									eprintln!("Saved!");
								}
							}
							ProtocolMessage::EncryptedMessage(message) => {
								println!("Received a msg: {message:?}");

								if let Ok(msg) =
									OlmMessage::from_parts(message.message_type, &message.message)
								{
									let mut acc_guard = acc_clone.lock().await;
									match msg {
										OlmMessage::PreKey(prekey_msg) => {
											println!("Received prekey message.");

											if let Ok(session) = &acc_guard.create_inbound_session(
												Curve25519PublicKey::from(message.sender_x25519),
												&prekey_msg,
											) {
												println!("Inbound session created successfully.");

												let text =
													String::from_utf8_lossy(&session.plaintext);
												println!("Message: {text}");
											} else {
												println!("Failed to create inbound session.");
											}
										}
										OlmMessage::Normal(_) => {
											println!("Received normal message.");
										}
									}

									if let Err(e) =
										save_state(&acc_clone, &msgable_users_clone).await
									{
										eprintln!("Save state failed: {e:?}");
									} else {
										eprintln!("Saved!");
									}
								} else {
									println!("Invalid message received.");
								}
							}
						}
					}
				}
				Ok(_) => {
					println!("[Notification] Received something of unknown type.");
				}
				Err(e) => {
					println!("[Notification] Error: {e}");
				}
			}
			print!("{PROMPT}");
			io::stdout().flush().unwrap();
		}
	});

	// Talking to server
	loop {
		print!("{PROMPT}");
		io::stdout().flush()?;
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;

		// Cmds (pre-conversation)
		match input.to_lowercase().trim() {
			"help" => {
				println!("-- Command list --");
				println!("list: Lists the clients that are connected to the server");
				println!(
					"msgable: Lists the clients that you have a session with and can message them properly"
				);
				println!("quit | exit: Shuts down the client");
				println!(
					"msg | key-exchange: Sends a message to or initiates a key exchange to a client, depending on if you have a valid session with them or not"
				);
			}
			"list" => {
				println!("{:?}", list_clients().await?);
			}
			"quit" | "exit" => {
				println!("Quitting...");
				std::process::exit(0);
			}
			"msgable" => {
				for entry in msgable_users.iter() {
					println!("{}", display_key(entry.key()));
				}
			}
			"msg" | "key-exchange" => {
				println!("{:?}", list_clients().await?);

				print!("Enter target client: ");
				io::stdout().flush()?;

				let target_client = {
					let mut input = String::new();
					io::stdin().read_line(&mut input)?;
					parse_hex_key(input.trim())?
				};

				if msgable_users.contains_key(&target_client) {
					// TODO: Start messaging
				} else if let Ok((encryption_key, otk)) =
    						fetch_encryption_key_and_otk(&target_client).await
    					{
    						let acc_guard = acc.lock().await;
    						let session = {
    							acc_guard.create_outbound_session(
    								SessionConfig::version_2(),
    								Curve25519PublicKey::from(encryption_key),
    								Curve25519PublicKey::from(otk),
    							)
    						};

    						msgable_users.insert(
    							target_client,
    							PeerSession {
    								x25519: encryption_key,
    								session,
    							},
    						);

    						let msg = build_message(
    							acc_guard.curve25519_key().to_bytes(),
    							target_client,
    							&msgable_users,
    						)
    						.await?;

    						write
    							.lock()
    							.await
    							.send(Message::Binary(Bytes::copy_from_slice(
    								&Signed::new_archived(msg, &acc_guard)?,
    							)))
    							.await?;

    						println!("Sent a pre-key message to {}", display_key(&target_client));
    					}

				if let Err(e) = save_state(&acc, &msgable_users).await {
					eprintln!("Save state failed: {e:?}");
				} else {
					eprintln!("Saved!");
				}
			}

			_ => println!("Invalid option. Ignoring..."),
		}
	}
}

async fn list_clients() -> anyhow::Result<Vec<String>> {
	Ok(reqwest::get(format!("{URL}/clients"))
		.await?
		.text()
		.await?
		.lines()
		.map(|line| line.trim().to_string())
		.collect())
}

async fn build_message(
	x25519_key: [u8; 32],
	target_client: [u8; 32],
	messageable_users: &Arc<DashMap<[u8; 32], PeerSession>>,
) -> anyhow::Result<ProtocolMessage> {
	print!("Enter message: ");
	io::stdout().flush()?;

	let message = {
		let mut message = String::new();
		io::stdin().read_line(&mut message)?;
		message
	};

	if let Some(mut peer_session) = messageable_users.get_mut(&target_client) {
		let (msg_type, msg) = peer_session.session.encrypt(message).to_parts();

		let msg = ProtocolMessage::EncryptedMessage(EncryptedMessage {
			sender_x25519: x25519_key,
			recipient_ed25519: target_client,
			message_type: msg_type,
			message: msg,
		});

		Ok(msg)
	} else {
		Err(anyhow::anyhow!("No session found with target client."))
	}
}

async fn fetch_encryption_key_and_otk(
	target_identity_key: &[u8; 32],
) -> anyhow::Result<([u8; 32], [u8; 32])> {
	let target_client = display_key(target_identity_key);
	let url = format!("{}/clients/{}/otk", URL, target_client);

	let body = reqwest::get(url).await?.text().await?;

	let mut lines = body.lines();
	let encryption_key =
		parse_hex_key(lines.next().ok_or_else(|| anyhow::anyhow!("missing key"))?)?;
	let otk = parse_hex_key(lines.next().ok_or_else(|| anyhow::anyhow!("missing otk"))?)?;

	Ok((encryption_key, otk))
}

fn save_state_keyring(state: &PersistedState) -> Result<()> {
	let json = serde_json::to_string(state).context("Serializing persisted state")?;

	let entry = Entry::new("veil-client", "default").context("Opening keyring entry")?;

	entry
		.set_password(&json)
		.context("Storing state in keyring")?;

	Ok(())
}

fn load_state_keyring() -> Result<PersistedState> {
	let entry = Entry::new("veil-client", "default").context("Opening keyring entry")?;

	let json = entry.get_password().context("Reading state from keyring")?;

	let state: PersistedState =
		serde_json::from_str(&json).context("Deserializing persisted state")?;

	Ok(state)
}

async fn save_state(
	acc: &Arc<Mutex<Account>>,
	peers: &Arc<DashMap<[u8; 32], PeerSession>>,
) -> Result<()> {
	let pickle = acc.lock().await.pickle();

	let mut peers_vec = Vec::with_capacity(peers.len());
	for entry in peers.iter() {
		peers_vec.push(PersistedPeer {
			identity_key: *entry.key(),
			x25519: entry.x25519,
			session: entry.session.pickle(),
		});
	}

	let state = PersistedState {
		account: pickle,
		peers: peers_vec,
		version: 1,
	};

	// This is a quick blocking call; fine for occasional saves.
	// If you expect it to be hot, wrap with tokio::task::spawn_blocking.
	save_state_keyring(&state)
}

use anyhow::Result;
use axum::{
	Router,
	body::Bytes,
	extract::{
		Path, State, WebSocketUpgrade,
		ws::{Message, WebSocket},
	},
	http::StatusCode,
	response::{IntoResponse, Response},
	routing,
};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt, stream::SplitSink};
use std::{
	collections::HashMap,
	sync::{Arc, LazyLock},
};
use tokio::{
	net::TcpListener,
	sync::{Mutex, RwLock},
};
use veil_protocol::*;
use vodozemac::olm::Account;

type KeyMap = Arc<DashMap<[u8; 32], ClientStore>>;

#[derive(Clone)]
struct ServerState {
	key_map: KeyMap,
	server_account: Arc<Mutex<Account>>,
}

struct ClientStore {
	identity_key: [u8; 32],
	encryption_key: [u8; 32],

	// Be extremely careful with this, it can easily cause deadlocks
	one_time_keys: Arc<DashMap<String, [u8; 32]>>, // Key ID | Public key
}

static CLIENTS: LazyLock<RwLock<HashMap<[u8; 32], SplitSink<WebSocket, Message>>>> =
	LazyLock::new(|| RwLock::new(HashMap::new()));

#[tokio::main]
async fn main() -> Result<()> {
	let key_map: KeyMap = Arc::new(DashMap::new());

	// Init keys so that server can sign things (clients literally dont accept anything that's not signed)
	let state = ServerState {
		key_map,
		server_account: Arc::new(Mutex::new(Account::new())),
	};
	{
		let mut server_account_guard = state.server_account.lock().await;

		server_account_guard.generate_one_time_keys(100);
		server_account_guard.mark_keys_as_published();

		println!(
			"My public key: {}",
			display_key(server_account_guard.ed25519_key().as_bytes())
		);
	}

	let router = Router::new()
		.route("/", routing::any(socket))
		.route("/clients", routing::get(list_clients))
		.route(
			"/clients/{id}/otk",
			routing::get(get_encryption_key_and_otk),
		)
		.with_state(state);

	axum::serve(TcpListener::bind("localhost:3000").await?, router).await?;

	Ok(())
}

async fn socket(socket: WebSocketUpgrade, State(state): State<ServerState>) -> Response {
	socket.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: ServerState) {
	let (mut sender, mut receiver) = socket.split();

	let public_key = if let Some(Ok(Message::Binary(bytes))) = receiver.next().await {
		if bytes.len() != 32 {
			eprintln!("Received invalid public key.");
			return;
		}

		bytes.first_chunk::<32>().unwrap().to_owned()
	} else {
		eprintln!("Received invalid public key.");
		return;
	};

	println!("{} connected", display_key(&public_key));
	CLIENTS.write().await.insert(public_key, sender);

	while let Some(Ok(Message::Binary(bytes))) = receiver.next().await {
		if let Ok((sender_public_key, data)) = process_data(&bytes, &public_key).await {
			match data {
				ProtocolMessage::EncryptedMessage(msg) => {
					// TODO: Handle encrypted messages
					eprintln!("Received an encrypted message");

					if let Some(sender) = CLIENTS.write().await.get_mut(&msg.recipient_ed25519) {
						if let Err(e) = sender
							.send(Message::Binary(Bytes::copy_from_slice(&bytes)))
							.await
						{
							eprintln!("{e:?}");
						} else {
							eprintln!(
								"Message routed successfully from {} to {}",
								display_key(&public_key),
								display_key(&msg.recipient_ed25519)
							);
						}
					} else {
						eprintln!("Client {} not connected", display_key(&public_key));
					}
				}
				ProtocolMessage::UploadKeys(upload) => {
					eprintln!("Received a key upload request.");

					let store = ClientStore {
						identity_key: sender_public_key,
						encryption_key: upload.encryption_key,
						one_time_keys: Arc::new(DashMap::new()),
					};

					for (i, otk) in upload.one_time_keys.iter().enumerate() {
						let key_id = format!("otk_{}", i);
						store.one_time_keys.insert(key_id, *otk);
					}

					state.key_map.insert(sender_public_key, store);

					eprintln!("Key upload request handled properly.");
				} // ProtocolMessage::KeyRequest(identity_key) => {
				  // 	// TODO: Handle key requests
				  // 	println!("Received a key request.");

				  // 	handle_key_request(identity_key, &state, &public_key).await;
				  // }
			}
		}
	}

	CLIENTS.write().await.remove(&public_key);
	println!("{} disconnected", display_key(&public_key));
}

async fn list_clients() -> impl IntoResponse {
	// TODO: Maybe say who in the future
	println!("List called");

	let clients = CLIENTS.read().await;
	let iter = clients.keys().map(display_key);
	itertools::Itertools::intersperse(iter, String::from("\n")).collect::<String>()
}

async fn pop_otk(
	key_map: &KeyMap,
	identity_key: &[u8; 32],
) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
	let otk_key = {
		let store = key_map.get(identity_key)?;
		store.one_time_keys.iter().next().map(|e| e.key().clone())
	}?;

	let store = key_map.get(identity_key)?;
	let (_, otk) = store.one_time_keys.remove(&otk_key)?;

	Some((store.identity_key, store.encryption_key, otk))
}

// async fn handle_key_request(identity_key: [u8; 32], state: &ServerState, public_key: &[u8; 32]) {
// 	if let Some(_) = {
// 		if let Some(store) = state.key_map.get(&identity_key) {
// 			store
// 				.one_time_keys
// 				.iter()
// 				.next()
// 				.map(|entry| entry.key().clone())
// 		} else {
// 			None
// 		}

// 		// Be very careful editing this section, you can easily cause a deadlock
// 	} {
// 		if let Some((identity_key, encryption_key, otk)) =
// 			pop_otk(&state.key_map, &identity_key).await
// 		{
// 			let response = ProtocolMessage::UploadKeys(UploadKeys {
// 				identity_key: identity_key,
// 				encryption_key: encryption_key,
// 				one_time_keys: vec![otk],
// 			});

// 			let acc_guard = state.server_account.lock().await;

// 			if let Ok(archived_response) = Signed::new_archived(response, &acc_guard) {
// 				if let Some(sender) = CLIENTS.write().await.get_mut(public_key) {
// 					if let Err(e) = sender
// 						.send(Message::Binary(Bytes::copy_from_slice(&archived_response)))
// 						.await
// 					{
// 						println!(
// 							"Archived response failed to send to {}: {e:?}",
// 							display_key(&identity_key)
// 						);
// 					} else {
// 						println!(
// 							"Archived key: {:?} successfully sent to client: {}",
// 							&archived_response,
// 							display_key(&identity_key)
// 						);
// 					}
// 				} else {
// 					println!("{} is not connected anymore", display_key(&identity_key));
// 				}
// 			} else {
// 				println!("Generating an archived response failed");
// 			}
// 		} else {
// 			println!(
// 				"No available OTKs to remove for {}",
// 				display_key(&identity_key)
// 			);
// 		}
// 	} else {
// 		println!("No available OTKs for {}", display_key(&identity_key));
// 	}
// }

async fn get_encryption_key_and_otk(
	State(state): State<ServerState>,
	Path(client_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
	let identity_key = match parse_hex_key(&client_id) {
		Ok(key) => key,
		Err(e) => return Err((StatusCode::BAD_REQUEST, format!("Invalid hex key: {}", e))),
	};

	match pop_otk(&state.key_map, &identity_key).await {
		Some((_, encryption_key, otk)) => {
			let encryption_key_hex = display_key(&encryption_key);
			let otk_hex = display_key(&otk);

			let body = format!("{encryption_key_hex}\n{otk_hex}");
			Ok(body)
		}
		None => Err((StatusCode::NOT_FOUND, "No OTKs available".into())),
	}
}

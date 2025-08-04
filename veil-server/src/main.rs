use anyhow::Result;
use axum::{
	Router,
	extract::{
		WebSocketUpgrade,
		ws::{Message, WebSocket},
	},
	response::{IntoResponse, Response},
	routing,
};
use futures::{SinkExt, StreamExt, stream::SplitSink};
use std::{collections::HashMap, sync::LazyLock};
use tokio::{net::TcpListener, sync::RwLock};
use veil_protocol::*;

#[tokio::main]
async fn main() -> Result<()> {
	let router = Router::new()
		.route("/", routing::any(socket))
		.route("/clients", routing::get(list_clients));

	axum::serve(TcpListener::bind("localhost:3000").await?, router).await?;

	Ok(())
}

static CLIENTS: LazyLock<RwLock<HashMap<[u8; 32], SplitSink<WebSocket, Message>>>> =
	LazyLock::new(|| RwLock::new(HashMap::new()));

async fn socket(socket: WebSocketUpgrade) -> Response {
	async fn handle(socket: WebSocket) {
		let (sender, mut receiver) = socket.split();

		let public_key = if let Some(Ok(Message::Binary(bytes))) = receiver.next().await {
			if bytes.len() != 32 {
				return;
			}

			bytes.first_chunk::<32>().unwrap().to_owned()
		} else {
			return;
		};

		println!("{} connected", display_key(&public_key));
		CLIENTS.write().await.insert(public_key, sender);

		while let Some(Ok(Message::Binary(bytes))) = receiver.next().await {
			match process_data(&bytes, &public_key).await {
				Ok(data) => {
					match data {
						ProtocolMessage::EncryptedMessage(msg) => {
							// Key exchange response needs to be dnoe first
						}
						ProtocolMessage::KeyExchangeRequest(req) => {
							println!("Received a key exchange request: {:?}", &req);
							println!(
								"Routing from {} to {}",
								display_key(&public_key),
								display_key(&req.recipient_identity_key)
							);

							if let Some(sender) =
								CLIENTS.write().await.get_mut(&req.recipient_identity_key)
							{
								if let Err(e) = sender.send(Message::Binary(bytes.clone())).await {
									eprintln!(
										"Failed to send key exchange request to {}: {:?}",
										display_key(&req.recipient_identity_key),
										e
									);
								} else {
									println!("Key exchange request sent");
								}
							} else {
								println!(
									"Recipient {} not connected. Dropping key exchange request.",
									display_key(&req.recipient_identity_key)
								);
							}
						}
						ProtocolMessage::KeyExchangeResponse(resp) => {
							println!(
								"Routing key exchange response from {} to {}",
								display_key(&public_key),
								display_key(&resp.initiator_identity_key)
							);

							if let Some(sender) =
								CLIENTS.write().await.get_mut(&resp.initiator_identity_key)
							{
								if let Err(e) = sender.send(Message::Binary(bytes.clone())).await {
									eprintln!(
										"Failed to send key exchange response to {}: {:?}",
										display_key(&resp.initiator_identity_key),
										e
									);
								} else {
									println!("Key exchange response sent successfully");
								}
							} else {
								println!(
									"Recipient {} not connected. Dropping key exchange response.",
									display_key(&resp.initiator_identity_key)
								);
							}
						}
					}
				}
				Err(e) => println!("{e:?}"),
			}

			// let message = if let Ok(message) =
			// 	rkyv::access::<ArchivedSigned<KeyExchangeRequest>, rkyv::rancor::Error>(&bytes)
			// {
			// 	println!("Valid key exchange request received.");
			// 	message
			// } else {
			// 	println!("Invalid key exchange request received.");
			// 	continue;
			// };

			// if let Some(sender) = CLIENTS.write().await.get_mut(&message.recipient) {
			// 	// let _ = sender.send(Message::Binary(bytes)).await;
			// } else {
			// 	println!(
			// 		"{} is not connected, dropping message",
			// 		display_key(&message.recipient)
			// 	);
			// 	continue;
			// }
		}

		CLIENTS.write().await.remove(&public_key);
		println!("{} disconnected", display_key(&public_key));
	}

	socket.on_upgrade(handle)
}

async fn list_clients() -> impl IntoResponse {
	// TODO: Maybe say who in the future
	println!("List called");

	let clients = CLIENTS.read().await;
	let iter = clients.keys().map(display_key);
	itertools::Itertools::intersperse(iter, String::from("\n")).collect::<String>()
}

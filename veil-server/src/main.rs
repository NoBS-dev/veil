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
use rkyv::{deserialize, util::AlignedVec};
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
			let mut aligned: AlignedVec = AlignedVec::new();
			aligned.extend_from_slice(&bytes);

			match rkyv::access::<ArchivedSigned, rkyv::rancor::Error>(&aligned) {
				// This will have to be updated every time you update the protocol!
				// I'm choosing not to add a _ so it will panic every time you try to use without it
				Ok(archived_signed) => {
					match deserialize::<Signed, rkyv::rancor::Error>(archived_signed) {
						Ok(signed) => match signed.verify_sig(&public_key) {
							Ok(true) => {
								println!("Signature from {} verified", display_key(&public_key));

								match signed.data {
									ProtocolMessage::EncryptedMessage(msg) => {
										// Key exchange response needs to be done first
										println!("Received an encrypted msg: {msg:?}")
									}
									ProtocolMessage::KeyExchangeRequest(req) => {
										println!("Received a key exchange request: {:?}", &req);
										println!(
											"Routing from {} to {}",
											display_key(&public_key),
											display_key(&req.target_identity_key)
										);

										if let Some(sender) =
											CLIENTS.write().await.get_mut(&req.target_identity_key)
										{
											if let Err(e) =
												sender.send(Message::Binary(bytes.clone())).await
											{
												eprintln!(
													"Failed to send key exchange request to {}: {e:?}",
													display_key(&req.target_identity_key),
												);
											} else {
												println!("Key exchange request sent");
											}
										} else {
											println!(
												"Recipient {} not connected. Dropping key exchange request.",
												display_key(&req.target_identity_key)
											);
										}
									}
									ProtocolMessage::KeyExchangeResponse(resp) => {
										println!(
											"Routing key exchange response from {} to {}",
											display_key(&public_key),
											display_key(&resp.target_identity_key)
										);

										if let Some(sender) =
											CLIENTS.write().await.get_mut(&resp.target_identity_key)
										{
											if let Err(e) =
												sender.send(Message::Binary(bytes.clone())).await
											{
												eprintln!(
													"Failed to send key exchange response to {}: {:?}",
													display_key(&resp.target_identity_key),
													e
												);
											} else {
												println!("Key exchange response sent");
											}
										} else {
											println!(
												"Recipient {} not connected. Dropping key exchange response.",
												display_key(&resp.target_identity_key)
											);
										}
									}
								}
							}
							Ok(false) => println!("Invalid signature"),
							Err(e) => eprintln!("Signature verification error: {e:?}"),
						},
						Err(e) => eprintln!("Failed to deserialize Signed: {e:?}"),
					}
				}
				Err(e) => println!("Failed to deserialize: {e:?}"),
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

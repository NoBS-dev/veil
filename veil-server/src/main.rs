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
		let (sender, mut reciever) = socket.split();

		let public_key = if let Some(Ok(Message::Binary(bytes))) = reciever.next().await {
			if bytes.len() != 32 {
				return;
			}

			bytes.first_chunk::<32>().unwrap().to_owned()
		} else {
			return;
		};

		println!("{} connected", display_key(&public_key));
		CLIENTS.write().await.insert(public_key, sender);

		while let Some(Ok(Message::Binary(bytes))) = reciever.next().await {
			match rkyv::access::<ArchivedSigned<EncryptedMessage>, rkyv::rancor::Error>(&bytes) {
				_ => (),
			}

			let message = if let Ok(message) =
				rkyv::access::<ArchivedEncryptedMessage, rkyv::rancor::Error>(&bytes)
			{
				println!("Valid message received!");
				message
			} else {
				println!("Invalid message recieved");
				continue;
			};

			let message = if let Ok(message) =
				rkyv::access::<ArchivedSigned<KeyExchangeRequest>, rkyv::rancor::Error>(&bytes)
			{
				println!("Valid key exchange request received.");
				message
			} else {
				println!("Invalid key exchange request received.");
				continue;
			};

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

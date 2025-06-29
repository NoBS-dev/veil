use anyhow::Result;
use axum::{
	Router,
	extract::{
		WebSocketUpgrade,
		ws::{Message, WebSocket},
	},
	response::Response,
	routing,
};
use futures::{SinkExt, StreamExt, stream::SplitSink};
use std::{collections::HashMap, sync::LazyLock};
use tokio::{net::TcpListener, sync::RwLock};
use veil_protocol::ArchivedEncryptedMessage;

#[tokio::main]
async fn main() -> Result<()> {
	axum::serve(
		TcpListener::bind("localhost:3000").await?,
		Router::new().route("/", routing::any(socket)),
	)
	.await?;

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

		CLIENTS.write().await.insert(public_key, sender);

		while let Some(Ok(Message::Binary(bytes))) = reciever.next().await {
			let message = if let Ok(message) =
				rkyv::access::<ArchivedEncryptedMessage, rkyv::rancor::Error>(&bytes)
			{
				message
			} else {
				println!("Invalid message recieved");
				continue;
			};

			if let Some(sender) = CLIENTS.write().await.get_mut(&message.recipient) {
				let _ = sender.send(Message::Binary(bytes)).await;
			} else {
				println!(
					"Recipient {:?} is not connected, dropping message",
					message.recipient
				);
				continue;
			}
		}

		CLIENTS.write().await.remove(&public_key);
		println!("Client {public_key:?} disconnected");
	}

	socket.on_upgrade(handle)
}

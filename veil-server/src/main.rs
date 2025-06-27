use anyhow::Result;
use axum::{
	Router,
	extract::{WebSocketUpgrade, ws::WebSocket},
	response::Response,
	routing,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
	axum::serve(
		TcpListener::bind("localhost:3000").await?,
		Router::new().route("/", routing::any(socket)),
	)
	.await?;

	Ok(())
}

async fn socket(socket: WebSocketUpgrade) -> Response {
	async fn handle(mut socket: WebSocket) {
		while let Some(Ok(message)) = socket.recv().await {
			println!("{message:?}");
		}
		println!("Client disconnected");
	}

	socket.on_upgrade(handle)
}

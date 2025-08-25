use crate::messaging;
use crate::state::State;
use anyhow::Result;
use futures_util::stream::SplitSink;
use std::{
	io::{self, Write},
	sync::Arc,
};
use tokio::{net::TcpStream, sync::Mutex};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::Message;
use veil_protocol::display_key;

pub async fn cli(
	prompt: &str,
	url: &str,
	mut write: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
	state: Arc<Mutex<State>>,
) -> Result<()> {
	loop {
		print!("{prompt}");
		io::stdout().flush()?;
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;

		let mut state = state.lock().await;
		match input.to_lowercase().trim() {
			"curve" => {
				println!("{}", display_key(state.account.curve25519_key().as_bytes()));

				println!(
					"{}",
					base64::encode(state.account.curve25519_key().as_bytes())
				);
			}
			"ed" => {
				println!("{}", display_key(state.account.ed25519_key().as_bytes()));

				println!("{}", base64::encode(state.account.ed25519_key().as_bytes()));
			}
			"list" => {
				println!("{:?}", list_clients(url).await?);
			}
			"quit" | "exit" => {
				println!("Quitting...");
				std::process::exit(0);
			}
			"remove" => {
				state.delete_from_keyring()?;
			}
			"msg" => {
				println!("{:?}", list_clients(url).await?);

				if let Err(e) = messaging::send(&mut write, &mut state, url).await {
					eprintln!("Send message error: {e:#}");
				}
			}
			_ => println!("Invalid option. Ignoring..."),
		}
	}
}

async fn list_clients(url: &str) -> anyhow::Result<Vec<String>> {
	Ok(reqwest::get(format!("{url}/clients"))
		.await?
		.text()
		.await?
		.lines()
		.map(|line| line.trim().to_string())
		.collect())
}

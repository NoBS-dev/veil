use anyhow::Result;
use futures_util::stream::SplitSink;
use std::{
	collections::HashMap,
	io::{self, Write},
	sync::Arc,
};
use tokio::{
	net::TcpStream,
	sync::{Mutex, RwLock},
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::Message;
use veil_protocol::{PeerSession, display_key};
use vodozemac::olm::Account;

use crate::{messaging::send_message, persistence::prompt_delete_profile};

pub async fn cli(
	prompt: &String,
	acc: Arc<Mutex<Account>>,
	url: &String,
	peers: &Arc<RwLock<HashMap<[u8; 32], PeerSession>>>,
	write: Arc<Mutex<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>>,
	ip_and_port: &String,
	profile: &String,
) -> Result<()> {
	loop {
		print!("{prompt}");
		io::stdout().flush()?;
		let mut input = String::new();
		io::stdin().read_line(&mut input)?;

		match input.to_lowercase().trim() {
			"curve" => {
				println!(
					"{}",
					display_key(acc.lock().await.curve25519_key().as_bytes())
				);

				println!(
					"{}",
					base64::encode(acc.lock().await.curve25519_key().as_bytes())
				);
			}
			"ed" => {
				println!("{}", display_key(acc.lock().await.ed25519_key().as_bytes()));

				println!(
					"{}",
					base64::encode(acc.lock().await.ed25519_key().as_bytes())
				);
			}
			"list" => {
				println!("{:?}", list_clients(&url).await?);
			}
			"quit" | "exit" => {
				println!("Quitting...");
				std::process::exit(0);
			}
			"remove" => {
				prompt_delete_profile()?;
			}
			"msg" => {
				println!("{:?}", list_clients(&url).await?);

				if let Err(e) =
					send_message(&acc, &peers, &write, &ip_and_port, &profile, &url).await
				{
					eprintln!("Send message error: {e:#}");
				}
			}

			_ => println!("Invalid option. Ignoring..."),
		}
	}
}

async fn list_clients(url: &String) -> anyhow::Result<Vec<String>> {
	Ok(reqwest::get(format!("{url}/clients"))
		.await?
		.text()
		.await?
		.lines()
		.map(|line| line.trim().to_string())
		.collect())
}

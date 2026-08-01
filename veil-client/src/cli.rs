use crate::state::State;
use crate::{WriteStream, messaging};
use anyhow::Result;
use std::{
	io::{self, Write},
	sync::Arc,
};
use tokio::sync::Mutex;
use veil_protocol::{display_key, parse_hex_key, safety_number};

pub async fn cli(
	prompt: &str,
	url: &str,
	mut write: WriteStream,
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
			"safety" => {
				if let Err(e) = show_safety_number(&state) {
					eprintln!("Safety number error: {e:#}");
				}
			}
			_ => println!("Invalid option. Ignoring..."),
		}
	}
}

/// Sessions are established on trust-on-first-use, so nothing so far rules out
/// the server having handed us its own prekey bundle in a peer's name. Reading
/// these digits to each other over a channel an attacker doesn't control is
/// what closes that gap.
fn show_safety_number(state: &State) -> Result<()> {
	print!("Enter peer identity key: ");
	io::stdout().flush()?;
	let mut input = String::new();
	io::stdin().read_line(&mut input)?;
	let peer = parse_hex_key(input.trim())?;

	let mine = *state.account.ed25519_key().as_bytes();
	println!("\n{}\n", safety_number(&mine, &peer));
	println!("Both of you should see the same digits. Compare them out of band.");

	if !state.peers.contains_key(&peer) {
		println!("(No session with this peer yet.)");
	}

	Ok(())
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

use crate::state::State;
use crate::{WriteStream, messaging};
use anyhow::Result;
use std::{
	io::{self, Write},
	sync::Arc,
};
use tokio::sync::Mutex;
use veil_protocol::{display_key, identity::UserId, safety_number};

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
				if let Err(e) = show_safety_number(&mut state) {
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
fn show_safety_number(state: &mut State) -> Result<()> {
	print!("Enter peer master key (hex): ");
	io::stdout().flush()?;
	let mut input = String::new();
	io::stdin().read_line(&mut input)?;
	let peer_master = veil_protocol::parse_hex_key(input.trim())?;

	let peer = match vodozemac::Ed25519PublicKey::from_slice(&peer_master) {
		Ok(key) => UserId::from_master_key(&key),
		Err(e) => anyhow::bail!("not a valid ed25519 key: {e}"),
	};

	// Compared over *master* keys, not device keys (§6.1). One comparison then
	// covers every device the peer owns, rather than needing to be repeated for
	// each one — per-device verification does not survive contact with users.
	println!(
		"\n{}\n",
		safety_number(&state.master_public_key(), &peer_master)
	);
	println!("That key belongs to user {peer}.");

	if state.is_verified(&peer) {
		println!("You have already verified this person.");
		return Ok(());
	}

	println!("Compare those digits with them over a channel an attacker does not control.");
	print!("Do they match? Recording this trusts every device they own, now and later [y/N]: ");
	io::stdout().flush()?;

	let mut answer = String::new();
	io::stdin().read_line(&mut answer)?;
	if !answer.trim().eq_ignore_ascii_case("y") {
		println!("Not recorded.");
		return Ok(());
	}

	// The §5.4 payoff: one signature over their master key, and their whole
	// device set follows — including devices they add afterwards.
	let verified = state.verify_user(&peer_master)?;
	state.save_to_keyring()?;
	println!("Verified {verified}. Their devices will now check out automatically.");

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

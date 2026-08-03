use crate::state::State;
use crate::{WriteStream, communities, messaging};
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
	write: Arc<Mutex<WriteStream>>,
	state: Arc<Mutex<State>>,
) -> Result<()> {
	loop {
		print!("{prompt}");
		io::stdout().flush()?;
		let mut input = String::new();
		// Ok(0) is EOF, not an error, so `?` does not catch it. Without this the
		// loop spins at full tilt printing the command list forever — which is
		// what a client does the moment its stdin closes.
		if io::stdin().read_line(&mut input)? == 0 {
			println!("\nInput closed. Quitting...");
			return Ok(());
		}

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

				if let Err(e) = messaging::send(&mut *write.lock().await, &mut state, url).await {
					eprintln!("Send message error: {e:#}");
				}
			}
			"devices" => {
				if let Err(e) = show_devices(&mut state, url).await {
					eprintln!("Device list error: {e:#}");
				}
			}
			"poll" => {
				match state.poll_interval_secs {
					Some(secs) => {
						state.poll_interval_secs = None;
						println!(
							"Polling off (was every {secs}s). Staying connected; messages \
							 arrive as they are sent."
						);
					}
					None => {
						state.poll_interval_secs = Some(3600);
						println!(
							"Polling on, hourly. Slower, and nobody learns when each \
							 message arrived — only that this device checked in."
						);
					}
				}
				if let Err(e) = state.save_to_keyring() {
					eprintln!("Save state failed: {e:#}");
				}
			}
			// ---- communities (§7, §8) ----------------------------------
			"found" => {
				if let Err(e) = communities::found(&write, &mut state).await {
					eprintln!("Could not found a community: {e:#}");
				}
			}
			"join" => {
				if let Err(e) = communities::join(&write, &state).await {
					eprintln!("Could not join: {e:#}");
				}
			}
			"say" => {
				if let Err(e) = communities::say(&write, &mut state, url).await {
					eprintln!("Could not post: {e:#}");
				}
			}
			"readers" => {
				if let Err(e) = communities::readers(&write, &state).await {
					eprintln!("Could not set readers: {e:#}");
				}
			}
			"search" => {
				if let Err(e) = communities::search(&state) {
					eprintln!("Could not search: {e:#}");
				}
			}
			"channels" => {
				if let Err(e) = communities::channels(&write, &state).await {
					eprintln!("Could not declare channels: {e:#}");
				}
			}
			"watch" => {
				if let Err(e) = communities::watch(&write, &state).await {
					eprintln!("Could not announce presence: {e:#}");
				}
			}
			"queue" => {
				if let Err(e) = communities::queue(&write, &state).await {
					eprintln!("Could not read the queue: {e:#}");
				}
			}
			"report" => {
				if let Err(e) = communities::report(&write, &state).await {
					eprintln!("Could not report: {e:#}");
				}
			}
			"attach" => {
				if let Err(e) = communities::attach(&write, &mut state, url).await {
					eprintln!("Could not attach: {e:#}");
				}
			}
			"delete" => {
				if let Err(e) = communities::delete(&write, &state).await {
					eprintln!("Could not delete: {e:#}");
				}
			}
			"role" => {
				if let Err(e) = communities::role(&write, &state).await {
					eprintln!("Could not set a role: {e:#}");
				}
			}
			"history" => {
				if let Err(e) = communities::history(&write, &state).await {
					eprintln!("Could not ask for history: {e:#}");
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
/// Fetches a peer's devices and reports what actually verified.
///
/// Two independent questions, deliberately shown separately (§5.4): whether a
/// device genuinely belongs to that user, and whether we have verified who that
/// user is. A device can pass the first and fail the second.
async fn show_devices(state: &mut State, url: &str) -> Result<()> {
	print!("Enter user id: ");
	io::stdout().flush()?;
	let mut input = String::new();
	io::stdin().read_line(&mut input)?;
	let user = UserId::parse(input.trim())?;

	let (keys, devices) = messaging::fetch_device_list(&user, url).await?;

	if devices.is_empty() {
		println!("No devices for {user} survived verification.");
		return Ok(());
	}

	let verified_person = state.is_verified(&user);
	println!(
		"\n{user} — {} device(s), {}\n",
		devices.len(),
		if verified_person {
			"person verified"
		} else {
			"person NOT verified — run `safety` to compare numbers"
		}
	);

	for device in &devices {
		println!(
			"  {}  {:<16} {}",
			device.device_id,
			if device.display_name.is_empty() {
				"(unnamed)"
			} else {
				&device.display_name
			},
			if verified_person {
				"trusted"
			} else {
				"belongs to this user, but the user is unverified"
			}
		);
	}

	// Cached so a later send can address a device without refetching. Only the
	// entries that verified are stored.
	state.peer_devices.insert(
		user,
		veil_protocol::identity::DeviceList {
			user,
			devices,
			updated_at: veil_protocol::now_ms()?,
		},
	);
	state.save_to_keyring()?;

	// Offer the master key so the user can go and verify the person.
	if !verified_person {
		println!(
			"\nTheir master key, for `safety`:\n  {}",
			display_key(&keys.master)
		);
	}

	Ok(())
}

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
	Ok(messaging::directory_client()?
		.get(format!("{url}/clients"))
		.send()
		.await?
		.text()
		.await?
		.lines()
		.map(|line| line.trim().to_string())
		.collect())
}

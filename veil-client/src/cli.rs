use crate::state::State;
use crate::{WriteStream, communities, messaging};
use anyhow::Result;
use std::{
	io::{self, Write},
	sync::Arc,
};
use tokio::sync::Mutex;
use veil_protocol::{
	community::{CommunityId, Mode, Role},
	display_key,
	identity::UserId,
	safety_number,
};

/// Asks a question on the terminal.
///
/// **Lives here rather than beside the commands**, which is the whole of the
/// outbound §17 change: a command that reads stdin cannot be driven by a view,
/// tested without a pipe, or translated. The commands take parameters; this is
/// where a person is asked for them.
fn ask(question: &str) -> Result<String> {
	print!("{question}");
	io::stdout().flush()?;
	let mut input = String::new();
	io::stdin().read_line(&mut input)?;
	Ok(input.trim().to_owned())
}

/// Runs a command and renders whatever it reported.
///
/// The same rendering the receive path gets, because they are the same events.
fn show(outcome: Result<Vec<crate::events::ClientEvent>>) {
	match outcome {
		Ok(events) => {
			for event in events {
				if event.is_diagnostic() {
					eprintln!("{}", event.render());
				} else {
					println!("{}", event.render());
				}
			}
		}
		Err(e) => eprintln!("{e:#}"),
	}
}

pub async fn cli(
	prompt: &str,
	url: &str,
	write: Arc<Mutex<WriteStream>>,
	state: Arc<Mutex<State>>,
	calls: crate::media::Calls,
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

				match (
					ask("Enter target device (<user-id>/<device-id>[@host]): "),
					ask("Enter message: "),
				) {
					(Ok(target), Ok(text)) => {
						let mut reported = Vec::new();
						let outcome = messaging::send(
							&mut *write.lock().await,
							&mut state,
							url,
							&target,
							&text,
							&mut reported,
						)
						.await;
						show(outcome.map(|()| reported));
					}
					_ => eprintln!("Could not read that."),
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
				let mode = match ask("Mode — (s)ealed end-to-end, or (o)pen server-readable: ")
					.map(|m| m.to_lowercase())
				{
					Ok(m) if m == "s" || m == "sealed" => Some(Mode::Sealed),
					Ok(m) if m == "o" || m == "open" => Some(Mode::Open),
					_ => None,
				};

				match mode {
					Some(mode) => show(communities::found(&write, &mut state, mode).await),
					None => eprintln!("That is not a mode."),
				}
			}
			"join" => match ask("Community id, or an invite: ") {
				Ok(entered) => show(communities::join(&write, &state, &entered).await),
				Err(e) => eprintln!("{e:#}"),
			},
			"say" => match (ask("Community id: "), ask("Channel: "), ask("Message: ")) {
				(Ok(id), Ok(channel), Ok(body)) => match CommunityId::parse(&id) {
					Ok(id) => {
						show(communities::say(&write, &mut state, url, id, &channel, &body).await)
					}
					Err(e) => eprintln!("{e:#}"),
				},
				_ => eprintln!("Could not read that."),
			},
			"readers" => match (ask("Community id: "), ask("Channel: ")) {
				(Ok(id), Ok(channel)) => match CommunityId::parse(&id) {
					Ok(id) => {
						let mut readers = Vec::new();
						loop {
							match ask("Reader user id (blank when done): ") {
								Ok(entry) if entry.is_empty() => break,
								Ok(entry) => match UserId::parse(&entry) {
									Ok(user) => readers.push(user),
									Err(e) => eprintln!("{e:#}"),
								},
								Err(e) => {
									eprintln!("{e:#}");
									break;
								}
							}
						}
						show(communities::readers(&write, &state, id, &channel, readers).await);
					}
					Err(e) => eprintln!("{e:#}"),
				},
				_ => eprintln!("Could not read that."),
			},
			"call" => match ask("Enter target device (<user-id>/<device-id>): ") {
				Ok(target) => {
					show(communities::call(&write, &mut state, url, &calls, &target).await)
				}
				Err(e) => eprintln!("{e:#}"),
			},
			"alias" => match ask("Alias to claim: ") {
				Ok(name) => show(communities::alias(&write, &state, &name).await),
				Err(e) => eprintln!("{e:#}"),
			},
			"contact" => show(communities::contact(&state)),
			"lookup" => match ask("Contact link, or an address (name@host): ") {
				Ok(entered) => show(communities::lookup(&mut state, &entered).await),
				Err(e) => eprintln!("{e:#}"),
			},
			"search" => match ask("Search for: ") {
				Ok(query) => show(communities::search(&state, &query)),
				Err(e) => eprintln!("{e:#}"),
			},
			"channels" => match ask("Community id: ").and_then(|id| CommunityId::parse(&id)) {
				Ok(id) => {
					// Listing first: declaring replaces the set, so seeing what
					// is there is part of deciding what to send.
					for event in communities::list_channels(&state, id) {
						println!("{}", event.render());
					}

					let mut channels = Vec::new();
					loop {
						match ask("Channel name (blank when done): ") {
							Ok(name) if name.is_empty() => break,
							Ok(name) => match ask("  topic: ") {
								Ok(topic) => channels
									.push(veil_protocol::community::ChannelSpec { name, topic }),
								Err(e) => {
									eprintln!("{e:#}");
									break;
								}
							},
							Err(e) => {
								eprintln!("{e:#}");
								break;
							}
						}
					}

					show(communities::declare_channels(&write, &state, id, channels).await);
				}
				Err(e) => eprintln!("{e:#}"),
			},
			"watch" => match ask("Community id: ").and_then(|id| CommunityId::parse(&id)) {
				Ok(id) => show(communities::watch(&write, &state, id).await),
				Err(e) => eprintln!("{e:#}"),
			},
			"queue" => match ask("Community id: ").and_then(|id| CommunityId::parse(&id)) {
				Ok(id) => show(communities::queue(&write, &state, id).await),
				Err(e) => eprintln!("{e:#}"),
			},
			"report" => {
				match (
					ask("Community id: "),
					ask("Channel: "),
					ask("Message number: "),
					ask("What was said: "),
					ask("Why you are reporting it: "),
				) {
					(Ok(id), Ok(channel), Ok(sequence), Ok(quoted), Ok(reason)) => {
						match (CommunityId::parse(&id), sequence.parse::<u64>()) {
							(Ok(id), Ok(sequence)) => show(
								communities::report(
									&write, &state, id, &channel, sequence, &quoted, &reason,
								)
								.await,
							),
							_ => eprintln!("Could not read that."),
						}
					}
					_ => eprintln!("Could not read that."),
				}
			}
			"attach" => match (ask("Community id: "), ask("Channel: "), ask("File path: ")) {
				(Ok(id), Ok(channel), Ok(path)) => match CommunityId::parse(&id) {
					Ok(id) => show(
						communities::attach(&write, &mut state, url, id, &channel, &path).await,
					),
					Err(e) => eprintln!("{e:#}"),
				},
				_ => eprintln!("Could not read that."),
			},
			"delete" => {
				match (
					ask("Community id: "),
					ask("Channel: "),
					ask("Message number: "),
				) {
					(Ok(id), Ok(channel), Ok(sequence)) => {
						match (CommunityId::parse(&id), sequence.parse::<u64>()) {
							(Ok(id), Ok(sequence)) => show(
								communities::delete(&write, &state, id, &channel, sequence).await,
							),
							_ => eprintln!("Could not read that."),
						}
					}
					_ => eprintln!("Could not read that."),
				}
			}
			"role" => {
				match (
					ask("Community id: "),
					ask("User id: "),
					ask("Role — (b)anned, (m)ember, (mod)erator: ").map(|r| r.to_lowercase()),
				) {
					(Ok(id), Ok(user), Ok(role)) => {
						let role = match role.as_str() {
							"b" | "banned" => Some(Role::Banned),
							"m" | "member" => Some(Role::Member),
							"mod" | "moderator" => Some(Role::Moderator),
							_ => None,
						};

						match (CommunityId::parse(&id), UserId::parse(&user), role) {
							(Ok(id), Ok(user), Some(role)) => {
								show(communities::role(&write, &state, id, user, role).await)
							}
							_ => eprintln!("Could not read that."),
						}
					}
					_ => eprintln!("Could not read that."),
				}
			}
			"history" => match (ask("Community id: "), ask("Channel: ")) {
				(Ok(id), Ok(channel)) => match CommunityId::parse(&id) {
					Ok(id) => show(communities::history(&write, &state, id, &channel).await),
					Err(e) => eprintln!("{e:#}"),
				},
				_ => eprintln!("Could not read that."),
			},
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

	let mut reported = Vec::new();
	let (keys, devices) = messaging::fetch_device_list(&user, url, &mut reported).await?;
	for event in &reported {
		eprintln!("{}", event.render());
	}

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

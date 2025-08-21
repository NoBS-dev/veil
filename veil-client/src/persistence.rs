use crate::types::{PersistedPeer, PersistedState};
use anyhow::{Context, Result, anyhow};
use keyring::Entry;
use std::{
	collections::HashMap,
	io::{self, Write},
	sync::Arc,
};
use tokio::sync::{Mutex, RwLock};
use veil_protocol::PeerSession;
use vodozemac::olm::Account;

pub async fn save_state_to_keyring(
	acc: &Arc<Mutex<Account>>,
	peers: &Arc<RwLock<HashMap<[u8; 32], PeerSession>>>,
	ip_and_port: &String,
	profile: &String,
) -> Result<()> {
	let pickle = acc.lock().await.pickle();

	let peers_vec = {
		let map = peers.read().await;
		map.iter()
			.map(|(id, ps)| PersistedPeer {
				identity_key: *id,
				x25519: ps.x25519,
				session: ps.session.pickle(),
			})
			.collect()
	};

	let state = PersistedState {
		ip_and_port: ip_and_port.clone(),
		account: pickle,
		peers: peers_vec,
	};

	let json = serde_json::to_string(&state).context("Serializing persisted state")?;
	let entry = entry_for(profile)?;
	entry
		.set_password(&json)
		.context("Storing state in keyring")?;
	Ok(())
}

pub fn load_state_from_keyring(profile: &String) -> Result<PersistedState> {
	let entry = entry_for(profile)?;
	let json = entry.get_password().context("Reading state from keyring")?;
	let state: PersistedState =
		serde_json::from_str(&json).context("Deserializing persisted state")?;
	Ok(state)
}

pub fn delete_state_from_keyring(profile: &str) -> Result<bool> {
	let mut removed = false;

	let entry = entry_for(profile)?;
	match entry.delete_password() {
		Ok(()) => removed = true,
		Err(keyring::Error::NoEntry) => { /* fine */ }
		Err(e) => return Err(anyhow!(e)).context("Deleting profile from keyring"),
	}

	Ok(removed)
}

fn normalized_username(profile: &str) -> String {
	let profile = profile.trim();
	if profile.is_empty() || profile.eq_ignore_ascii_case("default") {
		"default".to_string()
	} else {
		profile.to_string()
	}
}

fn entry_for(profile: &str) -> Result<Entry> {
	let user = normalized_username(profile);
	Entry::new("veil-client", &user).context("Opening keyring entry")
}

pub fn prompt_delete_profile() -> anyhow::Result<()> {
	print!("Profile to delete (empty = default): ");
	io::stdout().flush()?;

	let mut profile = String::new();
	io::stdin().read_line(&mut profile)?;

	let p = match profile.trim() {
		"" => "default",
		anything_else => anything_else,
	};

	match delete_state_from_keyring(p)? {
		true => println!(
			"Removed profile '{}' from keyring.",
			format!("{}", p).trim()
		),
		false => println!("No keyring entry found for '{}'.", format!("{}", p).trim()),
	}
	Ok(())
}

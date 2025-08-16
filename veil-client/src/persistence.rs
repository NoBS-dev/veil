use crate::types::{PersistedPeer, PersistedState};
use anyhow::{Context, Result};
use dashmap::DashMap;
use keyring::Entry;
use std::sync::Arc;
use tokio::sync::Mutex;
use vodozemac::olm::Account;

pub async fn save_state_to_keyring(
	acc: &Arc<Mutex<Account>>,
	peers: &Arc<DashMap<[u8; 32], crate::PeerSession>>,
	ip_and_port: &String,
	profile: &String,
) -> Result<()> {
	let pickle = acc.lock().await.pickle();

	let mut peers_vec = Vec::with_capacity(peers.len());
	for entry in peers.iter() {
		peers_vec.push(PersistedPeer {
			identity_key: *entry.key(),
			x25519: entry.x25519,
			session: entry.session.pickle(),
		});
	}

	let state = PersistedState {
		ip_and_port: ip_and_port.clone(),
		account: pickle,
		peers: peers_vec,
	};

	let json = serde_json::to_string(&state).context("Serializing persisted state")?;
	let entry = Entry::new("veil-client", profile).context("Opening keyring entry")?;
	entry
		.set_password(&json)
		.context("Storing state in keyring")?;

	Ok(())
}

pub fn load_state_from_keyring(profile: &String) -> Result<PersistedState> {
	let entry = Entry::new("veil-client", profile).context("Opening keyring entry")?;
	let json = entry.get_password().context("Reading state from keyring")?;
	let state: PersistedState =
		serde_json::from_str(&json).context("Deserializing persisted state")?;
	Ok(state)
}

use crate::types::{PersistedPeer, PersistedState};
use anyhow::{Context, Result};
use keyring::Entry;
use std::{collections::HashMap, sync::Arc};
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

	let mut peers_vec = Vec::with_capacity(peers.read().await.len());
	for (identity_key, session) in peers.read().await.iter() {
		peers_vec.push(PersistedPeer {
			identity_key: *identity_key,
			x25519: session.x25519,
			session: session.session.pickle(),
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

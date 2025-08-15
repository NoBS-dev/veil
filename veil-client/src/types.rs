use serde::{Deserialize, Serialize};
use vodozemac::olm::{AccountPickle, SessionPickle};

#[derive(Serialize, Deserialize)]
pub struct PersistedPeer {
	pub identity_key: [u8; 32],
	pub x25519: [u8; 32],
	pub session: SessionPickle,
}

#[derive(Serialize, Deserialize)]
pub struct PersistedState {
	pub account: AccountPickle,
	pub peers: Vec<PersistedPeer>,
}

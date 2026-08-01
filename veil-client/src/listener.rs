use crate::{
	ReadStream,
	state::{PeerSession, State},
};
use futures_util::StreamExt;
use std::sync::Arc;
use tokio::sync::Mutex;
use tungstenite::protocol::Message;
use veil_protocol::{
	EncryptedMessage, ProtocolMessage, ReplayGuard, display_key, message::MessageId, open_envelope,
};
use vodozemac::olm::OlmMessage;

pub async fn listener(mut read: ReadStream, state: Arc<Mutex<State>>, server_identity: [u8; 32]) {
	let mut replay_guard = ReplayGuard::default();

	while let Some(incoming_data) = read.next().await {
		match incoming_data {
			Ok(Message::Binary(protocol_message)) => {
				let opened = match open_envelope(&protocol_message) {
					Ok(opened) => opened,
					Err(e) => {
						eprintln!("[Notification] Discarding an unverifiable envelope: {e:#}");
						continue;
					}
				};

				if let Err(e) = replay_guard.check(opened.timestamp_ms, opened.nonce) {
					eprintln!("[Notification] Discarding a replayed envelope: {e:#}");
					continue;
				}

				match opened.message {
					ProtocolMessage::EncryptedMessage(encrypted_message) => {
						process_encrypted_message(state.clone(), opened.sender, encrypted_message)
							.await;
					}
					ProtocolMessage::RemainingOneTimeKeys(remaining_otks) => {
						// Only the server has a view of the pool, so anyone else
						// claiming to report on it is trying to talk us into
						// regenerating keys.
						if opened.sender != server_identity {
							eprintln!(
								"[Notification] Ignoring an OTK count from {}, which is not the server.",
								display_key(&opened.sender)
							);
							continue;
						}

						println!("We have {remaining_otks} OTKs left.");

						// If we have less than half OTKs in our pool, regen some more
					}
					protocol_message => {
						println!(
							"Received a protocol message that we don't usually handle: {:?}",
							protocol_message
						);
					}
				}
			}
			Ok(_) => println!("[Notification] Received something of unknown type."),
			Err(e) => println!("[Notification] Error: {e}"),
		}
	}
}

async fn process_encrypted_message(
	state: Arc<Mutex<State>>,
	signing_device_key: [u8; 32],
	message: EncryptedMessage,
) {
	let olm_message = match OlmMessage::from_parts(message.message_type, &message.message) {
		Ok(olm_message) => olm_message,
		Err(_) => {
			eprintln!("Invalid message recieved.");
			return;
		}
	};

	let mut state = state.lock().await;

	// Sessions are per device (§5.2), so a peer with three devices is three
	// sessions and each is addressed separately.
	let sender = message.sender;

	if message.recipient != state.address() {
		eprintln!(
			"Dropping a message addressed to {} — this device is {}.",
			message.recipient,
			state.address()
		);
		return;
	}

	// The envelope proves *some* device key signed this; the payload *claims* a
	// device address. Nothing links the two until cross-signing (§5.4), so the
	// key is pinned on first contact and enforced from then on.
	if let Some(peer) = state.peers.get(&sender)
		&& peer.ed25519 != signing_device_key
	{
		eprintln!(
			"Dropping a message claiming to be {sender}: signed by a different device key \
			 than the one pinned for that address."
		);
		return;
	}

	// Recomputed rather than taken from the wire, so it cannot disagree with
	// what actually arrived (§10).
	let id = message.id();

	// Duplicates are dropped before any Olm work: decrypting twice would
	// advance a ratchet for a message we have already handled. Retries are the
	// common cause, not attacks.
	if let Some(peer) = state.peers.get(&sender)
		&& peer.seen_ids.contains(&id)
	{
		eprintln!("Ignoring a duplicate of {id} from {sender}.");
		return;
	}

	// The peer tells us where they were in the conversation. A head we never
	// sent means our view and theirs disagree — worth surfacing rather than
	// silently ignoring (§10.1).
	if !message.seen_head.is_root()
		&& let Some(peer) = state.peers.get(&sender)
		&& !peer.sent_ids.contains(&message.seen_head)
	{
		eprintln!(
			"note: {sender} references {} as last seen, which we have no record of sending.",
			message.seen_head
		);
	}

	match olm_message {
		OlmMessage::PreKey(prekey_msg) => {
			if !state.peers.contains_key(&sender) {
				println!("New session from {sender}.");
				match state
					.account
					.create_inbound_session(prekey_msg.identity_key(), &prekey_msg)
				{
					Ok(session) => {
						println!("Message: {}", String::from_utf8_lossy(&session.plaintext));

						let mut peer = PeerSession {
							x25519: message.sender_x25519,
							ed25519: signing_device_key,
							seen_head: MessageId::ROOT,
							seen_ids: Default::default(),
							sent_ids: Default::default(),
							session: session.session,
						};
						peer.observe(id);
						state.peers.insert(sender, peer);
					}
					Err(e) => eprintln!("Prekey parsing error: {e:#}"),
				}
			} else if let Some(peer) = state.peers.get_mut(&sender) {
				match peer.session.decrypt(&prekey_msg.into()) {
					Ok(pt) => {
						peer.observe(id);
						println!("{sender}: {}", String::from_utf8_lossy(&pt));
					}
					Err(e) => eprintln!("Decrypt failed: {e:?}"),
				}
			}
		}

		OlmMessage::Normal(normal_msg) => {
			if let Some(peer) = state.peers.get_mut(&sender) {
				match peer.session.decrypt(&normal_msg.into()) {
					Ok(pt) => {
						peer.observe(id);
						println!("{sender}: {}", String::from_utf8_lossy(&pt));
					}
					Err(e) => eprintln!("Decrypt failed: {e:?}"),
				}
			} else {
				eprintln!("Message from {sender} but no session for that device; dropping.");
			}
		}
	}

	if let Err(e) = state.save_to_keyring() {
		eprintln!("Save state failed: {e:?}");
	} else {
		eprintln!("Saved!");
	}
}

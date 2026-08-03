use crate::{
	ReadStream, WriteStream,
	state::{PeerSession, State},
};
use futures_util::SinkExt;
use futures_util::StreamExt;
use std::sync::Arc;
use tokio::sync::Mutex;
use tungstenite::Bytes;
use tungstenite::protocol::Message;
use veil_protocol::{
	EncryptedMessage, Envelope, ProtocolMessage, ReplayGuard, display_key, message::MessageId,
	open_envelope,
};
use vodozemac::olm::OlmMessage;

pub async fn listener(
	mut read: ReadStream,
	write: Arc<Mutex<WriteStream>>,
	state: Arc<Mutex<State>>,
	server_identity: [u8; 32],
) {
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

					// Mail queued while we were away. Only the server can
					// legitimately send this, and only the *inner* frame is
					// trusted — it carries its own sender's signature.
					ProtocolMessage::Mail(mail) => {
						if opened.sender != server_identity {
							eprintln!(
								"[Notification] Ignoring queued mail offered by {}, which is not the server.",
								display_key(&opened.sender)
							);
							continue;
						}

						match open_envelope(&mail.frame) {
							// Anything routed to a device can end up queued, so
							// this has to handle every such frame rather than
							// only DMs. A channel key that arrived while the
							// device was away is the common case, and dropping
							// it here left the device permanently unable to read
							// a channel it had been given access to.
							Ok(inner) => match inner.message {
								ProtocolMessage::EncryptedMessage(msg) => {
									process_encrypted_message(state.clone(), inner.sender, msg)
										.await;
								}
								ProtocolMessage::ChannelKey(key) => {
									accept_channel_key(state.clone(), inner.sender, key).await;
								}
								other => eprintln!(
									"[Notification] Queued mail was a {}, which is not \
									 something a device can be sent.",
									frame_name(&other)
								),
							},
							Err(e) => {
								eprintln!("[Notification] Queued mail is unverifiable: {e:#}")
							}
						}

						// Acknowledged after processing, not on receipt: if we
						// die in between, the server still holds it (§12.2).
						if let Err(e) = acknowledge(&write, &state, mail.id).await {
							eprintln!("[Notification] Could not acknowledge mail: {e:#}");
						}
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
					ProtocolMessage::Delivery(delivery) => {
						show_delivery(state.clone(), *delivery).await;
					}
					ProtocolMessage::ChannelKey(key) => {
						accept_channel_key(state.clone(), opened.sender, key).await;
					}
					ProtocolMessage::Ephemeral(event) => {
						let who = event
							.who
							.map(|user| user.to_string())
							.unwrap_or_else(|| "somebody".to_owned());

						match event.event {
							veil_protocol::EphemeralEvent::Watching => {
								println!("[{}] {who} is here.", event.community)
							}
							veil_protocol::EphemeralEvent::Away => {
								println!("[{}] {who} left.", event.community)
							}
							veil_protocol::EphemeralEvent::Typing => {
								println!(
									"[{}#{}] {who} is typing...",
									event.community, event.channel
								)
							}
							veil_protocol::EphemeralEvent::Read { sequence } => println!(
								"[{}#{}] {who} has read up to {sequence}.",
								event.community, event.channel
							),
						}
					}
					ProtocolMessage::ReportQueue { community, entries } => {
						if entries.is_empty() {
							println!("[{community}] no reports waiting.");
						}
						for (channel, sequence, reason, attributed) in entries {
							println!(
								"[{community}#{channel} {sequence}] reported: {reason}{}",
								if attributed {
									" (with attribution)"
								} else {
									" (unattributed — signal, not proof)"
								}
							);
						}
					}
					ProtocolMessage::CommunityResult {
						community,
						ok,
						detail,
					} => {
						if ok {
							println!("[{community}] {detail}");
						} else {
							eprintln!("[{community}] refused: {detail}");
						}
					}
					ProtocolMessage::CommunityState(view) => {
						let mut state = state.lock().await;
						// The root is checked against the id it was served
						// under, and the chain is replayed, before any of it is
						// believed. A host that edits either is caught here
						// rather than trusted not to (invariant 13, 16).
						match serde_json::from_str::<veil_protocol::community::CommunityRoot>(
							&view.root,
						)
						.map_err(anyhow::Error::from)
						.and_then(|root| {
							let id = root.id();
							state
								.accept_community(id, &view.root, &view.policy_chain)
								.map(|()| id)
						}) {
							Ok(id) => {
								println!(
									"[{id}] verified: {} member(s), {} policy record(s)",
									view.members.len(),
									view.policy_chain.len()
								);
								if let Err(e) = state.save_to_keyring() {
									eprintln!("[Notification] Save state failed: {e:#}");
								}
							}
							Err(e) => eprintln!(
								"[Notification] Refusing a community the host could not \
								 justify: {e:#}"
							),
						}
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

/// Tells the server a queued message has been dealt with, so it can drop it.
async fn acknowledge(
	write: &Arc<Mutex<WriteStream>>,
	state: &Arc<Mutex<State>>,
	id: u64,
) -> anyhow::Result<()> {
	let framed = {
		let state = state.lock().await;
		Envelope::seal(&ProtocolMessage::Acknowledge(vec![id]), &state.account)?
	};

	write
		.lock()
		.await
		.send(Message::Binary(Bytes::copy_from_slice(&framed)))
		.await?;
	Ok(())
}

/// Prints a channel message, decrypting it first if the channel is Sealed.
async fn show_delivery(state: Arc<Mutex<State>>, delivery: veil_protocol::ChannelDelivery) {
	use veil_protocol::{
		community::Mode,
		groupkeys::{ChannelId, GroupKeyProvider},
	};

	let mut state = state.lock().await;
	let channel = ChannelId::new(delivery.community, &delivery.channel);

	// A tombstone has no content to show and none to decrypt (§10.5). Shown as
	// a gap rather than hidden, so history stays legible: something was here,
	// and its place in the chain is intact.
	if delivery.tombstoned {
		println!(
			"[{}#{} {}] <deleted>",
			delivery.community, delivery.channel, delivery.sequence
		);
		return;
	}

	let body = match state.community_mode(&delivery.community) {
		Some(Mode::Sealed) => {
			let mut provider = match state.megolm() {
				Ok(provider) => provider,
				Err(e) => {
					eprintln!("[Notification] Could not load group keys: {e:#}");
					return;
				}
			};

			match provider.decrypt(&channel, &delivery.sender, &delivery.body) {
				Ok(plaintext) => {
					// Decrypting advances a ratchet, so the result has to be
					// kept or the next message fails.
					let _ = state.store_megolm(&provider);
					let _ = state.save_to_keyring();
					String::from_utf8_lossy(&plaintext).into_owned()
				}
				// Not an error worth hiding: it usually means the key for this
				// session never arrived, which is what a reader added after the
				// fact looks like (§8.3 — joiners cannot read earlier history).
				Err(e) => format!("<unreadable: {e}>"),
			}
		}
		_ => String::from_utf8_lossy(&delivery.body).into_owned(),
	};

	// The body states the sender's view of policy. Comparing it against ours is
	// what turns a host withholding a policy record into something visible
	// (§8.5) — so this is reported to the person rather than only logged.
	let body = match veil_protocol::channelbody::ChannelBody::decode(body.as_bytes()) {
		Ok(inner) => {
			let ours = state
				.community_state(&delivery.community)
				.map(|community| community.chain_head())
				.unwrap_or((0, [0u8; 32]));

			let comparison = inner.compare(ours);
			if comparison.is_notable() {
				eprintln!(
					"warning: {}#{} — {}",
					delivery.community,
					delivery.channel,
					comparison.explain()
				);
			}

			match inner.content {
				veil_protocol::channelbody::Content::Text(text) => text,
				// The blob is not fetched here: downloading every file that
				// arrives is a decision for whoever is reading.
				veil_protocol::channelbody::Content::File(attachment) => format!(
					"<file {} — {} bytes, {}>",
					attachment.filename,
					attachment.size,
					if attachment.key.is_some() {
						"encrypted"
					} else {
						"stored in the clear"
					}
				),
			}
		}
		// A body from before this existed, or from another implementation.
		Err(_) => body,
	};

	// Position and chain come from the host (§10.1), and are shown so a
	// discrepancy is visible to a person rather than silently absorbed.
	println!(
		"[{}#{} {}] {body}",
		delivery.community, delivery.channel, delivery.sequence
	);
}

/// Takes a Megolm session key a peer sent us.
///
/// The envelope's signer is what identifies the sender — not the `sender` field
/// (invariant 1). A key accepted from the wrong device would let anyone inject a
/// session and then author messages that appear to come from it.
async fn accept_channel_key(
	state: Arc<Mutex<State>>,
	envelope_signer: [u8; 32],
	key: veil_protocol::ChannelKey,
) {
	use veil_protocol::groupkeys::{ChannelId, GroupKeyProvider};

	let mut state = state.lock().await;

	if key.recipient != state.address() {
		eprintln!(
			"[Notification] Discarding a channel key addressed to {}",
			key.recipient
		);
		return;
	}

	// The sender must be a device we have a session with, and that session's
	// pinned signing key must be the one that signed this envelope.
	match state.peers.get(&key.sender) {
		Some(peer) if peer.ed25519 == envelope_signer => {}
		Some(_) => {
			eprintln!(
				"[Notification] Discarding a channel key from {}: signed by a different key \
				 than the session we hold with it",
				key.sender
			);
			return;
		}
		// No session yet: this is the first thing that device has sent us, and
		// the payload is a prekey message that establishes one.
		None => {}
	}

	let plaintext = match decrypt_channel_key(&mut state, &key, envelope_signer) {
		Ok(plaintext) => plaintext,
		Err(e) => {
			eprintln!(
				"[Notification] Could not open a channel key from {}: {e:#}",
				key.sender
			);
			return;
		}
	};

	let channel = ChannelId::new(key.community, &key.channel);
	let mut provider = match state.megolm() {
		Ok(provider) => provider,
		Err(e) => {
			eprintln!("[Notification] Could not load group keys: {e:#}");
			return;
		}
	};

	match provider.accept_key(&channel, &key.sender, &plaintext) {
		Ok(()) => {
			if let Err(e) = state.store_megolm(&provider) {
				eprintln!("[Notification] Could not store group keys: {e:#}");
				return;
			}
			let _ = state.save_to_keyring();
			println!("[{channel}] key accepted from {}.", key.sender);
		}
		Err(e) => eprintln!("[Notification] Refusing a channel key: {e:#}"),
	}
}

/// Olm-decrypts a key delivery, opening an inbound session if this is the first
/// thing we have had from that device.
fn decrypt_channel_key(
	state: &mut State,
	key: &veil_protocol::ChannelKey,
	envelope_signer: [u8; 32],
) -> anyhow::Result<Vec<u8>> {
	use vodozemac::olm::OlmMessage;

	let olm = OlmMessage::from_parts(key.message_type, &key.message)?;

	if let Some(peer) = state.peers.get_mut(&key.sender) {
		return Ok(peer.session.decrypt(&olm)?);
	}

	let OlmMessage::PreKey(prekey) = olm else {
		anyhow::bail!(
			"no session with {} and this is not a prekey message",
			key.sender
		);
	};

	let opened = state
		.account
		.create_inbound_session(prekey.identity_key(), &prekey)?;

	state.peers.insert(
		key.sender,
		crate::state::PeerSession {
			x25519: key.sender_x25519,
			// Pinned to whoever actually signed this envelope, not to the
			// address it claims. Everything from this device afterwards has to
			// match, which is what stops a third party taking over the session
			// by claiming the same address.
			ed25519: envelope_signer,
			seen_head: veil_protocol::message::MessageId::ROOT,
			seen_ids: Default::default(),
			sent_ids: Default::default(),
			session: opened.session,
		},
	);

	Ok(opened.plaintext)
}

/// A frame's name, for diagnostics that should not print its contents.
fn frame_name(message: &ProtocolMessage) -> &'static str {
	match message {
		ProtocolMessage::Challenge(_) => "challenge",
		ProtocolMessage::Authenticate(_) => "authentication",
		ProtocolMessage::UploadKeys(_) => "key upload",
		ProtocolMessage::EncryptedMessage(_) => "message",
		ProtocolMessage::Mail(_) => "mail",
		ProtocolMessage::Acknowledge(_) => "acknowledgement",
		ProtocolMessage::RemainingOneTimeKeys(_) => "one-time key count",
		ProtocolMessage::ServerAuthenticate(_) => "server authentication",
		ProtocolMessage::Deposit(_) => "deposit",
		ProtocolMessage::DepositResult(_) => "deposit result",
		ProtocolMessage::CreateCommunity(_) => "community creation",
		ProtocolMessage::JoinCommunity(_) => "community join",
		ProtocolMessage::CommunityState(_) => "community state",
		ProtocolMessage::Post(_) => "channel post",
		ProtocolMessage::Delivery(_) => "channel delivery",
		ProtocolMessage::Backfill { .. } => "backfill request",
		ProtocolMessage::SubmitPolicy(_) => "policy record",
		ProtocolMessage::FetchCommunity(_) => "community fetch",
		ProtocolMessage::DeleteMessage { .. } => "delete",
		ProtocolMessage::Ephemeral(_) => "ephemeral event",
		ProtocolMessage::Report(_) => "report",
		ProtocolMessage::FetchReports(_) => "report fetch",
		ProtocolMessage::ReportQueue { .. } => "report queue",
		ProtocolMessage::UploadBlob(_) => "blob upload",
		ProtocolMessage::BlobStored { .. } => "blob stored",
		ProtocolMessage::FetchBlob(_) => "blob fetch",
		ProtocolMessage::BlobContent { .. } => "blob content",
		ProtocolMessage::ChannelKey(_) => "channel key",
		ProtocolMessage::CommunityResult { .. } => "community result",
	}
}

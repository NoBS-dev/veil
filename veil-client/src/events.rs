//! What happened, as data rather than as text — `DESIGN.md` §17.
//!
//! §17 puts a **library with no UI dependency** underneath the client, with the
//! interface on the far side of a socket. The thing standing in the way was not
//! the socket; it was that the protocol code printed its results. A `println!`
//! in the middle of a decrypt cannot be rendered by a Qt view, tested without
//! capturing stdout, or translated.
//!
//! So the inbound path produces one of these instead, and something else decides
//! what to do with it. [`ClientEvent::render`] is that something for the CLI, and
//! it lives here rather than in the protocol code — deliberately, so the two can
//! be separated by moving one file rather than by unpicking every call site.
//!
//! **Events carry values, never formatted strings.** A variant holding
//! `"3 members"` would push the formatting decision back inside, which is the
//! problem this exists to solve.

use veil_protocol::{
	EphemeralEvent,
	community::CommunityId,
	identity::{DeviceAddress, UserId},
};

/// Something the client learned. One per thing that happened.
#[derive(Debug, Clone)]
pub enum ClientEvent {
	/// A direct message, already decrypted.
	///
	/// `from` is carried even though the terminal renderer does not show it —
	/// it printed only the text before this existed, and changing that is a
	/// separate decision from moving the data. A view that wants to attribute
	/// messages needs it, and an event that omitted it would force the next
	/// caller back into the protocol code to get it. That is the shape §17 is
	/// trying to avoid.
	DirectMessage {
		#[allow(dead_code)]
		from: DeviceAddress,
		text: String,
	},
	/// A peer opened a new Olm session with us.
	SessionOpened { from: DeviceAddress },

	/// A message in a channel, at the position the host gave it.
	ChannelMessage {
		community: CommunityId,
		channel: String,
		sequence: u64,
		body: ChannelContent,
	},
	/// A channel's key material arrived and was accepted.
	ChannelKeyAccepted {
		community: CommunityId,
		channel: String,
		from: DeviceAddress,
	},

	/// A community's root and chain checked out.
	CommunityVerified {
		community: CommunityId,
		members: usize,
		policy_records: usize,
	},
	/// The host said what became of a community request.
	CommunityResult {
		community: CommunityId,
		ok: bool,
		detail: String,
	},
	/// The moderation queue (§7.6).
	ReportQueue {
		community: CommunityId,
		entries: Vec<ReportEntry>,
	},

	/// Presence, typing or read state (§10.3).
	Ephemeral {
		community: CommunityId,
		channel: String,
		who: Option<UserId>,
		event: EphemeralEvent,
	},

	/// How many one-time keys the host still holds for us.
	OneTimeKeys { remaining: u16 },

	/// Something a person should know about but which is not a message.
	///
	/// Kept as a single variant rather than one per cause: these are for
	/// somebody reading a log, and enumerating them would be a taxonomy nobody
	/// consumes. Anything a *view* needs to act on deserves its own variant.
	Notice { severity: Severity, text: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelContent {
	Text(String),
	File {
		filename: String,
		size: u64,
		encrypted: bool,
	},
	/// The content was deleted (§10.5). The gap is shown rather than hidden, so
	/// history stays legible.
	Deleted,
	/// Sealed, and this device has no key for the session it was sent under.
	Unreadable {
		why: String,
	},
}

#[derive(Debug, Clone)]
pub struct ReportEntry {
	pub channel: String,
	pub sequence: u64,
	pub reason: String,
	pub attributed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
	Info,
	/// Something is wrong but the client carried on.
	Warning,
}

impl ClientEvent {
	pub fn warn(text: impl Into<String>) -> Self {
		Self::Notice {
			severity: Severity::Warning,
			text: text.into(),
		}
	}

	pub fn info(text: impl Into<String>) -> Self {
		Self::Notice {
			severity: Severity::Info,
			text: text.into(),
		}
	}

	/// Renders for the terminal.
	///
	/// The only place in the client that decides how any of this *looks*. A Qt
	/// view would replace this function and nothing else.
	pub fn render(&self) -> String {
		match self {
			Self::DirectMessage { text, .. } => format!("Message: {text}"),
			Self::SessionOpened { from } => format!("New session from {from}."),

			Self::ChannelMessage {
				community,
				channel,
				sequence,
				body,
			} => format!("[{community}#{channel} {sequence}] {}", body.render()),

			Self::ChannelKeyAccepted {
				community,
				channel,
				from,
			} => format!("[{community}#{channel}] key accepted from {from}."),

			Self::CommunityVerified {
				community,
				members,
				policy_records,
			} => format!(
				"[{community}] verified: {members} member(s), {policy_records} policy record(s)"
			),

			Self::CommunityResult {
				community,
				ok,
				detail,
			} => {
				if *ok {
					format!("[{community}] {detail}")
				} else {
					format!("[{community}] refused: {detail}")
				}
			}

			Self::ReportQueue { community, entries } if entries.is_empty() => {
				format!("[{community}] no reports waiting.")
			}
			Self::ReportQueue { community, entries } => entries
				.iter()
				.map(|entry| {
					format!(
						"[{community}#{} {}] reported: {}{}",
						entry.channel,
						entry.sequence,
						entry.reason,
						if entry.attributed {
							" (with attribution)"
						} else {
							" (unattributed — signal, not proof)"
						}
					)
				})
				.collect::<Vec<_>>()
				.join("\n"),

			Self::Ephemeral {
				community,
				channel,
				who,
				event,
			} => {
				let who = who
					.map(|user| user.to_string())
					.unwrap_or_else(|| "somebody".to_owned());

				match event {
					EphemeralEvent::Watching => format!("[{community}] {who} is here."),
					EphemeralEvent::Away => format!("[{community}] {who} left."),
					EphemeralEvent::Typing => {
						format!("[{community}#{channel}] {who} is typing...")
					}
					EphemeralEvent::Read { sequence } => {
						format!("[{community}#{channel}] {who} has read up to {sequence}.")
					}
				}
			}

			Self::OneTimeKeys { remaining } => format!("We have {remaining} OTKs left."),

			Self::Notice { severity, text } => match severity {
				Severity::Info => text.clone(),
				Severity::Warning => format!("[Notification] {text}"),
			},
		}
	}

	/// Whether this belongs on stderr.
	pub fn is_diagnostic(&self) -> bool {
		matches!(
			self,
			Self::Notice {
				severity: Severity::Warning,
				..
			}
		)
	}
}

impl ChannelContent {
	fn render(&self) -> String {
		match self {
			Self::Text(text) => text.clone(),
			Self::File {
				filename,
				size,
				encrypted,
			} => format!(
				"<file {filename} — {size} bytes, {}>",
				if *encrypted {
					"encrypted"
				} else {
					"stored in the clear"
				}
			),
			Self::Deleted => "<deleted>".to_owned(),
			Self::Unreadable { why } => format!("<unreadable: {why}>"),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn community() -> CommunityId {
		use veil_protocol::{
			community::{CommunityRoot, Mode},
			crosssign::CrossSigningSecrets,
		};

		let founder = CrossSigningSecrets::new();
		CommunityRoot::found(
			Mode::Open,
			vec![founder.master_public()],
			1,
			founder.master_secret(),
			1_000,
		)
		.unwrap()
		.id()
	}

	/// A tombstone renders as a gap, not as nothing — history has to stay
	/// legible across a deletion (§10.5).
	#[test]
	fn a_deleted_message_renders_as_a_gap() {
		let event = ClientEvent::ChannelMessage {
			community: community(),
			channel: "general".into(),
			sequence: 4,
			body: ChannelContent::Deleted,
		};

		assert!(event.render().contains("<deleted>"));
		assert!(event.render().contains("#general 4"));
	}

	#[test]
	fn an_attachment_says_whether_it_is_encrypted() {
		let encrypted = ClientEvent::ChannelMessage {
			community: community(),
			channel: "general".into(),
			sequence: 1,
			body: ChannelContent::File {
				filename: "photo.png".into(),
				size: 42,
				encrypted: true,
			},
		};
		assert!(encrypted.render().contains("encrypted"));

		let plain = ClientEvent::ChannelMessage {
			community: community(),
			channel: "general".into(),
			sequence: 1,
			body: ChannelContent::File {
				filename: "banner.png".into(),
				size: 42,
				encrypted: false,
			},
		};
		assert!(plain.render().contains("stored in the clear"));
	}

	/// An unattributed report must not read as proof (§7.6).
	#[test]
	fn an_unattributed_report_says_so() {
		let event = ClientEvent::ReportQueue {
			community: community(),
			entries: vec![ReportEntry {
				channel: "general".into(),
				sequence: 3,
				reason: "abuse".into(),
				attributed: false,
			}],
		};

		let rendered = event.render();
		assert!(rendered.contains("signal, not proof"));
		assert!(!rendered.contains("with attribution"));
	}

	#[test]
	fn an_empty_queue_says_so_rather_than_rendering_nothing() {
		let event = ClientEvent::ReportQueue {
			community: community(),
			entries: Vec::new(),
		};
		assert!(event.render().contains("no reports waiting"));
	}

	/// Warnings go to stderr, ordinary events do not — a view that mixes them
	/// makes a log unreadable.
	#[test]
	fn warnings_are_separated_from_events() {
		assert!(ClientEvent::warn("something").is_diagnostic());
		assert!(!ClientEvent::info("something").is_diagnostic());
		assert!(
			!ClientEvent::OneTimeKeys { remaining: 3 }.is_diagnostic(),
			"an ordinary event is not a diagnostic"
		);
	}

	/// A refusal must be distinguishable from a success at a glance.
	#[test]
	fn a_refusal_reads_as_one() {
		let refused = ClientEvent::CommunityResult {
			community: community(),
			ok: false,
			detail: "you are banned".into(),
		};
		assert!(refused.render().contains("refused:"));

		let accepted = ClientEvent::CommunityResult {
			community: community(),
			ok: true,
			detail: "joined".into(),
		};
		assert!(!accepted.render().contains("refused"));
	}
}

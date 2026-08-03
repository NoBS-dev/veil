//! Local message history and search — `DESIGN.md` §10.4.
//!
//! **Why a file rather than the keyring.** The Secret Service is built for small
//! secrets: items live in a daemon's memory and are marshalled over D-Bus, so a
//! history blob per profile abuses it. The client already keeps `State` as one
//! JSON document rewritten in full on every save, which is the same mistake at a
//! smaller scale — adding message history there would rewrite everything each
//! time a message arrived.
//!
//! So the pattern is the ordinary one: **the data lives in a file, and the
//! keyring holds the key that opens it.** Thirty-two bytes in the keyring,
//! everything else on disk.
//!
//! **The whole database is encrypted, index included.** §10.4 is explicit that
//! encrypting only the backup is not enough — a plaintext local index is a
//! searchable copy of every message, and undoes Sealed for anyone who takes the
//! device. Putting the FTS index *inside* an encrypted database gets that by
//! construction rather than by wrapping a search engine's directory.
//!
//! **Indexed at decrypt time, never on demand** (§10.4). A message is recorded as
//! it comes through the receive pipeline, so search is never "building…" and the
//! cost is amortised into work already happening.
//!
//! §10.4 specifies Tantivy, and is right for the scale it describes — segment
//! based, incrementally backed up, Lucene-class. SQLite's FTS5 is the first cut:
//! it is already a dependency, it is inside the encryption boundary, and the
//! interface here is small enough that replacing the engine touches this file
//! only. What it is *not* is a plan to stay on FTS5 for a million messages.

use anyhow::Result;
use rusqlite::{Connection, params};
use veil_protocol::community::CommunityId;

pub struct History {
	db: Connection,
}

/// One stored message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
	pub community: Option<CommunityId>,
	pub channel: String,
	/// Rendered rather than typed. The store keeps what it was handed: parsing
	/// it back would need a fallback for a row it could not read, and a silently
	/// wrong address is worse than a string.
	pub sender: String,
	pub sequence: Option<u64>,
	pub text: String,
	pub at: u64,
}

impl History {
	/// Opens the store, creating it if needed.
	///
	/// The key is supplied by the caller, which holds it in the profile — so it
	/// reaches the keyring the same way every other secret does, and this file
	/// never decides where it lives.
	pub fn open(path: &std::path::Path, key: &[u8; 32]) -> Result<Self> {
		if let Some(parent) = path.parent() {
			std::fs::create_dir_all(parent)?;
		}

		let db = Connection::open(path)?;

		// Before any other statement: SQLCipher needs the key to read the
		// header, so a query issued first fails as "not a database" rather than
		// as a wrong password.
		db.pragma_update(None, "key", hex(key))?;

		// Fails on a database opened with the wrong key, which is the only
		// point at which that can be detected.
		db.execute_batch(
			"CREATE TABLE IF NOT EXISTS messages (
			     id         INTEGER PRIMARY KEY AUTOINCREMENT,
			     community  TEXT,
			     channel    TEXT NOT NULL,
			     sender     TEXT NOT NULL,
			     sequence   INTEGER,
			     body       TEXT NOT NULL,
			     at         INTEGER NOT NULL,
			     UNIQUE (community, channel, sequence)
			 );

			 -- The index lives inside the encrypted database, which is what
			 -- §10.4 asks for. An external index would be a searchable copy of
			 -- every message sitting next to it in the clear.
			 CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts
			     USING fts5(body, content='messages', content_rowid='id');

			 CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
			     INSERT INTO messages_fts(rowid, body) VALUES (new.id, new.body);
			 END;
			 CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
			     INSERT INTO messages_fts(messages_fts, rowid, body)
			         VALUES('delete', old.id, old.body);
			 END;",
		)?;

		Ok(Self { db })
	}

	/// Records a message as it comes through the receive pipeline.
	///
	/// A repeat is ignored rather than stored twice: backfill overlaps live
	/// delivery by design, so the same message arrives both ways routinely.
	pub fn record(&self, entry: &Entry) -> Result<()> {
		self.db.execute(
			"INSERT OR IGNORE INTO messages (community, channel, sender, sequence, body, at)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
			params![
				entry.community.map(|id| id.to_string()),
				entry.channel,
				entry.sender,
				entry.sequence,
				entry.text,
				entry.at,
			],
		)?;
		Ok(())
	}

	/// Drops a message's text, keeping nothing of it (§10.5).
	///
	/// A tombstone reaches every client that is listening, and a local copy that
	/// survived it would make "deleted" mean rather less than it says — the more
	/// so because this copy is searchable.
	pub fn forget(&self, community: &CommunityId, channel: &str, sequence: u64) -> Result<()> {
		self.db.execute(
			"DELETE FROM messages WHERE community = ?1 AND channel = ?2 AND sequence = ?3",
			params![community.to_string(), channel, sequence],
		)?;
		Ok(())
	}

	/// Full-text search, most recent first.
	pub fn search(&self, query: &str, limit: usize) -> Result<Vec<Entry>> {
		let mut stmt = self.db.prepare(
			"SELECT m.community, m.channel, m.sender, m.sequence, m.body, m.at
			 FROM messages_fts f JOIN messages m ON m.id = f.rowid
			 WHERE messages_fts MATCH ?1
			 ORDER BY m.at DESC LIMIT ?2",
		)?;

		let rows = stmt.query_map(params![query, limit as i64], |r| {
			Ok(Entry {
				community: r
					.get::<_, Option<String>>(0)?
					.and_then(|id| CommunityId::parse(&id).ok()),
				channel: r.get(1)?,
				sender: r.get(2)?,
				sequence: r.get(3)?,
				text: r.get(4)?,
				at: r.get::<_, i64>(5)? as u64,
			})
		})?;

		Ok(rows.collect::<Result<Vec<_>, _>>()?)
	}

	/// How many messages are stored. Used by the tests that check a wrong key
	/// opens nothing and that a repeat is not stored twice.
	#[allow(dead_code)]
	pub fn count(&self) -> Result<i64> {
		Ok(self
			.db
			.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?)
	}
}

fn hex(key: &[u8; 32]) -> String {
	// SQLCipher takes a raw key as x'..' rather than deriving one from a
	// passphrase, which is what we want: the key is already random.
	let digits: String = key.iter().map(|b| format!("{b:02x}")).collect();
	format!("x'{digits}'")
}

#[cfg(test)]
mod tests {
	use super::*;
	use veil_protocol::{
		community::{CommunityRoot, Mode},
		crosssign::CrossSigningSecrets,
	};

	fn temp(name: &str) -> std::path::PathBuf {
		let path =
			std::env::temp_dir().join(format!("veil-history-{}-{name}.db", std::process::id()));
		let _ = std::fs::remove_file(&path);
		path
	}

	fn community() -> CommunityId {
		let founder = CrossSigningSecrets::new();
		CommunityRoot::found(
			Mode::Sealed,
			vec![founder.master_public()],
			1,
			founder.master_secret(),
			1_000,
		)
		.unwrap()
		.id()
	}

	fn entry(text: &str, sequence: u64, community: CommunityId) -> Entry {
		Entry {
			community: Some(community),
			channel: "general".into(),
			sender: "someone/somewhere".into(),
			sequence: Some(sequence),
			text: text.into(),
			at: 1_000 + sequence,
		}
	}

	#[test]
	fn a_message_is_recorded_and_found() {
		let path = temp("found");
		let history = History::open(&path, &[7u8; 32]).unwrap();
		let id = community();

		history
			.record(&entry("the quick brown fox", 1, id))
			.unwrap();
		history
			.record(&entry("something unrelated", 2, id))
			.unwrap();

		let hits = history.search("brown", 10).unwrap();
		assert_eq!(hits.len(), 1);
		assert_eq!(hits[0].text, "the quick brown fox");

		let _ = std::fs::remove_file(&path);
	}

	/// §10.4: a plaintext index on disk is a searchable copy of every message,
	/// and undoes Sealed for anyone who takes the device.
	#[test]
	fn nothing_readable_reaches_the_disk() {
		let path = temp("encrypted");
		let history = History::open(&path, &[7u8; 32]).unwrap();
		history
			.record(&entry("a distinctive secret phrase", 1, community()))
			.unwrap();
		drop(history);

		let raw = std::fs::read(&path).unwrap();
		assert!(
			!raw.windows(b"distinctive".len())
				.any(|w| w == b"distinctive"),
			"the message must not be readable in the file"
		);
		assert!(
			!raw.windows(b"general".len()).any(|w| w == b"general"),
			"nor its metadata, which the whole-database encryption also covers"
		);

		let _ = std::fs::remove_file(&path);
	}

	/// The key is the only thing standing between the file and whoever has it.
	#[test]
	fn the_wrong_key_does_not_open_it() {
		let path = temp("wrongkey");
		let history = History::open(&path, &[7u8; 32]).unwrap();
		history.record(&entry("private", 1, community())).unwrap();
		drop(history);

		assert!(
			History::open(&path, &[8u8; 32]).is_err(),
			"a different key must not open the store"
		);
		// The control: the right one still does, so the refusal is about the key.
		assert_eq!(
			History::open(&path, &[7u8; 32]).unwrap().count().unwrap(),
			1
		);

		let _ = std::fs::remove_file(&path);
	}

	/// Backfill overlaps live delivery by design, so the same message arrives
	/// twice as a matter of course.
	#[test]
	fn the_same_message_is_not_stored_twice() {
		let path = temp("dedup");
		let history = History::open(&path, &[7u8; 32]).unwrap();
		let id = community();

		history.record(&entry("said once", 1, id)).unwrap();
		history.record(&entry("said once", 1, id)).unwrap();

		assert_eq!(history.count().unwrap(), 1);
		assert_eq!(history.search("once", 10).unwrap().len(), 1);

		let _ = std::fs::remove_file(&path);
	}

	/// A deletion must reach the local copy too — the more so because this one
	/// is searchable (§10.5).
	#[test]
	fn a_deleted_message_leaves_the_index() {
		let path = temp("forget");
		let history = History::open(&path, &[7u8; 32]).unwrap();
		let id = community();

		history.record(&entry("regrettable", 1, id)).unwrap();
		assert_eq!(history.search("regrettable", 10).unwrap().len(), 1);

		history.forget(&id, "general", 1).unwrap();
		assert!(
			history.search("regrettable", 10).unwrap().is_empty(),
			"a deleted message must not remain searchable"
		);

		let _ = std::fs::remove_file(&path);
	}

	#[test]
	fn history_survives_reopening() {
		let path = temp("reopen");
		{
			let history = History::open(&path, &[7u8; 32]).unwrap();
			history.record(&entry("before", 1, community())).unwrap();
		}

		let history = History::open(&path, &[7u8; 32]).unwrap();
		assert_eq!(history.search("before", 10).unwrap().len(), 1);

		let _ = std::fs::remove_file(&path);
	}
}

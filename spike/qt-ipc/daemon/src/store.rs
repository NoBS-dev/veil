//! The message store, in the shape `DESIGN.md` §12.1 describes: a per-channel
//! append-only log keyed by `(channel, seq)`, with `seq` assigned by the host
//! and monotonic within a channel (§10).
//!
//! SQLite rather than a `HashMap` on purpose — persistence across restarts is
//! the thing worth proving, and it is what the real store will be.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct Stored {
	pub seq: i64,
	pub author: String,
	pub colour: String,
	pub body: String,
	pub time: String,
	pub mine: bool,
}

pub struct Store {
	db: Connection,
}

impl Store {
	pub fn open(path: &str) -> Result<Self> {
		let db = Connection::open(path)?;
		db.execute_batch(
			"PRAGMA journal_mode = WAL;
			 CREATE TABLE IF NOT EXISTS messages (
			     channel TEXT    NOT NULL,
			     seq     INTEGER NOT NULL,
			     author  TEXT    NOT NULL,
			     colour  TEXT    NOT NULL,
			     body    TEXT    NOT NULL,
			     time    TEXT    NOT NULL,
			     mine    INTEGER NOT NULL,
			     PRIMARY KEY (channel, seq)
			 );",
		)?;
		Ok(Self { db })
	}

	pub fn is_empty(&self) -> Result<bool> {
		let n: i64 = self
			.db
			.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?;
		Ok(n == 0)
	}

	/// Appends and returns the assigned `seq`. The host owns ordering, so the
	/// next sequence is derived here rather than supplied by a caller.
	pub fn append(
		&self,
		channel: &str,
		author: &str,
		colour: &str,
		body: &str,
		time: &str,
		mine: bool,
	) -> Result<Stored> {
		let seq: i64 = self.db.query_row(
			"SELECT COALESCE(MAX(seq), 0) + 1 FROM messages WHERE channel = ?1",
			params![channel],
			|r| r.get(0),
		)?;

		self.db.execute(
			"INSERT INTO messages (channel, seq, author, colour, body, time, mine)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
			params![channel, seq, author, colour, body, time, mine as i64],
		)?;

		Ok(Stored {
			seq,
			author: author.to_owned(),
			colour: colour.to_owned(),
			body: body.to_owned(),
			time: time.to_owned(),
			mine,
		})
	}

	/// A channel's history in order. The real client would page this by `seq`
	/// rather than fetching everything (§12.2).
	pub fn history(&self, channel: &str) -> Result<Vec<Stored>> {
		let mut stmt = self.db.prepare(
			"SELECT seq, author, colour, body, time, mine
			 FROM messages WHERE channel = ?1 ORDER BY seq",
		)?;
		let rows = stmt
			.query_map(params![channel], |r| {
				Ok(Stored {
					seq: r.get(0)?,
					author: r.get(1)?,
					colour: r.get(2)?,
					body: r.get(3)?,
					time: r.get(4)?,
					mine: r.get::<_, i64>(5)? != 0,
				})
			})?
			.collect::<Result<Vec<_>, _>>()?;
		Ok(rows)
	}

	pub fn channel_count(&self, channel: &str) -> Result<i64> {
		Ok(self.db.query_row(
			"SELECT COUNT(*) FROM messages WHERE channel = ?1",
			params![channel],
			|r| r.get(0),
		)?)
	}
}

//! Server persistence — `DESIGN.md` §12.1.
//!
//! Two stores live here. The **key directory** holds users, their cross-signing
//! keys, their devices and prekey bundles; the **mailbox** holds frames for
//! devices that were not connected when something arrived. Before this, a
//! restart lost every key and a message to anyone offline was dropped on the
//! floor.
//!
//! **SQLite rather than Postgres**, which §12.1 originally named. Requiring a
//! database server to run a home server is friction §1.3 cannot afford — the
//! invariant is that one person on a domestic connection can run one. Postgres
//! remains the path for large hosts, and the schema here is deliberately plain
//! so moving is a port rather than a redesign.
//!
//! Calls run inline rather than on a blocking pool: local SQLite writes in WAL
//! mode are tens of microseconds, and routing no longer waits on sockets
//! (§13.3). A pool and `spawn_blocking` is the answer if that stops being true.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use veil_protocol::{
	ChannelDelivery,
	community::CommunityId,
	crosssign::CrossSigningPublic,
	identity::{Device, DeviceAddress, DeviceId, UserId},
};
use vodozemac::olm::Account;

pub struct Store {
	db: Connection,
}

/// A device's published prekey material.
pub struct PrekeyBundle {
	pub signing_key: [u8; 32],
	pub encryption_key: [u8; 32],
	pub one_time_key: [u8; 32],
	pub remaining: u16,
}

impl Store {
	pub fn open(path: &str) -> Result<Self> {
		let db = Connection::open(path)?;
		db.execute_batch(
			"PRAGMA journal_mode = WAL;
			 PRAGMA foreign_keys = ON;
			 -- Zero freed content rather than merely unlinking it, so a page
			 -- that later shrinks does not leave the old bytes behind. Defence
			 -- in depth for §10.5 rather than the mechanism — what actually
			 -- removes a deleted message is the WAL checkpoint in `tombstone`.
			 PRAGMA secure_delete = ON;

			 CREATE TABLE IF NOT EXISTS users (
			     user_id BLOB PRIMARY KEY,
			     keys    TEXT NOT NULL          -- CrossSigningPublic, as JSON
			 );

			 CREATE TABLE IF NOT EXISTS devices (
			     user_id       BLOB    NOT NULL,
			     device_id     BLOB    NOT NULL,
			     ed25519       BLOB    NOT NULL,
			     curve25519    BLOB    NOT NULL,
			     ssk_signature BLOB    NOT NULL,
			     display_name  TEXT    NOT NULL,
			     created_at    INTEGER NOT NULL,
			     last_seen     INTEGER NOT NULL,
			     PRIMARY KEY (user_id, device_id)
			 );

			 CREATE TABLE IF NOT EXISTS prekeys (
			     user_id        BLOB    NOT NULL,
			     device_id      BLOB    NOT NULL,
			     encryption_key BLOB    NOT NULL,
			     fallback_key   BLOB    NOT NULL,
			     last_upload_ms INTEGER NOT NULL,
			     PRIMARY KEY (user_id, device_id)
			 );

			 CREATE TABLE IF NOT EXISTS one_time_keys (
			     user_id   BLOB NOT NULL,
			     device_id BLOB NOT NULL,
			     key_id    TEXT NOT NULL,
			     key       BLOB NOT NULL,
			     PRIMARY KEY (user_id, device_id, key_id)
			 );

			 -- Frames for devices that were not connected. Retained until the
			 -- recipient acknowledges (§12.2), which is why DMs need no
			 -- sequencing: a mailbox is an unordered set.
			 CREATE TABLE IF NOT EXISTS mailbox (
			     id          INTEGER PRIMARY KEY AUTOINCREMENT,
			     user_id     BLOB    NOT NULL,
			     device_id   BLOB    NOT NULL,
			     frame       BLOB    NOT NULL,
			     received_at INTEGER NOT NULL
			 );
			 CREATE INDEX IF NOT EXISTS mailbox_recipient
			     ON mailbox (user_id, device_id, id);

			 -- Envelopes bound for another server (§3.4 step 2). The sending
			 -- server owns delivery, so this has to outlive the sender's
			 -- connection *and* the process: 'her server forwards it, queueing
			 -- and retrying if that server is down' is a promise the client
			 -- cannot keep on its own, since it may never come back online.
			 CREATE TABLE IF NOT EXISTS outbound (
			     id           INTEGER PRIMARY KEY AUTOINCREMENT,
			     host         TEXT    NOT NULL,
			     frame        BLOB    NOT NULL,
			     queued_at    INTEGER NOT NULL,
			     attempts     INTEGER NOT NULL DEFAULT 0,
			     next_try_at  INTEGER NOT NULL
			 );
			 CREATE INDEX IF NOT EXISTS outbound_due ON outbound (next_try_at);

			 -- The server's own Olm account, so its identity key survives a
			 -- restart. Clients pin that key on first connect and refuse a
			 -- changed one (invariant 6), so regenerating it at every start —
			 -- which is what happened before this table — locked out every
			 -- client the server had ever spoken to. Another server recognises
			 -- us by the same key (§3.4), so it has to be stable there too.
			 -- A community lives on exactly one host and never replicates
			 -- (§3.3), so these tables are authoritative rather than a cached
			 -- view of somebody else's state. That is the whole reason no
			 -- state resolution is needed.
			 CREATE TABLE IF NOT EXISTS communities (
			     community_id BLOB PRIMARY KEY,
			     root         TEXT    NOT NULL,   -- CommunityRoot, as JSON
			     mode         TEXT    NOT NULL,
			     created_at   INTEGER NOT NULL
			 );

			 CREATE TABLE IF NOT EXISTS community_policy (
			     community_id BLOB    NOT NULL,
			     sequence     INTEGER NOT NULL,
			     record       TEXT    NOT NULL,   -- SignedPolicy, as JSON
			     PRIMARY KEY (community_id, sequence)
			 );

			 CREATE TABLE IF NOT EXISTS community_members (
			     community_id BLOB    NOT NULL,
			     user_id      BLOB    NOT NULL,
			     joined_at    INTEGER NOT NULL,
			     PRIMARY KEY (community_id, user_id)
			 );

			 -- Ordering is the host's, not the sender's (§10.1). A member sends
			 -- one message and the host gives it a position, so nobody can
			 -- claim one -- which is what removes the need for the state
			 -- resolution Matrix uses to reconcile competing claims.
			 CREATE TABLE IF NOT EXISTS channel_messages (
			     community_id BLOB    NOT NULL,
			     channel      TEXT    NOT NULL,
			     sequence     INTEGER NOT NULL,
			     sender_user  BLOB    NOT NULL,
			     sender_device BLOB   NOT NULL,
			     body         BLOB    NOT NULL,
			     nonce        BLOB    NOT NULL,
			     origin_ts    INTEGER NOT NULL,
			     prev_hash    BLOB    NOT NULL,
			     chain_hash   BLOB    NOT NULL,
			     -- Stored rather than derived, because a tombstone has no
			     -- content left to derive it from (§10.5). The chain links
			     -- message ids, so keeping this is what lets deletion leave the
			     -- chain intact.
			     -- Nullable: SQLite only accepts constant defaults, and a
			     -- column added to an existing store cannot have a computed
			     -- one. A missing id reads as all-zero, which is what a row
			     -- written before this column existed has.
			     message_id   BLOB,
			     tombstoned   INTEGER NOT NULL DEFAULT 0,
			     PRIMARY KEY (community_id, channel, sequence)
			 );

			 CREATE TABLE IF NOT EXISTS server_identity (
			     id      INTEGER PRIMARY KEY CHECK (id = 1),
			     pickle  TEXT NOT NULL
			 );",
		)?;

		// Columns added after the table first shipped. `CREATE TABLE IF NOT
		// EXISTS` will not add them to a store that already exists, and an
		// operator's database is not something to discard on an upgrade (§1.3).
		for column in [
			"ALTER TABLE channel_messages ADD COLUMN message_id BLOB",
			"ALTER TABLE channel_messages ADD COLUMN tombstoned INTEGER NOT NULL DEFAULT 0",
		] {
			// Already present is the common case, and not an error.
			let _ = db.execute(column, []);
		}

		Ok(Self { db })
	}

	// ---- key directory ----------------------------------------------------

	/// Records a device and refreshes its owner's cross-signing keys.
	///
	/// The keys are replaced rather than kept from first sight: a user who
	/// rotates a subkey (§5.5) would otherwise have stale keys served forever,
	/// and every device enrolled under the new one would fail verification.
	/// Safe because the caller has just verified them against the user id.
	pub fn upsert_device(
		&self,
		user: &UserId,
		keys: &CrossSigningPublic,
		device: &Device,
	) -> Result<()> {
		self.db.execute(
			"INSERT INTO users (user_id, keys) VALUES (?1, ?2)
			 ON CONFLICT(user_id) DO UPDATE SET keys = excluded.keys",
			params![user.as_bytes().as_slice(), serde_json::to_string(keys)?],
		)?;

		self.db.execute(
			"INSERT INTO devices
			   (user_id, device_id, ed25519, curve25519, ssk_signature,
			    display_name, created_at, last_seen)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
			 ON CONFLICT(user_id, device_id) DO UPDATE SET
			   ed25519       = excluded.ed25519,
			   curve25519    = excluded.curve25519,
			   ssk_signature = excluded.ssk_signature,
			   display_name  = excluded.display_name,
			   last_seen     = excluded.last_seen",
			params![
				user.as_bytes().as_slice(),
				device.device_id.as_bytes().as_slice(),
				device.ed25519.as_slice(),
				device.curve25519.as_slice(),
				device.ssk_signature.as_slice(),
				device.display_name,
				device.created_at,
				device.last_seen,
			],
		)?;

		Ok(())
	}

	/// Fills in what only the key upload knows.
	pub fn complete_device(
		&self,
		address: &DeviceAddress,
		curve25519: &[u8; 32],
		display_name: &str,
		last_seen: u64,
	) -> Result<()> {
		self.db.execute(
			"UPDATE devices SET curve25519 = ?3, display_name = ?4, last_seen = ?5
			 WHERE user_id = ?1 AND device_id = ?2",
			params![
				address.user.as_bytes().as_slice(),
				address.device.as_bytes().as_slice(),
				curve25519.as_slice(),
				display_name,
				last_seen,
			],
		)?;
		Ok(())
	}

	/// A user's keys and the devices that are complete enough to serve.
	///
	/// A device is recorded at handshake but its Olm identity key only arrives
	/// with the upload that follows; serving the half-built entry would make a
	/// peer's device-list check disagree with the prekey bundle.
	pub fn device_list(&self, user: &UserId) -> Result<Option<(CrossSigningPublic, Vec<Device>)>> {
		let keys: Option<String> = self
			.db
			.query_row(
				"SELECT keys FROM users WHERE user_id = ?1",
				params![user.as_bytes().as_slice()],
				|r| r.get(0),
			)
			.optional()?;

		let Some(keys) = keys else {
			return Ok(None);
		};

		let mut stmt = self.db.prepare(
			"SELECT device_id, ed25519, curve25519, ssk_signature, display_name,
			        created_at, last_seen
			 FROM devices
			 WHERE user_id = ?1 AND curve25519 != zeroblob(32)",
		)?;

		let devices = stmt
			.query_map(params![user.as_bytes().as_slice()], |r| {
				Ok(Device {
					device_id: DeviceId::from_bytes(blob16(r.get::<_, Vec<u8>>(0)?)),
					ed25519: blob32(r.get::<_, Vec<u8>>(1)?),
					curve25519: blob32(r.get::<_, Vec<u8>>(2)?),
					ssk_signature: blob64(r.get::<_, Vec<u8>>(3)?),
					display_name: r.get(4)?,
					created_at: r.get(5)?,
					last_seen: r.get(6)?,
				})
			})?
			.collect::<Result<Vec<_>, _>>()?;

		Ok(Some((serde_json::from_str(&keys)?, devices)))
	}

	// ---- prekeys ----------------------------------------------------------

	/// Replaces a device's prekey material.
	///
	/// Refuses an upload that does not advance the clock, so a captured upload
	/// cannot be replayed to resurrect one-time keys already handed out.
	pub fn store_prekeys(
		&mut self,
		address: &DeviceAddress,
		encryption_key: &[u8; 32],
		fallback_key: &[u8; 32],
		one_time_keys: &[[u8; 32]],
		uploaded_at: u64,
	) -> Result<bool> {
		let previous: Option<u64> = self
			.db
			.query_row(
				"SELECT last_upload_ms FROM prekeys WHERE user_id = ?1 AND device_id = ?2",
				params![
					address.user.as_bytes().as_slice(),
					address.device.as_bytes().as_slice()
				],
				|r| r.get(0),
			)
			.optional()?;

		if previous.is_some_and(|last| uploaded_at <= last) {
			return Ok(false);
		}

		let tx = self.db.transaction()?;
		tx.execute(
			"INSERT INTO prekeys
			   (user_id, device_id, encryption_key, fallback_key, last_upload_ms)
			 VALUES (?1, ?2, ?3, ?4, ?5)
			 ON CONFLICT(user_id, device_id) DO UPDATE SET
			   encryption_key = excluded.encryption_key,
			   fallback_key   = excluded.fallback_key,
			   last_upload_ms = excluded.last_upload_ms",
			params![
				address.user.as_bytes().as_slice(),
				address.device.as_bytes().as_slice(),
				encryption_key.as_slice(),
				fallback_key.as_slice(),
				uploaded_at,
			],
		)?;

		tx.execute(
			"DELETE FROM one_time_keys WHERE user_id = ?1 AND device_id = ?2",
			params![
				address.user.as_bytes().as_slice(),
				address.device.as_bytes().as_slice()
			],
		)?;

		for (i, key) in one_time_keys.iter().enumerate() {
			tx.execute(
				"INSERT INTO one_time_keys (user_id, device_id, key_id, key)
				 VALUES (?1, ?2, ?3, ?4)",
				params![
					address.user.as_bytes().as_slice(),
					address.device.as_bytes().as_slice(),
					format!("otk_{i}"),
					key.as_slice(),
				],
			)?;
		}

		tx.commit()?;
		Ok(true)
	}

	/// Hands out a prekey bundle, consuming a one-time key if asked to.
	///
	/// Past the caller's budget it serves the fallback key instead, so
	/// exhaustion degrades rather than failing (§7 built invariant).
	pub fn take_prekey_bundle(
		&mut self,
		address: &DeviceAddress,
		consume: bool,
	) -> Result<Option<PrekeyBundle>> {
		let user = address.user.as_bytes().to_vec();
		let device = address.device.as_bytes().to_vec();

		let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = self
			.db
			.query_row(
				"SELECT d.ed25519, p.encryption_key, p.fallback_key
				 FROM prekeys p JOIN devices d
				   ON d.user_id = p.user_id AND d.device_id = p.device_id
				 WHERE p.user_id = ?1 AND p.device_id = ?2",
				params![user, device],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
			)
			.optional()?;

		let Some((signing_key, encryption_key, fallback_key)) = row else {
			return Ok(None);
		};

		let mut one_time_key = blob32(fallback_key);
		if consume {
			let claimed: Option<(String, Vec<u8>)> = self
				.db
				.query_row(
					"SELECT key_id, key FROM one_time_keys
					 WHERE user_id = ?1 AND device_id = ?2 LIMIT 1",
					params![user, device],
					|r| Ok((r.get(0)?, r.get(1)?)),
				)
				.optional()?;

			if let Some((key_id, key)) = claimed {
				self.db.execute(
					"DELETE FROM one_time_keys
					 WHERE user_id = ?1 AND device_id = ?2 AND key_id = ?3",
					params![user, device, key_id],
				)?;
				one_time_key = blob32(key);
			}
		}

		let remaining: i64 = self.db.query_row(
			"SELECT COUNT(*) FROM one_time_keys WHERE user_id = ?1 AND device_id = ?2",
			params![user, device],
			|r| r.get(0),
		)?;

		Ok(Some(PrekeyBundle {
			signing_key: blob32(signing_key),
			encryption_key: blob32(encryption_key),
			one_time_key,
			remaining: remaining.try_into().unwrap_or(u16::MAX),
		}))
	}

	// ---- mailbox ----------------------------------------------------------

	/// Queues a frame for a device that was not connected.
	pub fn enqueue(&self, recipient: &DeviceAddress, frame: &[u8], received_at: u64) -> Result<()> {
		self.db.execute(
			"INSERT INTO mailbox (user_id, device_id, frame, received_at)
			 VALUES (?1, ?2, ?3, ?4)",
			params![
				recipient.user.as_bytes().as_slice(),
				recipient.device.as_bytes().as_slice(),
				frame,
				received_at,
			],
		)?;
		Ok(())
	}

	/// Everything waiting for a device, oldest first.
	pub fn pending(&self, recipient: &DeviceAddress) -> Result<Vec<(i64, Vec<u8>)>> {
		let mut stmt = self.db.prepare(
			"SELECT id, frame FROM mailbox
			 WHERE user_id = ?1 AND device_id = ?2 ORDER BY id",
		)?;

		Ok(stmt
			.query_map(
				params![
					recipient.user.as_bytes().as_slice(),
					recipient.device.as_bytes().as_slice()
				],
				|r| Ok((r.get(0)?, r.get(1)?)),
			)?
			.collect::<Result<Vec<_>, _>>()?)
	}

	/// Drops frames the recipient has confirmed receiving.
	///
	/// Scoped to the acknowledging device on purpose: an id is just a row
	/// number, so without this a client could acknowledge — and therefore
	/// delete — mail addressed to somebody else.
	pub fn acknowledge_for(&self, recipient: &DeviceAddress, ids: &[i64]) -> Result<usize> {
		let mut dropped = 0;
		for id in ids {
			dropped += self.db.execute(
				"DELETE FROM mailbox WHERE id = ?1 AND user_id = ?2 AND device_id = ?3",
				params![
					id,
					recipient.user.as_bytes().as_slice(),
					recipient.device.as_bytes().as_slice()
				],
			)?;
		}
		Ok(dropped)
	}

	// ---- communities (§7, §8) ---------------------------------------------

	/// Records a community this host will serve.
	///
	/// The caller has already checked that the id is the hash of the root
	/// (invariant 13) and that the founder signed it. Storing the mode
	/// alongside is a convenience for queries, not a second source of truth —
	/// it is inside the id, so it cannot be changed under the same identity.
	pub fn create_community(
		&self,
		id: &CommunityId,
		root_json: &str,
		mode: &str,
		now: u64,
	) -> Result<bool> {
		let inserted = self.db.execute(
			"INSERT OR IGNORE INTO communities (community_id, root, mode, created_at)
			 VALUES (?1, ?2, ?3, ?4)",
			params![id.as_bytes().as_slice(), root_json, mode, now],
		)?;
		Ok(inserted == 1)
	}

	pub fn community_root(&self, id: &CommunityId) -> Result<Option<String>> {
		Ok(self
			.db
			.query_row(
				"SELECT root FROM communities WHERE community_id = ?1",
				params![id.as_bytes().as_slice()],
				|r| r.get(0),
			)
			.optional()?)
	}

	pub fn policy_chain(&self, id: &CommunityId) -> Result<Vec<String>> {
		let mut stmt = self.db.prepare(
			"SELECT record FROM community_policy WHERE community_id = ?1 ORDER BY sequence",
		)?;
		Ok(stmt
			.query_map(params![id.as_bytes().as_slice()], |r| r.get(0))?
			.collect::<Result<Vec<_>, _>>()?)
	}

	/// Appends a policy record. Fails if that sequence is already taken, which
	/// is what stops a stale record being replayed into the chain.
	pub fn append_policy(&self, id: &CommunityId, sequence: u64, record: &str) -> Result<()> {
		self.db.execute(
			"INSERT INTO community_policy (community_id, sequence, record) VALUES (?1, ?2, ?3)",
			params![id.as_bytes().as_slice(), sequence, record],
		)?;
		Ok(())
	}

	pub fn add_member(&self, id: &CommunityId, user: &UserId, now: u64) -> Result<()> {
		self.db.execute(
			"INSERT OR IGNORE INTO community_members (community_id, user_id, joined_at)
			 VALUES (?1, ?2, ?3)",
			params![id.as_bytes().as_slice(), user.as_bytes().as_slice(), now],
		)?;
		Ok(())
	}

	pub fn is_member(&self, id: &CommunityId, user: &UserId) -> Result<bool> {
		Ok(self.db.query_row(
			"SELECT EXISTS(SELECT 1 FROM community_members WHERE community_id = ?1 AND user_id = ?2)",
			params![id.as_bytes().as_slice(), user.as_bytes().as_slice()],
			|r| r.get::<_, i64>(0),
		)? == 1)
	}

	pub fn members(&self, id: &CommunityId) -> Result<Vec<UserId>> {
		let mut stmt = self
			.db
			.prepare("SELECT user_id FROM community_members WHERE community_id = ?1")?;
		let rows = stmt
			.query_map(params![id.as_bytes().as_slice()], |r| {
				r.get::<_, Vec<u8>>(0)
			})?
			.collect::<Result<Vec<_>, _>>()?;

		Ok(rows
			.into_iter()
			.filter_map(|b| b.as_slice().try_into().ok().map(UserId::from_bytes))
			.collect())
	}

	/// Files a message and hands back the position the host gave it.
	///
	/// The sequence and the previous hash come from here, never from the
	/// sender. Two messages racing get two positions; neither can claim one.
	pub fn append_channel_message(&self, delivery: &ChannelDelivery) -> Result<()> {
		self.db.execute(
			"INSERT INTO channel_messages
			   (community_id, channel, sequence, sender_user, sender_device,
			    body, nonce, origin_ts, prev_hash, chain_hash, message_id)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
			params![
				delivery.community.as_bytes().as_slice(),
				delivery.channel,
				delivery.sequence,
				delivery.sender.user.as_bytes().as_slice(),
				delivery.sender.device.as_bytes().as_slice(),
				delivery.body,
				delivery.nonce.as_slice(),
				delivery.origin_ts,
				delivery.prev_hash.as_slice(),
				delivery.chain_hash().as_slice(),
				delivery.id().as_bytes().as_slice(),
			],
		)?;
		Ok(())
	}

	/// Discards a message's content, keeping its place in the chain (§10.5).
	///
	/// Tombstoning rather than deleting the row. The chain links message ids,
	/// and a message id is a hash of the *original* content, so blanking the
	/// body leaves identity and position untouched and the chain still verifies
	/// end to end. Removing the row would break it.
	///
	/// Returns who wrote it, so the caller can decide whether this was allowed —
	/// and `None` when there is nothing at that position.
	pub fn author_of(
		&self,
		id: &CommunityId,
		channel: &str,
		sequence: u64,
	) -> Result<Option<UserId>> {
		let row: Option<Vec<u8>> = self
			.db
			.query_row(
				"SELECT sender_user FROM channel_messages
				 WHERE community_id = ?1 AND channel = ?2 AND sequence = ?3",
				params![id.as_bytes().as_slice(), channel, sequence],
				|r| r.get(0),
			)
			.optional()?;

		Ok(row.and_then(|bytes| bytes.as_slice().try_into().ok().map(UserId::from_bytes)))
	}

	pub fn tombstone(&self, id: &CommunityId, channel: &str, sequence: u64) -> Result<bool> {
		let changed = self.db.execute(
			"UPDATE channel_messages SET body = zeroblob(0), tombstoned = 1
			 WHERE community_id = ?1 AND channel = ?2 AND sequence = ?3",
			params![id.as_bytes().as_slice(), channel, sequence],
		)?;

		// **This is what makes the deletion real**, and it was found by testing
		// rather than by reasoning: blanking the row leaves the original bytes
		// sitting in the write-ahead log, so a test that grepped the store for
		// the deleted content still found it. Folding the log back in and
		// truncating it is what removes them.
		//
		// Verified by mutation: without this the content is still there;
		// without `secure_delete` it is not. So this line is load-bearing and
		// that pragma is defence in depth, not the mechanism.
		self.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

		Ok(changed == 1)
	}

	/// The tail of a channel: the next sequence, and what to chain onto.
	pub fn channel_head(&self, id: &CommunityId, channel: &str) -> Result<(u64, [u8; 32])> {
		let row: Option<(i64, Vec<u8>)> = self
			.db
			.query_row(
				"SELECT sequence, chain_hash FROM channel_messages
				 WHERE community_id = ?1 AND channel = ?2
				 ORDER BY sequence DESC LIMIT 1",
				params![id.as_bytes().as_slice(), channel],
				|r| Ok((r.get(0)?, r.get(1)?)),
			)
			.optional()?;

		Ok(match row {
			None => (1, [0u8; 32]),
			Some((sequence, hash)) => (
				sequence as u64 + 1,
				hash.as_slice().try_into().unwrap_or([0u8; 32]),
			),
		})
	}

	/// Everything in a channel after `after`, oldest first.
	pub fn channel_since(
		&self,
		id: &CommunityId,
		channel: &str,
		after: u64,
		limit: usize,
	) -> Result<Vec<ChannelDelivery>> {
		let mut stmt = self.db.prepare(
			"SELECT sequence, sender_user, sender_device, body, nonce, origin_ts,
			        prev_hash, tombstoned, message_id
			 FROM channel_messages
			 WHERE community_id = ?1 AND channel = ?2 AND sequence > ?3
			 ORDER BY sequence LIMIT ?4",
		)?;

		let community = *id;
		let channel_name = channel.to_owned();
		let rows = stmt.query_map(
			params![id.as_bytes().as_slice(), channel, after, limit as i64],
			move |r| {
				let user: Vec<u8> = r.get(1)?;
				let device: Vec<u8> = r.get(2)?;
				let nonce: Vec<u8> = r.get(4)?;
				let prev: Vec<u8> = r.get(6)?;

				Ok(ChannelDelivery {
					community,
					channel: channel_name.clone(),
					sender: DeviceAddress::new(
						UserId::from_bytes(user.as_slice().try_into().unwrap_or([0; 16])),
						DeviceId::from_bytes(device.as_slice().try_into().unwrap_or([0; 16])),
					),
					body: r.get(3)?,
					nonce: nonce.as_slice().try_into().unwrap_or([0; 16]),
					origin_ts: r.get::<_, i64>(5)? as u64,
					sequence: r.get::<_, i64>(0)? as u64,
					prev_hash: prev.as_slice().try_into().unwrap_or([0; 32]),
					tombstoned: r.get::<_, i64>(7)? == 1,
					message_id: r
						.get::<_, Option<Vec<u8>>>(8)?
						.and_then(|bytes| bytes.as_slice().try_into().ok())
						.unwrap_or([0; 32]),
				})
			},
		)?;

		Ok(rows.collect::<Result<Vec<_>, _>>()?)
	}

	// ---- the server's own identity ----------------------------------------

	/// Loads the server's account, generating one on first run.
	///
	/// Stored unencrypted alongside the rest of the database, which is the
	/// honest position: the mailbox next to it holds ciphertext the key cannot
	/// open, and there is nowhere better to put it on a box the operator
	/// already controls. Protect the database file.
	pub fn load_or_create_account(&self) -> Result<Account> {
		let existing: Option<String> = self
			.db
			.query_row("SELECT pickle FROM server_identity WHERE id = 1", [], |r| {
				r.get(0)
			})
			.optional()?;

		if let Some(pickle) = existing {
			return Ok(Account::from_pickle(serde_json::from_str(&pickle)?));
		}

		let account = Account::new();
		self.db.execute(
			"INSERT INTO server_identity (id, pickle) VALUES (1, ?1)",
			params![serde_json::to_string(&account.pickle())?],
		)?;
		Ok(account)
	}

	// ---- outbound to other servers (§3.4) ---------------------------------

	/// Is this user one of ours?
	///
	/// The question S2S turns on, in both directions: whether to deliver locally
	/// or forward, and whether an incoming deposit is ours to accept. A user is
	/// local once they have published a device here, which happens during their
	/// first handshake.
	///
	/// This is why remote device lists must never be cached in `devices` — doing
	/// so would silently make every cached stranger look like a local user, and
	/// deposits for them would be accepted into mailboxes nobody reads.
	pub fn is_local_user(&self, user: &UserId) -> Result<bool> {
		Ok(self.db.query_row(
			"SELECT EXISTS(SELECT 1 FROM devices WHERE user_id = ?1)",
			params![user.as_bytes().as_slice()],
			|r| r.get::<_, i64>(0),
		)? == 1)
	}

	/// Queues an envelope for delivery to another server.
	pub fn enqueue_outbound(&self, host: &str, frame: &[u8], now: u64) -> Result<()> {
		self.db.execute(
			"INSERT INTO outbound (host, frame, queued_at, next_try_at)
			 VALUES (?1, ?2, ?3, ?3)",
			params![host, frame, now],
		)?;
		Ok(())
	}

	/// Everything due for a retry, oldest first.
	pub fn outbound_due(&self, now: u64, limit: usize) -> Result<Vec<(i64, String, Vec<u8>, i64)>> {
		let mut stmt = self.db.prepare(
			"SELECT id, host, frame, attempts FROM outbound
			 WHERE next_try_at <= ?1 ORDER BY id LIMIT ?2",
		)?;

		Ok(stmt
			.query_map(params![now, limit as i64], |r| {
				Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
			})?
			.collect::<Result<Vec<_>, _>>()?)
	}

	pub fn drop_outbound(&self, id: i64) -> Result<()> {
		self.db
			.execute("DELETE FROM outbound WHERE id = ?1", params![id])?;
		Ok(())
	}

	/// Backs an entry off after a failed attempt.
	///
	/// Exponential, capped. Uncapped backoff would eventually schedule a retry
	/// past any plausible outage and strand the mail; a fixed short interval
	/// would hammer a server that is down for a day.
	pub fn defer_outbound(&self, id: i64, attempts: i64, now: u64) -> Result<()> {
		const CAP_MS: u64 = 60 * 60 * 1000;
		let delay = (1000u64 << attempts.min(12)).min(CAP_MS);

		self.db.execute(
			"UPDATE outbound SET attempts = ?2, next_try_at = ?3 WHERE id = ?1",
			params![id, attempts + 1, now + delay],
		)?;
		Ok(())
	}

	#[allow(dead_code)] // exposed for operators and tests, not the running server
	pub fn outbound_count(&self) -> Result<i64> {
		Ok(self
			.db
			.query_row("SELECT COUNT(*) FROM outbound", [], |r| r.get(0))?)
	}

	// ---- backup and restore (§12.3, §12.4) --------------------------------

	// Exposed for operators and tested; not called by the running server, which
	// takes backups out of band.
	#[allow(dead_code)]
	/// Writes a consistent copy of the store to `path`, safe to take while the
	/// server is running.
	///
	/// SQLite's own backup API rather than copying the file: a plain `cp` of a
	/// live WAL database can capture a torn state, which is exactly the sort of
	/// backup that looks fine until the day it is needed.
	pub fn back_up_to(&self, path: &str) -> Result<()> {
		self.db.execute("VACUUM INTO ?1", params![path])?;
		Ok(())
	}

	/// Checks a store is intact and readable.
	///
	/// A backup nobody has verified is a guess (§12.3), so this is what the
	/// restore path runs before an operator relies on it.
	pub fn verify_integrity(&self) -> Result<()> {
		let result: String = self
			.db
			.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
		if result != "ok" {
			anyhow::bail!("integrity check failed: {result}");
		}

		// Structural check as well as physical: the tables the server needs
		// must actually be present, so a restored file that is merely valid
		// SQLite is not mistaken for a working store.
		for table in ["users", "devices", "prekeys", "one_time_keys", "mailbox"] {
			let found: i64 = self.db.query_row(
				"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
				params![table],
				|r| r.get(0),
			)?;
			if found == 0 {
				anyhow::bail!("restored store has no {table} table");
			}
		}

		Ok(())
	}

	/// Rows held, for an operator checking a restore landed.
	pub fn summary(&self) -> Result<Vec<(String, i64)>> {
		let mut out = Vec::new();
		for table in ["users", "devices", "one_time_keys", "mailbox"] {
			let n: i64 = self
				.db
				.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
			out.push((table.to_owned(), n));
		}
		Ok(out)
	}

	#[cfg(test)]
	pub fn pending_count(&self, recipient: &DeviceAddress) -> Result<i64> {
		Ok(self.db.query_row(
			"SELECT COUNT(*) FROM mailbox WHERE user_id = ?1 AND device_id = ?2",
			params![
				recipient.user.as_bytes().as_slice(),
				recipient.device.as_bytes().as_slice()
			],
			|r| r.get(0),
		)?)
	}
}

fn blob16(v: Vec<u8>) -> [u8; 16] {
	let mut out = [0u8; 16];
	out.copy_from_slice(&v[..16.min(v.len())]);
	out
}
fn blob32(v: Vec<u8>) -> [u8; 32] {
	let mut out = [0u8; 32];
	out[..32.min(v.len())].copy_from_slice(&v[..32.min(v.len())]);
	out
}
fn blob64(v: Vec<u8>) -> [u8; 64] {
	let mut out = [0u8; 64];
	out[..64.min(v.len())].copy_from_slice(&v[..64.min(v.len())]);
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use veil_protocol::crosssign::CrossSigningSecrets;

	fn fixture() -> (Store, UserId, CrossSigningPublic, Device) {
		let store = Store::open(":memory:").unwrap();
		let secrets = CrossSigningSecrets::new();
		let user = secrets.user_id();
		let device_id = DeviceId::generate();
		let ed25519 = [3u8; 32];

		let device = Device {
			device_id,
			ed25519,
			curve25519: [4u8; 32],
			ssk_signature: secrets.sign_device(&device_id, &ed25519),
			display_name: "laptop".into(),
			created_at: 1,
			last_seen: 1,
		};

		(store, user, secrets.public(), device)
	}

	#[test]
	fn a_device_list_survives_and_verifies() {
		let (store, user, keys, device) = fixture();
		store.upsert_device(&user, &keys, &device).unwrap();

		let (stored_keys, devices) = store.device_list(&user).unwrap().unwrap();
		assert_eq!(devices.len(), 1);

		// The point of persisting it: what comes back still chains to the user.
		assert!(
			stored_keys
				.verify_device_list(&user, &devices)
				.unwrap()
				.len() == 1
		);
	}

	/// A device is recorded at handshake with no Olm key; serving it then would
	/// make a peer's checks disagree with the prekey bundle.
	#[test]
	fn incomplete_devices_are_withheld_until_completed() {
		let (store, user, keys, mut device) = fixture();
		device.curve25519 = [0; 32];
		store.upsert_device(&user, &keys, &device).unwrap();

		assert!(store.device_list(&user).unwrap().unwrap().1.is_empty());

		store
			.complete_device(
				&DeviceAddress::new(user, device.device_id),
				&[9; 32],
				"laptop",
				2,
			)
			.unwrap();
		assert_eq!(store.device_list(&user).unwrap().unwrap().1.len(), 1);
	}

	#[test]
	fn one_time_keys_are_consumed_then_degrade_to_the_fallback() {
		let (mut store, user, keys, device) = fixture();
		store.upsert_device(&user, &keys, &device).unwrap();
		let address = DeviceAddress::new(user, device.device_id);

		store
			.store_prekeys(&address, &[4; 32], &[99; 32], &[[1; 32], [2; 32]], 10)
			.unwrap();

		let first = store.take_prekey_bundle(&address, true).unwrap().unwrap();
		assert_eq!(first.remaining, 1);
		let second = store.take_prekey_bundle(&address, true).unwrap().unwrap();
		assert_eq!(second.remaining, 0);
		assert_ne!(first.one_time_key, second.one_time_key);

		// Exhausted: serve the fallback rather than failing.
		let third = store.take_prekey_bundle(&address, true).unwrap().unwrap();
		assert_eq!(third.one_time_key, [99; 32]);

		// Over budget: fallback without consuming.
		let fourth = store.take_prekey_bundle(&address, false).unwrap().unwrap();
		assert_eq!(fourth.one_time_key, [99; 32]);
	}

	/// A captured upload replayed later must not resurrect consumed keys.
	#[test]
	fn a_stale_prekey_upload_is_refused() {
		let (mut store, user, keys, device) = fixture();
		store.upsert_device(&user, &keys, &device).unwrap();
		let address = DeviceAddress::new(user, device.device_id);

		assert!(
			store
				.store_prekeys(&address, &[4; 32], &[9; 32], &[[1; 32]], 100)
				.unwrap()
		);
		assert!(
			!store
				.store_prekeys(&address, &[4; 32], &[9; 32], &[[1; 32], [2; 32]], 50)
				.unwrap(),
			"an older upload must not be accepted"
		);
		assert!(
			!store
				.store_prekeys(&address, &[4; 32], &[9; 32], &[[1; 32]], 100)
				.unwrap(),
			"the same upload replayed must not be accepted"
		);
	}

	/// The gap this store exists to close: a message for someone offline used
	/// to be dropped.
	#[test]
	fn mail_waits_for_a_device_that_was_not_connected() {
		let (store, user, _, device) = fixture();
		let address = DeviceAddress::new(user, device.device_id);

		store.enqueue(&address, b"first", 1).unwrap();
		store.enqueue(&address, b"second", 2).unwrap();
		assert_eq!(store.pending_count(&address).unwrap(), 2);

		let waiting = store.pending(&address).unwrap();
		assert_eq!(waiting.len(), 2);
		assert_eq!(waiting[0].1, b"first", "oldest first");

		// Acknowledged only after delivery, so an interrupted flush retries.
		store.acknowledge_for(&address, &[waiting[0].0]).unwrap();
		assert_eq!(store.pending_count(&address).unwrap(), 1);
		assert_eq!(store.pending(&address).unwrap()[0].1, b"second");
	}

	/// An id is a row number, so acknowledgement must be scoped to the device
	/// doing the acknowledging — otherwise a client could delete other people's
	/// mail by guessing.
	#[test]
	fn a_device_cannot_acknowledge_another_devices_mail() {
		let (store, user, _, device) = fixture();
		let mine = DeviceAddress::new(user, device.device_id);
		let other = DeviceAddress::new(user, DeviceId::generate());

		store.enqueue(&mine, b"private", 1).unwrap();
		let id = store.pending(&mine).unwrap()[0].0;

		assert_eq!(store.acknowledge_for(&other, &[id]).unwrap(), 0);
		assert_eq!(store.pending_count(&mine).unwrap(), 1, "mail must survive");

		assert_eq!(store.acknowledge_for(&mine, &[id]).unwrap(), 1);
		assert_eq!(store.pending_count(&mine).unwrap(), 0);
	}

	/// §12.3: a backup that has not been verified is a guess. This is the check
	/// the restore path runs.
	#[test]
	fn a_backup_restores_and_verifies() {
		let (store, user, keys, device) = fixture();
		store.upsert_device(&user, &keys, &device).unwrap();
		store
			.enqueue(&DeviceAddress::new(user, device.device_id), b"waiting", 1)
			.unwrap();

		let path = std::env::temp_dir().join(format!("veil-backup-{}.db", std::process::id()));
		let path = path.to_str().unwrap();
		let _ = std::fs::remove_file(path);
		store.back_up_to(path).unwrap();

		// Reopened cold, as an operator would after a restore.
		let restored = Store::open(path).unwrap();
		restored.verify_integrity().unwrap();

		let (_, devices) = restored.device_list(&user).unwrap().unwrap();
		assert_eq!(devices.len(), 1, "devices survive the round trip");
		assert_eq!(
			restored
				.pending_count(&DeviceAddress::new(user, device.device_id))
				.unwrap(),
			1,
			"queued mail survives too"
		);

		let summary = restored.summary().unwrap();
		assert!(summary.iter().any(|(t, n)| t == "users" && *n == 1));

		let _ = std::fs::remove_file(path);
	}

	#[test]
	fn mailboxes_do_not_leak_between_devices() {
		let (store, user, _, device) = fixture();
		let mine = DeviceAddress::new(user, device.device_id);
		let other = DeviceAddress::new(user, DeviceId::generate());

		store.enqueue(&mine, b"for me", 1).unwrap();
		assert_eq!(store.pending_count(&other).unwrap(), 0);
	}
}

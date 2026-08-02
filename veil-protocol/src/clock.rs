//! Time, without trusting the system clock — `DESIGN.md` §13.4.
//!
//! Timestamps are a security control here, not a convenience: [`crate::ReplayGuard`]
//! accepts a window around "now", so a box whose clock has drifted cannot talk
//! to anyone — and it fails as a *signature rejection*, which is close to
//! undiagnosable for whoever is running it.
//!
//! So a server asks the network what time it is and keeps the difference, rather
//! than reading its own clock and hoping. It does **not** set the system clock: a
//! container shares its host's, and adjusting it needs `CAP_SYS_TIME` and would
//! change the host. Reading the time is a plain outbound UDP request that works
//! anywhere, including in a container with no privileges at all.
//!
//! The probe blocks, deliberately — it runs at startup and then rarely, so an
//! async caller can hand it to a blocking task rather than this crate taking a
//! runtime dependency for one UDP round trip.

use std::{
	net::{ToSocketAddrs, UdpSocket},
	time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_TO_UNIX: u64 = 2_208_988_800;

/// Public pools, deliberately from different operators.
///
/// NTP is unauthenticated, so a single source is a single point of lying — and
/// an attacker who controls the answer widens the replay window. Several
/// independent answers with the median taken means one bad source is outvoted.
pub const DEFAULT_SOURCES: [&str; 4] = [
	"time.cloudflare.com:123",
	"time.google.com:123",
	"pool.ntp.org:123",
	"time.nist.gov:123",
];

fn system_now_ms() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_millis() as u64)
		.unwrap_or(0)
}

fn ntp_to_unix_ms(seconds: u32, fraction: u32) -> u64 {
	let unix_seconds = u64::from(seconds).saturating_sub(NTP_TO_UNIX);
	// The fraction is a fixed-point 2^-32 of a second.
	let millis = (u64::from(fraction) * 1_000) >> 32;
	unix_seconds * 1_000 + millis
}

/// Asks one server the time and returns the offset from our clock, in
/// milliseconds. Positive means our clock is behind.
///
/// Uses all four NTP timestamps so the round trip cancels out, rather than
/// taking the server's transmit time at face value and inheriting the latency
/// as error.
pub fn probe(source: &str, timeout: Duration) -> anyhow::Result<i64> {
	let address = source
		.to_socket_addrs()?
		.next()
		.ok_or_else(|| anyhow::anyhow!("{source} did not resolve"))?;

	let socket = UdpSocket::bind("0.0.0.0:0")?;
	socket.set_read_timeout(Some(timeout))?;
	socket.set_write_timeout(Some(timeout))?;

	// LI = 0, VN = 4, Mode = 3 (client). Everything else zero.
	let mut packet = [0u8; 48];
	packet[0] = 0b00_100_011;

	let sent_at = system_now_ms();
	socket.send_to(&packet, address)?;

	let mut response = [0u8; 48];
	let (read, from) = socket.recv_from(&mut response)?;
	let received_at = system_now_ms();

	if from.ip() != address.ip() {
		anyhow::bail!("reply came from {} rather than {}", from.ip(), address.ip());
	}
	if read < 48 {
		anyhow::bail!("short reply from {source}: {read} bytes");
	}

	let word = |at: usize| u32::from_be_bytes(response[at..at + 4].try_into().unwrap());

	// Stratum 0 means "kiss of death" — the server is telling us to go away.
	if response[1] == 0 {
		anyhow::bail!("{source} refused service (stratum 0)");
	}

	let server_received = ntp_to_unix_ms(word(32), word(36));
	let server_sent = ntp_to_unix_ms(word(40), word(44));
	if server_sent == 0 {
		anyhow::bail!("{source} returned an empty timestamp");
	}

	// offset = ((T2 - T1) + (T3 - T4)) / 2
	let out = server_received as i64 - sent_at as i64;
	let back = server_sent as i64 - received_at as i64;
	Ok((out + back) / 2)
}

/// The offset to apply to the system clock, and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sync {
	/// Agreed by a majority of sources.
	Network { offset_ms: i64, sources: usize },
	/// Nothing answered. The system clock is used as-is.
	///
	/// Air-gapped and firewalled deployments are legitimate, so this is a
	/// warning rather than a refusal to start (§13.4) — but it is a *loud* one,
	/// because it means timestamp failures are now the operator's to diagnose.
	SystemClockOnly,
}

/// Queries several sources and takes the median offset.
///
/// The median rather than the mean: one source lying, or one wildly wrong
/// answer, should not move the result at all.
pub fn synchronise(sources: &[&str], timeout: Duration) -> Sync {
	let mut offsets: Vec<i64> = sources
		.iter()
		.filter_map(|source| match probe(source, timeout) {
			Ok(offset) => Some(offset),
			Err(e) => {
				eprintln!("clock: {source} did not answer ({e})");
				None
			}
		})
		.collect();

	if offsets.is_empty() {
		return Sync::SystemClockOnly;
	}

	offsets.sort_unstable();
	Sync::Network {
		offset_ms: offsets[offsets.len() / 2],
		sources: offsets.len(),
	}
}

/// A clock that reports network time rather than the system's.
///
/// Everything that stamps or checks a protocol timestamp should read this, so
/// that a drifting host is corrected in one place instead of failing in several.
#[derive(Debug, Clone, Default)]
pub struct Clock {
	offset_ms: i64,
}

impl Clock {
	/// A clock that trusts the system, for tests and for callers that have not
	/// synchronised.
	pub fn system() -> Self {
		Self { offset_ms: 0 }
	}

	pub fn with_offset(offset_ms: i64) -> Self {
		Self { offset_ms }
	}

	pub fn from_sync(sync: Sync) -> Self {
		match sync {
			Sync::Network { offset_ms, .. } => Self { offset_ms },
			Sync::SystemClockOnly => Self::system(),
		}
	}

	pub fn offset_ms(&self) -> i64 {
		self.offset_ms
	}

	pub fn now_ms(&self) -> u64 {
		system_now_ms().saturating_add_signed(self.offset_ms)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn an_ntp_timestamp_converts_to_unix_millis() {
		// 1970-01-01 in NTP terms is exactly the epoch difference.
		assert_eq!(ntp_to_unix_ms(NTP_TO_UNIX as u32, 0), 0);
		assert_eq!(ntp_to_unix_ms(NTP_TO_UNIX as u32 + 1, 0), 1_000);
		// Half a second is the top bit of the fraction.
		assert_eq!(ntp_to_unix_ms(NTP_TO_UNIX as u32, 1 << 31), 500);
	}

	#[test]
	fn an_offset_shifts_the_clock() {
		let system = Clock::system();
		let ahead = Clock::with_offset(60_000);
		let behind = Clock::with_offset(-60_000);

		assert!(ahead.now_ms() > system.now_ms());
		assert!(behind.now_ms() < system.now_ms());
		assert_eq!(ahead.offset_ms(), 60_000);
	}

	/// Unreachable sources must degrade to the system clock rather than
	/// stopping a server from starting — air-gapped deployments are legitimate.
	#[test]
	fn no_reachable_source_degrades_to_the_system_clock() {
		// Reserved for documentation, so nothing is listening.
		let sync = synchronise(&["192.0.2.1:123"], Duration::from_millis(150));
		assert_eq!(sync, Sync::SystemClockOnly);
		assert_eq!(Clock::from_sync(sync).offset_ms(), 0);
	}

	#[test]
	fn a_network_sync_becomes_the_clocks_offset() {
		let clock = Clock::from_sync(Sync::Network {
			offset_ms: 1_234,
			sources: 3,
		});
		assert_eq!(clock.offset_ms(), 1_234);
	}
}

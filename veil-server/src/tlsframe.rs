//! TLS record framing validation for the relay — `DESIGN.md` §3.2.
//!
//! The relay forwards bytes it cannot read, which is what keeps it out of the
//! trust set. But a server that opens connections on a user's behalf and cannot
//! inspect the traffic is an open proxy, so it has to constrain *something*.
//!
//! §3.2 settles on TLS records rather than a Veil-specific outer frame, and the
//! reason is versioning: a custom frame couples relay upgrades to protocol
//! evolution, so a relay on older software could not forward newer frame types
//! and every protocol change would need a fleet upgrade before it could ship.
//! TLS records already expose type and length while keeping contents encrypted,
//! which is all the relay needs.
//!
//! What this actually buys: the tunnel carries TLS and nothing else. It cannot
//! be pointed at a plaintext HTTP server, an SMTP server or a DNS resolver and
//! made to carry a useful payload, because none of those speak in records that
//! pass this check. Combined with the destination handshake (invariant 15),
//! which proves the far end is a Veil server, the general open-proxy vector is
//! removed rather than mitigated.
//!
//! It is deliberately *not* a security boundary against the client: someone can
//! obviously emit well-formed records containing anything they like. The point
//! is that the destination is already proven to be a Veil host, so there is
//! nothing on the other end for that traffic to reach.

/// A TLS record header: content type, version, and a 16-bit length.
const HEADER: usize = 5;

/// Largest record body TLS permits.
///
/// 2^14 of plaintext, plus room for the AEAD expansion a ciphertext record
/// carries. Anything larger is not TLS, and forwarding it would let the tunnel
/// be used to make a peer allocate.
const MAX_BODY: usize = (1 << 14) + 2048;

/// Streaming check that what passes through is TLS.
///
/// Stateful because records span writes: a 4 KiB record arriving in three
/// chunks is normal, and a checker that looked at each chunk in isolation would
/// reject ordinary traffic.
pub struct RecordValidator {
	/// Bytes still to come in the record being carried.
	remaining: usize,
	/// Partial header, when a write split one.
	header: Vec<u8>,
	/// Whether the first record has been seen.
	started: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
	Ok,
	/// Not TLS. The tunnel is closed rather than the bytes dropped — a peer
	/// sending this is either broken or probing, and neither deserves a
	/// half-open connection.
	NotTls(&'static str),
}

impl Default for RecordValidator {
	fn default() -> Self {
		Self::new()
	}
}

impl RecordValidator {
	pub fn new() -> Self {
		Self {
			remaining: 0,
			header: Vec::with_capacity(HEADER),
			started: false,
		}
	}

	/// Whether any complete record has been seen yet.
	///
	/// Used to refuse a tunnel that never carried TLS at all, as distinct from
	/// one carrying it badly.
	pub fn saw_tls(&self) -> bool {
		self.started
	}

	pub fn check(&mut self, mut bytes: &[u8]) -> Verdict {
		while !bytes.is_empty() {
			// Mid-record: skip the body without looking at it. This is the
			// branch that runs for essentially all traffic.
			if self.remaining > 0 {
				let taken = self.remaining.min(bytes.len());
				self.remaining -= taken;
				bytes = &bytes[taken..];
				continue;
			}

			let wanted = HEADER - self.header.len();
			let taken = wanted.min(bytes.len());
			self.header.extend_from_slice(&bytes[..taken]);
			bytes = &bytes[taken..];

			if self.header.len() < HEADER {
				return Verdict::Ok; // header split across writes; wait for more
			}

			match Self::parse_header(&self.header) {
				Ok(length) => {
					self.remaining = length;
					self.started = true;
					self.header.clear();
				}
				Err(why) => {
					self.header.clear();
					return Verdict::NotTls(why);
				}
			}
		}

		Verdict::Ok
	}

	fn parse_header(header: &[u8]) -> Result<usize, &'static str> {
		// 20 change_cipher_spec, 21 alert, 22 handshake, 23 application_data.
		// 24 heartbeat is excluded on purpose: it is the extension behind
		// Heartbleed, nothing in Veil uses it, and there is no reason to carry
		// it to a host that does not want it either.
		if !(20..=23).contains(&header[0]) {
			return Err("record content type is not TLS");
		}

		// The legacy version field. TLS 1.3 pins it to 0x0303 on everything
		// after the first ClientHello, which may carry 0x0301 for compatibility.
		if header[1] != 0x03 || header[2] > 0x04 {
			return Err("record version is not TLS");
		}

		let length = u16::from_be_bytes([header[3], header[4]]) as usize;
		if length == 0 || length > MAX_BODY {
			return Err("record length is out of range");
		}

		Ok(length)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn record(kind: u8, body: usize) -> Vec<u8> {
		let mut out = vec![kind, 0x03, 0x03];
		out.extend_from_slice(&(body as u16).to_be_bytes());
		out.extend(std::iter::repeat_n(0xAB, body));
		out
	}

	#[test]
	fn ordinary_traffic_passes() {
		let mut v = RecordValidator::new();
		assert_eq!(v.check(&record(22, 512)), Verdict::Ok); // handshake
		assert_eq!(v.check(&record(23, 4096)), Verdict::Ok); // application data
		assert!(v.saw_tls());
	}

	/// The case a naive per-chunk checker gets wrong: records do not arrive
	/// aligned to writes, and rejecting a split one would break every real
	/// connection.
	#[test]
	fn a_record_split_across_writes_passes() {
		let full = record(23, 4096);
		let mut v = RecordValidator::new();

		for chunk in full.chunks(100) {
			assert_eq!(v.check(chunk), Verdict::Ok);
		}
		assert!(v.saw_tls());
	}

	/// Including a split *header*, which is the awkward one — fewer than five
	/// bytes is not enough to decide anything.
	#[test]
	fn a_header_split_across_writes_passes() {
		let full = record(23, 64);
		let mut v = RecordValidator::new();

		assert_eq!(v.check(&full[..2]), Verdict::Ok);
		assert_eq!(v.check(&full[2..4]), Verdict::Ok);
		assert_eq!(v.check(&full[4..]), Verdict::Ok);
		assert!(v.saw_tls());
	}

	#[test]
	fn plain_http_is_refused() {
		let mut v = RecordValidator::new();
		assert!(matches!(
			v.check(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			Verdict::NotTls(_)
		));
		assert!(!v.saw_tls());
	}

	/// The open-proxy case that matters: a tunnel must not be usable to speak
	/// to a plaintext service.
	#[test]
	fn other_plaintext_protocols_are_refused() {
		for probe in [
			&b"EHLO evil.example\r\n"[..],            // SMTP
			&b"*1\r\n$4\r\nPING\r\n"[..],             // Redis
			&b"\x00\x00\x00\x00\x00\x01\x00\x00"[..], // DNS-ish
		] {
			let mut v = RecordValidator::new();
			assert!(
				matches!(v.check(probe), Verdict::NotTls(_)),
				"should have refused {probe:?}"
			);
		}
	}

	#[test]
	fn an_oversized_record_is_refused() {
		let mut header = vec![23, 0x03, 0x03];
		header.extend_from_slice(&u16::MAX.to_be_bytes());
		assert!(matches!(
			RecordValidator::new().check(&header),
			Verdict::NotTls(_)
		));
	}

	#[test]
	fn an_unknown_content_type_is_refused() {
		// 24 is heartbeat, deliberately excluded.
		for kind in [0u8, 19, 24, 255] {
			let mut v = RecordValidator::new();
			assert!(
				matches!(v.check(&record(kind, 16)), Verdict::NotTls(_)),
				"content type {kind} should not pass"
			);
		}
	}

	/// A valid first record does not license whatever follows it.
	#[test]
	fn junk_after_a_good_record_is_still_caught() {
		let mut v = RecordValidator::new();
		assert_eq!(v.check(&record(22, 32)), Verdict::Ok);
		assert!(matches!(v.check(b"GET / HTTP/1.1\r\n"), Verdict::NotTls(_)));
	}

	/// Body bytes are skipped without inspection, so a record whose *contents*
	/// look like HTTP still passes. That is the design: the relay validates
	/// framing and never content.
	#[test]
	fn record_contents_are_not_inspected() {
		let body = b"GET / HTTP/1.1\r\n";
		let mut framed = vec![23, 0x03, 0x03];
		framed.extend_from_slice(&(body.len() as u16).to_be_bytes());
		framed.extend_from_slice(body);

		assert_eq!(RecordValidator::new().check(&framed), Verdict::Ok);
	}
}

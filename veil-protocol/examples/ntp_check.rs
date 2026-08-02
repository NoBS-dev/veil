fn main() {
	use std::time::Duration;
	use veil_protocol::clock::{self, Sync};
	for s in clock::DEFAULT_SOURCES {
		match clock::probe(s, Duration::from_secs(3)) {
			Ok(o) => println!("  {s:<26} offset {o:+} ms"),
			Err(e) => println!("  {s:<26} failed: {e}"),
		}
	}
	match clock::synchronise(&clock::DEFAULT_SOURCES, Duration::from_secs(3)) {
		Sync::Network { offset_ms, sources } => {
			println!("  => median {offset_ms:+} ms from {sources} source(s)")
		}
		Sync::SystemClockOnly => println!("  => no source answered; system clock"),
	}
}

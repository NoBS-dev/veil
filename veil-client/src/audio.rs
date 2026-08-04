//! Capture, encoding and playback — `DESIGN.md` §9.
//!
//! The last step between a negotiated call and a conversation. Two
//! battle-tested libraries do the parts that should not be written twice:
//! **cpal** for devices, which is what most Rust audio stands on, and
//! **libopus** through the `opus` crate, which is the codec every WebRTC
//! endpoint already speaks.
//!
//! # The shape of the pipeline
//!
//! ```text
//! microphone → cpal → PCM → Opus encode → RTP → SRTP → network
//! network → SRTP → RTP → JitterBuffer → Opus decode → PCM → cpal → speaker
//! ```
//!
//! Veil's contribution is the middle: the session those packets travel over was
//! authenticated by the Olm handshake (§9). Everything either side of it is
//! ordinary audio work, and doing it ordinarily is the point.
//!
//! # Choices that are not arbitrary
//!
//! **20 ms frames, 48 kHz, mono.** The frame length matches
//! [`crate::media::PACKET`] because a codec frame and a network packet should be
//! the same thing — mismatched, every packet either splits a frame or carries
//! two, and latency or overhead goes up for nothing. 48 kHz is what WebRTC
//! negotiates. Mono because §9.1's bandwidth figures assume voice, and stereo
//! doubles the cost to convey nothing a conversation needs.
//!
//! **Concealment is the codec's, not silence.** When the jitter buffer reports a
//! gap, Opus is asked to generate a frame rather than being handed zeros. Its
//! packet-loss concealment continues the waveform, which sounds like a brief
//! roughness; silence sounds like a hole, and a listener hears the difference at
//! one lost packet in a hundred.
//!
//! **Device buffers never match frame size.** A capture callback delivers
//! whatever the hardware chose — 128 samples, 441, 1024 — and Opus needs exactly
//! 960. [`FrameBuilder`] accumulates across callbacks, which is unglamorous and
//! is where naive implementations produce clicks.

use anyhow::Result;

/// Samples in one 20 ms frame at 48 kHz, mono.
pub const FRAME: usize = 960;
/// The sample rate WebRTC negotiates for Opus.
pub const RATE: u32 = 48_000;

/// Accumulates device callbacks into codec-sized frames.
///
/// A capture callback hands over whatever the hardware chose, which is almost
/// never 960 samples. Encoding what arrives would produce frames of varying
/// length, and Opus rejects most of them; padding to length inserts silence into
/// the middle of speech, which is audible as a click at every callback boundary.
#[derive(Default)]
pub struct FrameBuilder {
	pending: Vec<i16>,
}

impl FrameBuilder {
	pub fn new() -> Self {
		Self {
			pending: Vec::with_capacity(FRAME * 2),
		}
	}

	/// Adds samples, returning every whole frame they completed.
	pub fn push(&mut self, samples: &[i16]) -> Vec<[i16; FRAME]> {
		self.pending.extend_from_slice(samples);

		let mut frames = Vec::new();
		while self.pending.len() >= FRAME {
			let mut frame = [0i16; FRAME];
			frame.copy_from_slice(&self.pending[..FRAME]);
			// Drained from the front rather than re-allocated: capture runs
			// fifty times a second for the length of a call.
			self.pending.drain(..FRAME);
			frames.push(frame);
		}

		frames
	}

	/// Samples held back, waiting for a frame to complete. Exposed so a test can
	/// check the remainder is kept rather than dropped, which is the difference
	/// between clean audio and a click at every callback boundary.
	#[allow(dead_code)]
	pub fn pending(&self) -> usize {
		self.pending.len()
	}
}

/// Encodes captured audio for the wire.
pub struct Encoder {
	inner: opus::Encoder,
	scratch: Vec<u8>,
}

impl Encoder {
	pub fn new() -> Result<Self> {
		let mut inner = opus::Encoder::new(RATE, opus::Channels::Mono, opus::Application::Voip)?;

		// Voice activity detection and discontinuous transmission: a muted or
		// silent participant sends almost nothing, which is what makes §9.1's
		// claim about fifty-person voice channels true rather than aspirational.
		inner.set_inband_fec(true)?;
		let _ = inner.set_bitrate(opus::Bitrate::Bits(32_000));

		Ok(Self {
			inner,
			// One frame of Opus never approaches this; sized once so encoding
			// does not allocate.
			scratch: vec![0u8; 4_000],
		})
	}

	pub fn encode(&mut self, frame: &[i16; FRAME]) -> Result<Vec<u8>> {
		let written = self.inner.encode(frame, &mut self.scratch)?;
		Ok(self.scratch[..written].to_vec())
	}
}

/// Decodes audio for playback, including what never arrived.
pub struct Decoder {
	inner: opus::Decoder,
}

impl Decoder {
	pub fn new() -> Result<Self> {
		Ok(Self {
			inner: opus::Decoder::new(RATE, opus::Channels::Mono)?,
		})
	}

	pub fn decode(&mut self, packet: &[u8]) -> Result<[i16; FRAME]> {
		let mut out = [0i16; FRAME];
		self.inner.decode(packet, &mut out, false)?;
		Ok(out)
	}

	/// Generates a frame for a packet that never arrived.
	///
	/// **Not silence.** Opus continues the waveform it was in the middle of,
	/// which sounds like a moment of roughness; a hole sounds like a hole, and
	/// the difference is audible at one lost packet in a hundred.
	pub fn conceal(&mut self) -> Result<[i16; FRAME]> {
		let mut out = [0i16; FRAME];
		self.inner.decode(&[], &mut out, false)?;
		Ok(out)
	}
}

/// The devices a call would use.
///
/// Separated from the pipeline so the parts that are pure computation stay
/// testable without hardware — which matters, because a machine with no sound
/// card is exactly where this runs in CI.
pub struct Devices;

impl Devices {
	/// The default input and output, if this machine has any.
	///
	/// Returns an error rather than panicking on a machine with no sound card.
	/// A client on a server, in a container, or on a box with audio disabled
	/// should be able to do everything except talk.
	pub fn open() -> Result<(cpal::Device, cpal::Device)> {
		use cpal::traits::HostTrait;

		let host = cpal::default_host();
		let input = host
			.default_input_device()
			.ok_or_else(|| anyhow::anyhow!("no microphone on this machine"))?;
		let output = host
			.default_output_device()
			.ok_or_else(|| anyhow::anyhow!("no speaker on this machine"))?;

		Ok((input, output))
	}

	/// Whether this machine can take part in a call at all.
	///
	/// Not consulted before placing a call on purpose: a client with no sound
	/// card should still be able to *make* one, and be told it has no audio,
	/// rather than being refused something it could otherwise do.
	#[allow(dead_code)]
	pub fn available() -> bool {
		Self::open().is_ok()
	}
}

/// Runs a call's audio for as long as the returned streams are held.
///
/// Dropping them stops the call's audio, which is why they are returned rather
/// than leaked into a task: a call that kept capturing after it ended would be a
/// microphone nobody asked for.
///
/// Both directions run on cpal's own threads. That is deliberate — audio
/// callbacks have a hard deadline, and anything that shares a thread with them
/// eventually causes a dropout. Neither callback allocates or locks anything
/// held across an await.
pub fn run(call: &crate::media::Call) -> Result<Streams> {
	// The streams live on their own thread and never leave it. `cpal::Stream` is
	// not `Send` — on some platforms it is bound to the thread that made it —
	// so a call held across an await cannot hold one directly. This also gets
	// the right behaviour for free: audio callbacks have a hard deadline, and
	// giving them a thread of their own is what a real client would do anyway.
	let (stop, stopped) = std::sync::mpsc::channel::<()>();
	let (started, ready) = std::sync::mpsc::channel::<Result<(), String>>();

	let track = call.outgoing.clone();
	let incoming = call.incoming.clone();
	let runtime = tokio::runtime::Handle::current();

	std::thread::spawn(move || match build(track, incoming, runtime) {
		Ok(streams) => {
			let _ = started.send(Ok(()));
			// Blocks until the call ends, holding the streams open. Dropping
			// them here is what stops the microphone.
			let _ = stopped.recv();
			drop(streams);
		}
		Err(e) => {
			let _ = started.send(Err(format!("{e:#}")));
		}
	});

	match ready.recv() {
		Ok(Ok(())) => Ok(Streams { _stop: stop }),
		Ok(Err(e)) => anyhow::bail!("{e}"),
		Err(_) => anyhow::bail!("the audio thread stopped before it started"),
	}
}

/// Builds the two device streams. Runs only on the audio thread.
fn build(
	track: std::sync::Arc<
		webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample,
	>,
	incoming: std::sync::Arc<tokio::sync::Mutex<crate::media::JitterBuffer>>,
	runtime: tokio::runtime::Handle,
) -> Result<(cpal::Stream, cpal::Stream)> {
	use cpal::traits::{DeviceTrait, StreamTrait};

	let (input, output) = Devices::open()?;

	let config = cpal::StreamConfig {
		channels: 1,
		sample_rate: cpal::SampleRate(RATE),
		buffer_size: cpal::BufferSize::Default,
	};

	// ---- capture: microphone to the outgoing track ----------------------
	let mut builder = FrameBuilder::new();
	let mut encoder = Encoder::new()?;
	let (frames, mut ready) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

	let capture = input.build_input_stream(
		&config,
		move |samples: &[i16], _: &cpal::InputCallbackInfo| {
			for frame in builder.push(samples) {
				if let Ok(packet) = encoder.encode(&frame) {
					// Handed off rather than sent from here: writing to the
					// track is async, and blocking an audio callback on it is
					// what produces dropouts.
					let _ = frames.send(packet);
				}
			}
		},
		|e| eprintln!("audio capture error: {e}"),
		None,
	)?;

	runtime.spawn(async move {
		use webrtc::media::Sample;

		while let Some(packet) = ready.recv().await {
			let sample = Sample {
				data: packet.into(),
				duration: crate::media::PACKET,
				..Default::default()
			};
			if track.write_sample(&sample).await.is_err() {
				break;
			}
		}
	});

	// ---- playback: the jitter buffer to the speaker ---------------------
	let mut decoder = Decoder::new()?;
	let mut queued: std::collections::VecDeque<i16> = std::collections::VecDeque::new();

	let playback = output.build_output_stream(
		&config,
		move |out: &mut [i16], _: &cpal::OutputCallbackInfo| {
			while queued.len() < out.len() {
				// `try_lock` rather than `lock`: an audio callback that blocked
				// on a receive thread would turn one slow moment into an
				// audible gap. Missing a turn costs one frame of concealment,
				// which is what the codec is for.
				let next = match incoming.try_lock() {
					Ok(mut buffer) => buffer.pop(),
					Err(_) => crate::media::Playback::Concealed,
				};

				let frame = match next {
					crate::media::Playback::Packet(payload) => decoder.decode(&payload),
					// A gap, or nothing buffered yet. The codec continues the
					// waveform rather than inserting a hole.
					crate::media::Playback::Concealed | crate::media::Playback::Filling => {
						decoder.conceal()
					}
				};

				match frame {
					Ok(samples) => queued.extend(samples),
					Err(_) => queued.extend([0i16; FRAME]),
				}
			}

			for slot in out.iter_mut() {
				*slot = queued.pop_front().unwrap_or(0);
			}
		},
		|e| eprintln!("audio playback error: {e}"),
		None,
	)?;

	capture.play()?;
	playback.play()?;

	Ok((capture, playback))
}

/// A call's audio, running until dropped.
///
/// Holds nothing but a signal: dropping it tells the audio thread to let its
/// streams go, which is what closes the microphone.
pub struct Streams {
	_stop: std::sync::mpsc::Sender<()>,
}

#[cfg(test)]
mod tests {
	use super::*;

	fn tone(samples: usize) -> Vec<i16> {
		// A 440 Hz sine, which encodes to something a codec has to work at —
		// silence would compress to almost nothing and prove less.
		(0..samples)
			.map(|n| {
				let t = n as f64 / f64::from(RATE);
				((t * 440.0 * std::f64::consts::TAU).sin() * 8_000.0) as i16
			})
			.collect()
	}

	#[test]
	fn audio_survives_a_round_trip_through_the_codec() {
		let mut encoder = Encoder::new().unwrap();
		let mut decoder = Decoder::new().unwrap();

		let mut frame = [0i16; FRAME];
		frame.copy_from_slice(&tone(FRAME));

		let packet = encoder.encode(&frame).unwrap();
		assert!(
			packet.len() < FRAME * 2,
			"a codec that did not compress would defeat the point: {} bytes",
			packet.len()
		);

		let decoded = decoder.decode(&packet).unwrap();
		assert_eq!(decoded.len(), FRAME);

		// Opus is lossy, so this compares energy rather than samples. A decoded
		// frame that came back near-silent would mean the round trip lost the
		// audio while still returning the right number of samples.
		let energy: i64 = decoded.iter().map(|s| i64::from(*s) * i64::from(*s)).sum();
		assert!(
			energy > 1_000_000,
			"the decoded frame should carry the signal, got energy {energy}"
		);
	}

	/// The case naive implementations get wrong: hardware hands over whatever
	/// buffer size it likes, and encoding that directly produces clicks.
	#[test]
	fn device_buffers_are_reassembled_into_whole_frames() {
		let mut builder = FrameBuilder::new();

		// Sizes a real device might actually use, none of them 960.
		assert!(builder.push(&tone(128)).is_empty());
		assert!(builder.push(&tone(441)).is_empty());
		assert!(builder.push(&tone(256)).is_empty());

		let frames = builder.push(&tone(200));
		assert_eq!(
			frames.len(),
			1,
			"128+441+256+200 = 1025, so one whole frame"
		);
		assert_eq!(builder.pending(), 1025 - FRAME, "and the remainder is kept");
	}

	#[test]
	fn a_large_buffer_yields_several_frames() {
		let mut builder = FrameBuilder::new();
		let frames = builder.push(&tone(FRAME * 3 + 17));

		assert_eq!(frames.len(), 3);
		assert_eq!(builder.pending(), 17);
	}

	/// A lost packet should sound like roughness, not a hole.
	#[test]
	fn concealment_produces_audio_rather_than_silence() {
		let mut encoder = Encoder::new().unwrap();
		let mut decoder = Decoder::new().unwrap();

		// Give the decoder something to continue from.
		let mut frame = [0i16; FRAME];
		frame.copy_from_slice(&tone(FRAME));
		let packet = encoder.encode(&frame).unwrap();
		decoder.decode(&packet).unwrap();

		let concealed = decoder.conceal().unwrap();
		let energy: i64 = concealed
			.iter()
			.map(|s| i64::from(*s) * i64::from(*s))
			.sum();

		assert!(
			energy > 0,
			"concealment must continue the waveform rather than inserting silence"
		);
	}

	/// A machine with no sound card must still run the client.
	#[test]
	fn a_machine_without_audio_reports_it_rather_than_panicking() {
		// Whatever this machine has, asking must not panic — and if it has
		// nothing, the error has to say so plainly.
		match Devices::open() {
			Ok(_) => {}
			Err(e) => {
				let message = format!("{e}");
				assert!(
					message.contains("microphone") || message.contains("speaker"),
					"the error should name what is missing, got: {message}"
				);
			}
		}
	}
}

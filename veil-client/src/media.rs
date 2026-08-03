//! Real-time media — `DESIGN.md` §9.
//!
//! **A 1:1 call needs no new cryptography** (§9), and this file is what that
//! claim cashes out to. WebRTC's DTLS-SRTP encrypts the media end to end; the
//! only thing that would make it forgeable is unauthenticated signalling, and
//! the SDP produced here travels over an Olm session to a cross-signed device.
//! So the fingerprint inside it is authenticated, and there is no new PKI, no
//! per-frame keying, and no MLS.
//!
//! # Where the performance actually is
//!
//! Not in the encryption. SRTP is AES-GCM over a ~160-byte payload — tens of
//! nanoseconds, against a 20 ms packet interval, so it is roughly a millionth of
//! the budget. Anyone who says an encrypted call is slow because of the
//! encryption has measured something else.
//!
//! What people hear is **latency and jitter**, and those come from four places:
//!
//! 1. **The jitter buffer**, which is the single biggest lever. Too small and
//!    every network hiccup is an audible gap; too large and the call feels like
//!    a satellite link. [`JitterBuffer`] adapts rather than picking a constant.
//! 2. **Packet loss concealment.** A lost packet must produce silence of the
//!    right length rather than a skipped instant, or speech speeds up and
//!    pitches oddly.
//! 3. **Allocation.** At 50 packets a second per stream, a per-packet allocation
//!    is 50 trips to the allocator a second doing nothing useful. The buffer
//!    reuses its storage.
//! 4. **The relay hop.** Relayed media takes a detour and pays for it in latency,
//!    which is what the P2P escalation in §9.1 exists to let people trade away —
//!    with both parties' consent, per call.

use anyhow::Result;
use std::{
	collections::{BTreeMap, HashMap},
	sync::Arc,
	time::Duration,
};
use tokio::sync::Mutex;

/// Calls in progress, by call id.
///
/// Outside `State` because a session is not serialisable and should not be: a
/// call does not survive the process, and a stored one would be an invitation to
/// resume something the other party has long since hung up on.
pub type Calls = Arc<Mutex<HashMap<[u8; 16], Call>>>;

pub fn calls() -> Calls {
	Arc::new(Mutex::new(HashMap::new()))
}

/// Reorders and paces incoming audio, adapting to the network it finds.
///
/// Fed by [`Session::on_audio`], which reads RTP off the wire and pushes it
/// here. What remains unwired is the far end: turning what comes out of this
/// into sound needs a playback device, which is a hardware concern rather than
/// a protocol one.
///
/// RTP arrives out of order, in bursts, and with gaps. Playback needs a steady
/// 20 ms tick. The buffer absorbs the difference, and how much it absorbs is the
/// whole trade: every millisecond held is a millisecond of delay added to the
/// conversation, and every millisecond not held is a chance to run dry.
///
/// **Adaptive rather than fixed**, because the right depth on a wired connection
/// and on a train differ by an order of magnitude, and a constant chosen for the
/// worst case makes every good connection feel bad.
pub struct JitterBuffer {
	/// Packets by sequence number. Ordered, so draining is a front pop and
	/// reordering costs nothing.
	packets: BTreeMap<u16, Vec<u8>>,
	/// Storage handed back for reuse, so steady state does not allocate.
	spare: Vec<Vec<u8>>,
	/// Next sequence number to play.
	next: Option<u16>,
	/// Earliest sequence held, in *sequence space* rather than numerically.
	///
	/// Needed because a `BTreeMap` orders by value, and across a wrap the
	/// numerically smallest key is the newest packet rather than the oldest.
	/// Starting playback from it would skip everything before the wrap and then
	/// treat it all as late.
	lowest: Option<u16>,
	/// Current target depth, in packets.
	target: usize,
	/// Observed arrival spread, smoothed.
	jitter: f64,
	last_arrival: Option<Duration>,
	last_sequence: Option<u16>,
	/// Packets that arrived after their slot had already played.
	late: u64,
	/// Slots that had to be concealed because nothing arrived.
	concealed: u64,
}

/// One packet interval. Opus at 20 ms is the standard trade between overhead and
/// latency: shorter multiplies per-packet header cost, longer adds delay nobody
/// gets back.
#[allow(dead_code)]
pub const PACKET: Duration = Duration::from_millis(20);

/// Never hold less than this. Below two packets any reordering at all becomes a
/// gap.
#[allow(dead_code)]
const MIN_DEPTH: usize = 2;
/// Never hold more than this. Past about half a second a conversation stops
/// working — people talk over each other — so dropping audio is the better
/// failure.
#[allow(dead_code)]
const MAX_DEPTH: usize = 25;

#[allow(dead_code)]
impl Default for JitterBuffer {
	fn default() -> Self {
		Self::new()
	}
}

#[allow(dead_code)]
impl JitterBuffer {
	pub fn new() -> Self {
		Self {
			packets: BTreeMap::new(),
			spare: Vec::new(),
			next: None,
			lowest: None,
			target: MIN_DEPTH,
			jitter: 0.0,
			last_arrival: None,
			last_sequence: None,
			late: 0,
			concealed: 0,
		}
	}

	/// Accepts a packet, and reports whether it was usable.
	///
	/// A packet whose slot has already played is counted and dropped: putting it
	/// back would play audio out of order, which sounds worse than the gap it
	/// would fill.
	pub fn push(&mut self, sequence: u16, payload: &[u8], arrived_at: Duration) -> Accepted {
		self.observe(sequence, arrived_at);

		if let Some(next) = self.next
			&& sequence_before(sequence, next)
		{
			self.late += 1;
			return Accepted::TooLate;
		}

		// Reuse storage rather than allocating per packet.
		let mut slot = self.spare.pop().unwrap_or_default();
		slot.clear();
		slot.extend_from_slice(payload);

		if let Some(displaced) = self.packets.insert(sequence, slot) {
			// A duplicate. Keep the first and recycle the second.
			self.recycle(displaced);
			return Accepted::Duplicate;
		}

		if self
			.lowest
			.is_none_or(|lowest| sequence_before(sequence, lowest))
		{
			self.lowest = Some(sequence);
		}

		Accepted::Yes
	}

	/// Takes the next packet to play, if the buffer has filled enough.
	///
	/// `None` before the target depth is reached is the buffer doing its job —
	/// starting playback immediately is what produces a call that stutters for
	/// its first few seconds.
	pub fn pop(&mut self) -> Playback {
		if self.packets.len() < self.target && self.next.is_none() {
			return Playback::Filling;
		}

		let wanted = match self.next {
			Some(next) => next,
			// The earliest in sequence space, which across a wrap is not the
			// numerically smallest key.
			None => match self.lowest {
				Some(first) => first,
				None => return Playback::Filling,
			},
		};

		match self.packets.remove(&wanted) {
			Some(payload) => {
				self.next = Some(wanted.wrapping_add(1));
				Playback::Packet(payload)
			}
			// Nothing for this slot. Concealed rather than skipped: skipping
			// shortens the stream and speech runs fast.
			None if !self.packets.is_empty() || self.next.is_some() => {
				self.next = Some(wanted.wrapping_add(1));
				self.concealed += 1;
				Playback::Concealed
			}
			None => Playback::Filling,
		}
	}

	/// Hands storage back for reuse.
	pub fn recycle(&mut self, mut buffer: Vec<u8>) {
		// Bounded, so a burst does not leave memory held forever.
		if self.spare.len() < MAX_DEPTH {
			buffer.clear();
			self.spare.push(buffer);
		}
	}

	/// How deep the buffer is currently trying to be, in packets.
	pub fn target_depth(&self) -> usize {
		self.target
	}

	pub fn held(&self) -> usize {
		self.packets.len()
	}

	/// Packets that arrived after their slot had played.
	pub fn late(&self) -> u64 {
		self.late
	}

	/// Slots played as silence because nothing arrived in time.
	pub fn concealed(&self) -> u64 {
		self.concealed
	}

	/// Updates the arrival-spread estimate and the depth that follows from it.
	///
	/// The estimate is RFC 3550's: a smoothed mean deviation of inter-arrival
	/// time from the expected interval. Smoothed because reacting to a single
	/// late packet would make the buffer oscillate, which is audible.
	fn observe(&mut self, sequence: u16, arrived_at: Duration) {
		if let (Some(previous), Some(last_sequence)) = (self.last_arrival, self.last_sequence) {
			let gap = sequence.wrapping_sub(last_sequence) as u32;
			if gap > 0 && gap < 100 {
				let expected = PACKET.as_secs_f64() * f64::from(gap);
				let actual = arrived_at.saturating_sub(previous).as_secs_f64();
				let deviation = (actual - expected).abs();

				// 1/16 is RFC 3550's gain: slow enough not to chase one packet,
				// fast enough to follow a real change within a second.
				self.jitter += (deviation - self.jitter) / 16.0;
			}
		}

		self.last_arrival = Some(arrived_at);
		self.last_sequence = Some(sequence);

		// Two standard deviations of observed spread, which covers the great
		// majority of arrivals without holding for the worst one ever seen.
		let packets = (self.jitter * 2.0 / PACKET.as_secs_f64()).ceil() as usize;
		self.target = packets.clamp(MIN_DEPTH, MAX_DEPTH);
	}
}

/// What became of a pushed packet.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
	Yes,
	/// Its slot had already played.
	TooLate,
	Duplicate,
}

/// What to play next.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum Playback {
	Packet(Vec<u8>),
	/// Nothing arrived for this slot; play silence of one packet's length.
	Concealed,
	/// Not enough held yet to start.
	Filling,
}

/// Whether `a` comes before `b` in RTP's 16-bit sequence space.
///
/// Wrapping matters: at 50 packets a second the counter wraps every 22 minutes,
/// and a comparison that ignored it would drop every packet for a while after
/// each wrap.
#[allow(dead_code)]
fn sequence_before(a: u16, b: u16) -> bool {
	b.wrapping_sub(a) < u16::MAX / 2
}

/// Everything one call holds: the peer connection, and the buffer its audio
/// arrives through.
///
/// Kept together because they have the same lifetime — the buffer is meaningless
/// once the connection is gone, and holding it separately invites the two to
/// drift apart.
pub struct Call {
	pub session: Session,
	/// Audio arriving from the far end, reordered and paced.
	///
	/// **The last unwired step is playback.** RTP reaches this buffer and comes
	/// back out in order — the tests drive exactly that — but turning packets
	/// into sound needs an output device, which is a hardware concern rather
	/// than a protocol one. These two fields are the interface that layer will
	/// use, which is why they are public and why nothing in the client reads
	/// them yet.
	#[allow(dead_code)]
	pub incoming: Arc<Mutex<JitterBuffer>>,
	/// Where outgoing audio is written. A microphone feeds this.
	#[allow(dead_code)]
	pub outgoing:
		Arc<webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample>,
}

impl Call {
	/// Opens a call, ready to send and receive audio.
	pub async fn open(relay: Option<&str>) -> Result<Self> {
		let session = Session::new(relay).await?;
		let outgoing = session.add_audio().await?;

		let incoming = Arc::new(Mutex::new(JitterBuffer::new()));
		session.on_audio(incoming.clone());

		Ok(Self {
			session,
			incoming,
			outgoing,
		})
	}

	/// Opens a call that is answering one, which must also offer to receive.
	pub async fn answering(relay: Option<&str>) -> Result<Self> {
		let call = Self::open(relay).await?;

		// Without a receiving transceiver the answer negotiates nothing for the
		// caller's audio, and the call is silent in one direction.
		call.session
			.connection
			.add_transceiver_from_kind(
				webrtc::rtp_transceiver::rtp_codec::RTPCodecType::Audio,
				None,
			)
			.await?;

		Ok(call)
	}
}

/// A call's media session.
///
/// Deliberately thin: WebRTC does the hard parts, and the value here is that
/// the SDP crosses an authenticated channel rather than anything this adds to
/// the media path.
pub struct Session {
	connection: std::sync::Arc<webrtc::peer_connection::RTCPeerConnection>,
}

impl Session {
	/// Opens a session, relayed or direct.
	///
	/// `relay` is the user's own home server acting as TURN (§9.1), which is the
	/// default because a call should not hand your address to whoever you are
	/// talking to. Passing none is the P2P escalation, and needs both parties'
	/// consent — see `veil_protocol::call`.
	pub async fn new(relay: Option<&str>) -> Result<Self> {
		// DTLS needs the provider installed, and `main` does it for the client's
		// own TLS. A test binary has no `main` of ours, so this makes a session
		// self-sufficient rather than dependent on who set it up first.
		let _ = rustls::crypto::ring::default_provider().install_default();

		use webrtc::{
			api::APIBuilder, ice_transport::ice_server::RTCIceServer,
			peer_connection::configuration::RTCConfiguration,
		};

		let mut media = webrtc::api::media_engine::MediaEngine::default();
		media.register_default_codecs()?;

		let api = APIBuilder::new().with_media_engine(media).build();

		let configuration = RTCConfiguration {
			ice_servers: relay
				.map(|url| {
					vec![RTCIceServer {
						urls: vec![url.to_owned()],
						..Default::default()
					}]
				})
				.unwrap_or_default(),
			..Default::default()
		};

		Ok(Self {
			connection: std::sync::Arc::new(api.new_peer_connection(configuration).await?),
		})
	}

	/// The offer to send to the other device, over the authenticated channel.
	pub async fn offer(&self) -> Result<String> {
		let offer = self.connection.create_offer(None).await?;
		self.connection.set_local_description(offer.clone()).await?;
		Ok(offer.sdp)
	}

	/// Answers an offer that arrived over the authenticated channel.
	pub async fn answer(&self, offer_sdp: &str) -> Result<String> {
		use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

		self.connection
			.set_remote_description(RTCSessionDescription::offer(offer_sdp.to_owned())?)
			.await?;

		let answer = self.connection.create_answer(None).await?;
		self.connection
			.set_local_description(answer.clone())
			.await?;
		Ok(answer.sdp)
	}

	pub async fn accept_answer(&self, answer_sdp: &str) -> Result<()> {
		use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

		self.connection
			.set_remote_description(RTCSessionDescription::answer(answer_sdp.to_owned())?)
			.await?;
		Ok(())
	}

	/// Adds an outgoing audio track.
	///
	/// Opus at 48 kHz, which is what every WebRTC endpoint speaks and what the
	/// 20 ms packet interval is chosen around. Returning the track rather than
	/// keeping it lets the caller push samples from wherever they come from —
	/// a microphone, a file, or a test.
	pub async fn add_audio(
		&self,
	) -> Result<Arc<webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample>>
	{
		use webrtc::{
			rtp_transceiver::rtp_codec::RTCRtpCodecCapability,
			track::track_local::track_local_static_sample::TrackLocalStaticSample,
		};

		let track = Arc::new(TrackLocalStaticSample::new(
			RTCRtpCodecCapability {
				mime_type: "audio/opus".to_owned(),
				clock_rate: 48_000,
				channels: 2,
				..Default::default()
			},
			"audio".to_owned(),
			"veil".to_owned(),
		));

		self.connection.add_track(track.clone()).await?;
		Ok(track)
	}

	/// Feeds incoming audio into a jitter buffer.
	///
	/// **This is where the buffer earns its place.** RTP arrives reordered, in
	/// bursts and with gaps; the buffer absorbs that and hands back a steady
	/// stream. Reading happens on its own task because a receive loop that
	/// shared a thread with playback would make every hiccup in one audible in
	/// the other.
	pub fn on_audio(&self, buffer: Arc<Mutex<JitterBuffer>>) {
		use std::time::Instant;

		let started = Instant::now();

		self.connection.on_track(Box::new(move |track, _, _| {
			let buffer = buffer.clone();

			Box::pin(async move {
				tokio::spawn(async move {
					while let Ok((packet, _)) = track.read_rtp().await {
						let arrived = started.elapsed();
						buffer.lock().await.push(
							packet.header.sequence_number,
							&packet.payload,
							arrived,
						);
					}
				});
			})
		}));
	}

	/// The DTLS fingerprint this session will present.
	///
	/// Not called by the client: the fingerprint is checked by DTLS itself
	/// against what the SDP declared, and the SDP arrived authenticated. This is
	/// here so a caller that wants to *show* somebody the fingerprint can,
	/// which a call UI reasonably would.
	#[allow(dead_code)]
	///
	/// **This is the value the whole design rests on.** It travels inside the
	/// SDP over an Olm session to a cross-signed device, which is what
	/// authenticates the media keys. A caller that compares it against a
	/// fingerprint learned any other way is checking the wrong thing — the
	/// point is that it arrived authenticated.
	pub fn fingerprint(sdp: &str) -> Option<String> {
		sdp.lines()
			.find_map(|line| line.trim().strip_prefix("a=fingerprint:"))
			.map(|f| f.trim().to_owned())
	}

	/// Resolves once the peers are connected, or gives up.
	///
	/// Exposed because a caller has to know when media may start, and polling a
	/// state enum from the outside is worse than being told.
	#[allow(dead_code)]
	pub async fn connected(&self, within: Duration) -> bool {
		use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;

		let deadline = tokio::time::Instant::now() + within;
		loop {
			match self.connection.connection_state() {
				RTCPeerConnectionState::Connected => return true,
				RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => return false,
				_ if tokio::time::Instant::now() >= deadline => return false,
				_ => tokio::time::sleep(Duration::from_millis(50)).await,
			}
		}
	}

	/// Adds this side's ICE candidates to the offer or answer already made.
	///
	/// Waits for gathering to finish rather than trickling them separately.
	/// Trickle ICE connects sooner and is what a finished client should do;
	/// gathering first keeps setup to one signalling round trip, which is the
	/// simpler thing to get right and to test.
	pub async fn local_description_when_gathered(&self) -> Result<String> {
		let mut gathered = self.connection.gathering_complete_promise().await;
		let _ = gathered.recv().await;

		self.connection
			.local_description()
			.await
			.map(|description| description.sdp)
			.ok_or_else(|| anyhow::anyhow!("no local description after gathering"))
	}

	#[allow(dead_code)]
	pub async fn close(&self) -> Result<()> {
		self.connection.close().await?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn at(ms: u64) -> Duration {
		Duration::from_millis(ms)
	}

	#[test]
	fn packets_play_in_order_however_they_arrive() {
		let mut buffer = JitterBuffer::new();

		// Out of order, as RTP routinely is.
		buffer.push(2, b"second", at(40));
		buffer.push(0, b"first", at(0));
		buffer.push(1, b"middle", at(20));

		assert_eq!(buffer.pop(), Playback::Packet(b"first".to_vec()));
		assert_eq!(buffer.pop(), Playback::Packet(b"middle".to_vec()));
		assert_eq!(buffer.pop(), Playback::Packet(b"second".to_vec()));
	}

	/// A gap must produce silence of the right length, not a skipped instant —
	/// otherwise speech runs fast and the pitch wanders.
	#[test]
	fn a_lost_packet_is_concealed_rather_than_skipped() {
		let mut buffer = JitterBuffer::new();

		buffer.push(0, b"first", at(0));
		buffer.push(2, b"third", at(40));

		assert_eq!(buffer.pop(), Playback::Packet(b"first".to_vec()));
		assert_eq!(
			buffer.pop(),
			Playback::Concealed,
			"the missing slot must still take one packet's time"
		);
		assert_eq!(buffer.pop(), Playback::Packet(b"third".to_vec()));
	}

	/// Playing a late packet would put audio out of order, which sounds worse
	/// than the gap it would fill.
	#[test]
	fn a_packet_that_missed_its_slot_is_dropped() {
		let mut buffer = JitterBuffer::new();

		buffer.push(0, b"first", at(0));
		buffer.push(1, b"second", at(20));
		buffer.pop();
		buffer.pop();

		assert_eq!(buffer.push(0, b"far too late", at(200)), Accepted::TooLate);
		assert_eq!(buffer.late(), 1);
	}

	#[test]
	fn a_duplicate_is_ignored() {
		let mut buffer = JitterBuffer::new();

		assert_eq!(buffer.push(5, b"once", at(0)), Accepted::Yes);
		assert_eq!(buffer.push(5, b"again", at(1)), Accepted::Duplicate);
		assert_eq!(buffer.held(), 1);
	}

	/// The counter wraps every 22 minutes at 50 packets a second. A comparison
	/// that ignored that would drop everything for a while after each wrap.
	#[test]
	fn the_sequence_space_wraps() {
		let mut buffer = JitterBuffer::new();

		buffer.push(u16::MAX - 1, b"before", at(0));
		buffer.push(u16::MAX, b"edge", at(20));
		buffer.push(0, b"after", at(40));

		assert_eq!(buffer.pop(), Playback::Packet(b"before".to_vec()));
		assert_eq!(buffer.pop(), Playback::Packet(b"edge".to_vec()));
		assert_eq!(
			buffer.pop(),
			Playback::Packet(b"after".to_vec()),
			"a wrap must not be read as a packet from the distant past"
		);
	}

	/// A steady connection should not be made to feel like a bad one.
	#[test]
	fn a_clean_connection_keeps_the_buffer_shallow() {
		let mut buffer = JitterBuffer::new();

		for n in 0..50u16 {
			buffer.push(n, b"tick", at(u64::from(n) * 20));
		}

		assert_eq!(
			buffer.target_depth(),
			MIN_DEPTH,
			"perfectly paced arrivals need the shallowest buffer, and so the least delay"
		);
	}

	/// And a bad one should be absorbed rather than heard.
	#[test]
	fn a_jittery_connection_deepens_the_buffer() {
		let mut buffer = JitterBuffer::new();

		// Arrivals scattered well either side of where they should be. Mild
		// jitter is deliberately *not* used here: two packets already absorbs
		// about 20 ms of spread, so a test built on that would be asserting the
		// floor rather than the adaptation.
		let mut when = 0u64;
		for n in 0..80u16 {
			when += if n % 2 == 0 { 4 } else { 120 };
			buffer.push(n, b"tick", at(when));
		}

		assert!(
			buffer.target_depth() > MIN_DEPTH,
			"observed spread should have deepened the buffer, got {}",
			buffer.target_depth()
		);
	}

	/// Past about half a second people talk over each other, so dropping audio
	/// becomes the better failure.
	#[test]
	fn the_buffer_refuses_to_grow_past_conversation_latency() {
		let mut buffer = JitterBuffer::new();

		let mut when = 0u64;
		for n in 0..200u16 {
			when += if n % 2 == 0 { 1 } else { 3_000 };
			buffer.push(n, b"tick", at(when));
		}

		assert!(
			buffer.target_depth() <= MAX_DEPTH,
			"a terrible connection must not turn the call into a monologue"
		);
	}

	/// At 50 packets a second, per-packet allocation is 50 pointless trips to
	/// the allocator every second.
	#[test]
	fn steady_state_reuses_its_storage() {
		let mut buffer = JitterBuffer::new();

		for n in 0..10u16 {
			buffer.push(n, b"tick", at(u64::from(n) * 20));
		}
		for _ in 0..10 {
			if let Playback::Packet(payload) = buffer.pop() {
				buffer.recycle(payload);
			}
		}

		let spare_before = buffer.spare.len();
		assert!(spare_before > 0, "recycled storage should have been kept");

		for n in 10..20u16 {
			buffer.push(n, b"tick", at(u64::from(n) * 20));
		}
		assert!(
			buffer.spare.len() < spare_before,
			"the next packets should have taken storage from the pool rather than allocating"
		);
	}

	/// The buffer waits before playing. Starting immediately is what makes a
	/// call stutter for its first few seconds.
	#[test]
	fn playback_waits_for_the_target_depth() {
		let mut buffer = JitterBuffer::new();
		buffer.target = 3;

		buffer.push(0, b"a", at(0));
		assert_eq!(buffer.pop(), Playback::Filling);

		buffer.push(1, b"b", at(20));
		buffer.push(2, b"c", at(40));
		assert_eq!(buffer.pop(), Playback::Packet(b"a".to_vec()));
	}
}

#[cfg(test)]
mod session_tests {
	use super::*;

	/// Audio actually flows, and arrives through the jitter buffer.
	///
	/// This is what turns the buffer from a tested algorithm into part of the
	/// media path: real RTP, produced by one peer's Opus track and read off the
	/// other's, encrypted by SRTP in between.
	#[tokio::test]
	async fn audio_flows_through_the_jitter_buffer() {
		use std::time::Instant;
		use webrtc::media::Sample;

		// The real types, assembled the way a call assembles them — so this
		// exercises what the client actually builds rather than a arrangement
		// that only exists in a test.
		let caller = Call::open(None).await.unwrap();
		let callee = Call::answering(None).await.unwrap();

		caller.session.offer().await.unwrap();
		let offer = caller
			.session
			.local_description_when_gathered()
			.await
			.unwrap();
		callee.session.answer(&offer).await.unwrap();
		let answer = callee
			.session
			.local_description_when_gathered()
			.await
			.unwrap();
		caller.session.accept_answer(&answer).await.unwrap();

		assert!(
			caller.session.connected(Duration::from_secs(20)).await,
			"the peers should connect before any audio is sent"
		);

		// Synthetic samples rather than a microphone: this container has no
		// audio devices, and the path being tested is the network one.
		let deadline = Instant::now() + Duration::from_secs(20);
		let mut sent = 0;
		while sent < 50 && Instant::now() < deadline {
			caller
				.outgoing
				.write_sample(&Sample {
					data: vec![0xAA; 160].into(),
					duration: PACKET,
					..Default::default()
				})
				.await
				.unwrap();
			sent += 1;
			tokio::time::sleep(PACKET).await;
		}

		// Give the last packets time to land.
		let mut held = 0;
		let deadline = Instant::now() + Duration::from_secs(10);
		while Instant::now() < deadline {
			held = callee.incoming.lock().await.held();
			if held >= 10 {
				break;
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}

		assert!(
			held >= 10,
			"audio should have arrived and been buffered, got {held} packets"
		);

		// And it comes back out in order, which is the buffer's whole job.
		let mut buffer = callee.incoming.lock().await;
		let first = buffer.pop();
		assert!(
			matches!(first, Playback::Packet(_)),
			"the buffer should yield a packet once filled, got {first:?}"
		);

		drop(buffer);
		caller.session.close().await.unwrap();
		callee.session.close().await.unwrap();
	}

	/// Two peers negotiate a real connection, using only what would have crossed
	/// the authenticated signalling channel.
	///
	/// This is the claim in §9 made concrete: no key exchange of Veil's own
	/// happens here. DTLS-SRTP does it, and Veil's contribution is that the SDP
	/// carrying the fingerprint arrived over a session with a cross-signed
	/// device.
	#[tokio::test]
	async fn two_peers_establish_an_encrypted_session() {
		let caller = Session::new(None).await.unwrap();
		let callee = Session::new(None).await.unwrap();

		// A data channel gives the connection something to negotiate; the media
		// path is identical, and this needs no audio hardware to exercise.
		caller.add_audio().await.unwrap();

		caller.offer().await.unwrap();
		let offer = caller.local_description_when_gathered().await.unwrap();

		callee.answer(&offer).await.unwrap();
		let answer = callee.local_description_when_gathered().await.unwrap();
		caller.accept_answer(&answer).await.unwrap();

		assert!(
			caller.connected(Duration::from_secs(20)).await,
			"the caller should reach a connected state"
		);
		assert!(
			callee.connected(Duration::from_secs(20)).await,
			"and so should the callee"
		);

		caller.close().await.unwrap();
		callee.close().await.unwrap();
	}

	/// The SDP carries a DTLS fingerprint, which is the value the design rests
	/// on: it travels authenticated, so the media keys are authenticated.
	#[tokio::test]
	async fn an_offer_carries_a_fingerprint_to_authenticate() {
		let caller = Session::new(None).await.unwrap();
		caller.add_audio().await.unwrap();
		let offer = caller.offer().await.unwrap();

		let fingerprint = Session::fingerprint(&offer)
			.expect("an offer must carry a fingerprint, or there is nothing to authenticate");
		assert!(
			fingerprint.starts_with("sha-256"),
			"got {fingerprint}, which is not a fingerprint we would recognise"
		);

		// Two sessions are two keys, so a fingerprint identifies one of them.
		let other = Session::new(None).await.unwrap();
		other.add_audio().await.unwrap();
		let theirs = Session::fingerprint(&other.offer().await.unwrap()).unwrap();
		assert_ne!(
			fingerprint, theirs,
			"distinct sessions must present distinct fingerprints"
		);

		caller.close().await.unwrap();
		other.close().await.unwrap();
	}
}

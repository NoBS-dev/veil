//! Nested TLS through a blind relay — `DESIGN.md` §3.2.
//!
//! ```text
//! client ──TLS──► home server ──TCP──► community host
//!        └──────────── TLS ─────────────────┘
//!                 (nested, end-to-end)
//! ```
//!
//! The relay forwards bytes it cannot read. Before this it forwarded *Veil
//! frames*, which meant a home server could read everything its users sent to a
//! community — putting two operators in the trust set and undoing the point of
//! relaying at all. It matters most for **Open** communities, whose content is
//! not end-to-end encrypted and so is protected by nothing else.
//!
//! Two pieces here. [`TunnelStream`] turns the relay's WebSocket into the plain
//! byte stream TLS needs, and [`BindingVerifier`] decides which certificate to
//! accept.
//!
//! **Why not just validate the certificate normally.** §1.3 requires that one
//! person on a domestic connection can host a community, and self-signed
//! certificates are the norm for that; demanding a CA-issued certificate would
//! quietly make self-hosting impossible. But accepting any certificate lets the
//! relay terminate the session with its own and read everything, which is the
//! attack this file exists to stop. So the certificate is checked against the
//! Veil identity instead: the server signs a hash of its own certificate into
//! the challenge, and a relay cannot produce that signature for a certificate it
//! generated. Trust-on-first-use in the identity key (invariant 6), and nothing
//! further is assumed.

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use std::{
	pin::Pin,
	sync::{Arc, Mutex},
	task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::protocol::Message;

/// A byte stream carried inside a relay's WebSocket.
///
/// The relay speaks WebSocket to us because that is what it accepts
/// connections as; TLS needs a stream. This adapts one to the other by putting
/// each write in a binary frame and reassembling reads. The relay never
/// interprets the payload — it checks only that it is TLS record framing
/// (§3.2), which is what stops the tunnel being pointed at a plaintext service.
pub struct TunnelStream {
	socket: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
	/// Bytes received but not yet read by TLS. A record does not arrive in one
	/// frame, and TLS reads in its own sizes.
	pending: Vec<u8>,
	read_from: usize,
}

impl TunnelStream {
	pub fn new(socket: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>) -> Self {
		Self {
			socket,
			pending: Vec::new(),
			read_from: 0,
		}
	}

	fn buffered(&self) -> usize {
		self.pending.len() - self.read_from
	}
}

impl AsyncRead for TunnelStream {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		loop {
			if self.buffered() > 0 {
				let take = self.buffered().min(buf.remaining());
				let from = self.read_from;
				let slice = self.pending[from..from + take].to_vec();
				buf.put_slice(&slice);
				self.read_from += take;

				if self.read_from == self.pending.len() {
					self.pending.clear();
					self.read_from = 0;
				}
				return Poll::Ready(Ok(()));
			}

			match self.socket.poll_next_unpin(cx) {
				Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
					self.pending = bytes.to_vec();
					self.read_from = 0;
				}
				// Anything else on a tunnel is noise; keep waiting for bytes.
				Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
					return Poll::Ready(Ok(())); // clean end of stream
				}
				Poll::Ready(Some(Ok(_))) => continue,
				Poll::Ready(Some(Err(e))) => {
					return Poll::Ready(Err(std::io::Error::other(e)));
				}
				Poll::Pending => return Poll::Pending,
			}
		}
	}
}

impl AsyncWrite for TunnelStream {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		match self.socket.poll_ready_unpin(cx) {
			Poll::Ready(Ok(())) => {
				let framed = Message::Binary(buf.to_vec().into());
				match self.socket.start_send_unpin(framed) {
					Ok(()) => Poll::Ready(Ok(buf.len())),
					Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
				}
			}
			Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
			Poll::Pending => Poll::Pending,
		}
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.socket
			.poll_flush_unpin(cx)
			.map_err(std::io::Error::other)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		self.socket
			.poll_close_unpin(cx)
			.map_err(std::io::Error::other)
	}
}

/// Records the certificate the peer presented, and accepts it provisionally.
///
/// **The acceptance is not the security decision.** Nothing has been proved when
/// this returns — the check that matters happens after the Veil challenge
/// arrives, when [`hash`] is compared against the `tls_binding` the server
/// signed. Splitting it this way is what allows self-signed certificates
/// without allowing a relay to substitute one: rustls has no way to know about
/// Veil identities, and the identity key has not been seen yet at this point in
/// the handshake.
///
/// The connection is useless until that comparison runs, so every caller must
/// run it. There is exactly one caller, immediately below.
#[derive(Debug)]
pub struct BindingVerifier {
	seen: Arc<Mutex<Option<[u8; 32]>>>,
}

impl BindingVerifier {
	pub fn new() -> (Arc<Self>, Arc<Mutex<Option<[u8; 32]>>>) {
		let seen = Arc::new(Mutex::new(None));
		(
			Arc::new(Self {
				seen: Arc::clone(&seen),
			}),
			seen,
		)
	}
}

impl rustls::client::danger::ServerCertVerifier for BindingVerifier {
	fn verify_server_cert(
		&self,
		end_entity: &rustls::pki_types::CertificateDer<'_>,
		_intermediates: &[rustls::pki_types::CertificateDer<'_>],
		_server_name: &rustls::pki_types::ServerName<'_>,
		_ocsp: &[u8],
		_now: rustls::pki_types::UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		use sha2::{Digest, Sha256};

		let hash: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
		*self.seen.lock().unwrap() = Some(hash);

		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &rustls::pki_types::CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(
			message,
			cert,
			dss,
			&rustls::crypto::ring::default_provider().signature_verification_algorithms,
		)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &rustls::pki_types::CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(
			message,
			cert,
			dss,
			&rustls::crypto::ring::default_provider().signature_verification_algorithms,
		)
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		rustls::crypto::ring::default_provider()
			.signature_verification_algorithms
			.supported_schemes()
	}
}

/// Opens a direct TLS session to a host.
///
/// Uses the same certificate binding as the relayed path, and for the same
/// reason: a self-hoster's certificate is self-signed (§1.3), so requiring a
/// certificate authority here would mean a home server could only be reached if
/// its operator could obtain one. Veil authenticates servers by identity key
/// and binds the certificate to it, which needs no authority at all.
pub async fn tls_direct(
	stream: tokio::net::TcpStream,
	destination: &str,
) -> Result<(
	tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
	Arc<Mutex<Option<[u8; 32]>>>,
)> {
	let (verifier, seen) = BindingVerifier::new();
	let config = rustls::ClientConfig::builder()
		.dangerous()
		.with_custom_certificate_verifier(verifier)
		.with_no_client_auth();

	let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
		.connect(server_name(destination), stream)
		.await?;

	Ok((stream, seen))
}

/// Only what goes in SNI. It is not what authenticates the peer — the
/// certificate hash and the identity key that signed it are.
fn server_name(destination: &str) -> rustls::pki_types::ServerName<'static> {
	let host = destination
		.trim_start_matches("wss://")
		.trim_start_matches("ws://")
		.split(':')
		.next()
		.unwrap_or("localhost")
		.to_owned();

	rustls::pki_types::ServerName::try_from(host)
		.unwrap_or(rustls::pki_types::ServerName::try_from("localhost").unwrap())
}

/// Runs a TLS session to `destination` over an established relay tunnel.
///
/// Returns the stream and a handle to the certificate hash that was negotiated,
/// which the caller must check against the server's signed `tls_binding` before
/// treating the session as private.
pub async fn tls_over_tunnel(
	tunnel: TunnelStream,
	destination: &str,
) -> Result<(
	tokio_rustls::client::TlsStream<TunnelStream>,
	Arc<Mutex<Option<[u8; 32]>>>,
)> {
	let (verifier, seen) = BindingVerifier::new();

	let config = rustls::ClientConfig::builder()
		.dangerous()
		.with_custom_certificate_verifier(verifier)
		.with_no_client_auth();

	let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
		.connect(server_name(destination), tunnel)
		.await?;

	Ok((stream, seen))
}

/// Refuses a session whose certificate the server never vouched for.
///
/// This is the check the whole file exists for. A relay that terminated the
/// inner TLS session would have to present a certificate of its own, and it
/// cannot make the destination's identity key sign a hash of it.
pub fn check_binding(negotiated: Option<[u8; 32]>, signed: &[u8; 32]) -> Result<()> {
	if signed == &[0u8; 32] {
		anyhow::bail!(
			"the destination serves plaintext, so a relayed connection to it cannot be \
			 private — the relay would see everything. Ask its operator for TLS, or \
			 connect directly and accept that it learns your IP (§3.5)."
		);
	}

	let Some(negotiated) = negotiated else {
		anyhow::bail!("no certificate was negotiated; refusing to continue");
	};

	if &negotiated != signed {
		anyhow::bail!(
			"the destination's signed certificate does not match the one this \
			 connection negotiated — something is terminating TLS in the middle, \
			 which is what tunnelling exists to prevent"
		);
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_matching_certificate_is_accepted() {
		let hash = [7u8; 32];
		assert!(check_binding(Some(hash), &hash).is_ok());
	}

	/// The attack: a relay terminates the inner session with its own
	/// certificate. It cannot forge the signature over the real one, so the
	/// hashes disagree.
	#[test]
	fn a_substituted_certificate_is_refused() {
		let error = check_binding(Some([1u8; 32]), &[2u8; 32]).unwrap_err();
		assert!(format!("{error}").contains("terminating TLS in the middle"));
	}

	/// A plaintext destination cannot be reached privately through a relay, and
	/// saying so is better than tunnelling to it and implying otherwise.
	#[test]
	fn a_plaintext_destination_is_refused() {
		assert!(check_binding(Some([1u8; 32]), &[0u8; 32]).is_err());
	}

	/// Failing open here would defeat the entire mechanism.
	#[test]
	fn a_missing_certificate_is_refused() {
		assert!(check_binding(None, &[3u8; 32]).is_err());
	}
}

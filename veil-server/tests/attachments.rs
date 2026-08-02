//! Attachments over the wire — `DESIGN.md` §10.2.
//!
//! The unit tests in `veil-protocol` cover the encryption. These cover what the
//! host does with what it is handed: that a blob's id is the hash of the bytes
//! *it* received rather than whatever the uploader claimed, that a Sealed
//! attachment leaves nothing readable, and that a client can tell when the
//! bytes it gets back are not the ones it asked for.

mod harness;

use harness::{Server, TestClient};
use std::time::Duration;
use veil_protocol::{
	ProtocolMessage,
	attachment::{self, Attachment},
};

const BEAT: Duration = Duration::from_millis(1500);

async fn upload(client: &mut TestClient, bytes: Vec<u8>) -> ([u8; 32], u64) {
	client
		.send(&ProtocolMessage::UploadBlob(bytes))
		.await
		.unwrap();

	loop {
		match client.recv(BEAT).await {
			Some(ProtocolMessage::BlobStored { id, size }) => return (id, size),
			Some(_) => continue,
			None => panic!("the host said nothing about the upload"),
		}
	}
}

async fn fetch(client: &mut TestClient, id: [u8; 32]) -> Vec<u8> {
	client.send(&ProtocolMessage::FetchBlob(id)).await.unwrap();

	loop {
		match client.recv(BEAT).await {
			Some(ProtocolMessage::BlobContent { bytes, .. }) => return bytes,
			Some(_) => continue,
			None => panic!("the host returned nothing for the blob"),
		}
	}
}

#[tokio::test]
async fn a_sealed_attachment_survives_the_round_trip_and_the_host_cannot_read_it() {
	let server = Server::start().await;
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let secret = b"the contents of a private photograph";
	let (attachment, ciphertext) = attachment::seal("photo.png", secret).unwrap();

	let (id, size) = upload(&mut alice, ciphertext.clone()).await;
	assert_eq!(id, attachment.blob, "the host's id must match the sender's");
	assert_eq!(size, ciphertext.len() as u64);
	tokio::time::sleep(BEAT).await;

	// What the host holds is not the file.
	let mut raw = std::fs::read(&server.db).unwrap();
	if let Ok(wal) = std::fs::read(format!("{}-wal", server.db)) {
		raw.extend_from_slice(&wal);
	}
	assert!(
		!raw.windows(secret.len()).any(|w| w == secret),
		"a Sealed attachment must not be readable in the host's store"
	);
	assert!(
		raw.windows(ciphertext.len()).any(|w| w == ciphertext),
		"but the ciphertext should be there, or the check above proves nothing"
	);

	// And the recipient gets the file back.
	let served = fetch(&mut alice, attachment.blob).await;
	assert_eq!(attachment::open(&attachment, &served).unwrap(), secret);

	server.stop().await;
}

/// The id is computed from the bytes that arrived, not taken from the uploader.
///
/// Otherwise a client could claim somebody else's id and overwrite their file —
/// or, worse, have a recipient fetch what it believed was a verified blob.
#[tokio::test]
async fn a_blob_id_is_the_hash_of_what_the_host_received() {
	let server = Server::start().await;
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let (first, _) = upload(&mut alice, b"the original file".to_vec()).await;
	let (second, _) = upload(&mut alice, b"a different file".to_vec()).await;

	assert_eq!(first, attachment::blob_id(b"the original file"));
	assert_ne!(first, second, "different bytes must not share an id");

	// Fetching the first id returns the first file, whatever was uploaded after.
	assert_eq!(fetch(&mut alice, first).await, b"the original file");

	server.stop().await;
}

/// A host that serves the wrong bytes is caught by the recipient, which is what
/// makes it safe to fetch a file from a host nobody trusts.
#[tokio::test]
async fn a_recipient_refuses_bytes_that_do_not_match_the_reference() {
	let server = Server::start().await;
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let (attachment, ciphertext) = attachment::seal("photo.png", b"the real file").unwrap();
	upload(&mut alice, ciphertext).await;

	// The host answers with something else entirely.
	let substituted = attachment::seal("photo.png", b"not the real file")
		.unwrap()
		.1;
	assert!(
		attachment::open(&attachment, &substituted).is_err(),
		"a recipient must refuse bytes that do not hash to the reference"
	);

	// The control: the genuine bytes are accepted.
	let served = fetch(&mut alice, attachment.blob).await;
	assert!(attachment::open(&attachment, &served).is_ok());

	server.stop().await;
}

/// An Open community's host holds the file itself — that is what lets it
/// thumbnail and transcode, and it is the trade §7.2 makes deliberately.
#[tokio::test]
async fn an_open_attachment_is_stored_as_the_file() {
	let server = Server::start().await;
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	let contents = b"a public announcement image".to_vec();
	let attachment: Attachment = attachment::open_tier("banner.png", &contents);
	let (id, _) = upload(&mut alice, contents.clone()).await;

	assert_eq!(id, attachment.blob);
	assert_eq!(fetch(&mut alice, id).await, contents);
	assert_eq!(
		attachment::open(&attachment, &contents).unwrap(),
		contents,
		"an Open attachment needs no key"
	);

	server.stop().await;
}

/// A blob that was never uploaded returns nothing rather than inventing one.
#[tokio::test]
async fn an_unknown_blob_returns_nothing() {
	let server = Server::start().await;
	let mut alice = TestClient::new().connect(&server.ws_url()).await.unwrap();
	alice.upload_keys(5).await.unwrap();
	tokio::time::sleep(BEAT).await;

	assert!(fetch(&mut alice, [9u8; 32]).await.is_empty());

	server.stop().await;
}

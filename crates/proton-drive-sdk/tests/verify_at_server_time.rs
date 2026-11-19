//! Signatures are verified at server time, the time they are made at.
//!
//! These tests move the process-wide server time offset, so they live in their
//! own test binary (process) and all set the same offset: server time an hour
//! ahead of the device clock, as on a device whose clock is slow.

use std::time::{SystemTime, UNIX_EPOCH};

use proton_drive_sdk::author::Author;
use proton_drive_sdk::crypto::CryptoGenerator;
use proton_drive_sdk::node::authorship::AuthorshipClaim;
use proton_drive_sdk::node::crypto::NodeCrypto;
use proton_drive_sdk::node::download::verify_manifest_signature;
use proton_drive_sdk::pgp::{PgpArmoredMessage, PgpArmoredSignature, PgpPrivateKey};
use proton_drive_sdk::server_time;
use proton_rpgp::{AsPublicKeyRef, CheckUnixTime, DataEncoding};

/// How far server time is ahead of the device clock in these tests.
const SERVER_AHEAD_SECONDS: i64 = 3_600;

fn device_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Sets server time an hour ahead of the device clock.
fn server_ahead() {
    server_time::update(device_now() + SERVER_AHEAD_SECONDS);
    let ahead = server_time::now_unix_seconds() - device_now();
    assert!(
        (SERVER_AHEAD_SECONDS - 2..=SERVER_AHEAD_SECONDS + 2).contains(&ahead),
        "server time is {ahead} s ahead"
    );
}

fn claim(keys: &[&PgpPrivateKey]) -> AuthorshipClaim {
    AuthorshipClaim {
        keys: keys
            .iter()
            .map(|key| key.0.as_public_key().clone())
            .collect(),
        author: Author::ANONYMOUS,
        key_retrieval_error_message: None,
    }
}

/// A detached signature by `key` dated `seconds` after server time.
fn signed_after_server_time(key: &PgpPrivateKey, data: &[u8], seconds: i64) -> PgpArmoredSignature {
    let date = CheckUnixTime::new((server_time::now_unix_seconds() + seconds) as u64);
    let bytes = proton_rpgp::Signer::default()
        .at_date(date)
        .with_signing_key(&key.0)
        .sign_detached(data, DataEncoding::Armored)
        .unwrap();
    PgpArmoredSignature(String::from_utf8(bytes).unwrap())
}

/// A message encrypted to `recipient` and signed by `signer` at server time plus `seconds`.
fn encrypted_after_server_time(
    recipient: &PgpPrivateKey,
    signer: &PgpPrivateKey,
    data: &[u8],
    seconds: i64,
) -> PgpArmoredMessage {
    let date = CheckUnixTime::new((server_time::now_unix_seconds() + seconds) as u64);
    let message = proton_rpgp::Encryptor::default()
        .at_date(date)
        .with_encryption_key(recipient.0.as_public_key())
        .with_signing_key(&signer.0)
        .encrypt(data)
        .unwrap();
    PgpArmoredMessage(String::from_utf8(message.armor().unwrap()).unwrap())
}

#[test]
fn a_manifest_signed_at_server_time_verifies() {
    server_ahead();
    let node_key = CryptoGenerator::generate_private_key().unwrap();
    let manifest = [7u8; 64];
    let signature = node_key.sign_detached_armored(&manifest).unwrap();

    verify_manifest_signature(
        &manifest,
        Some(&signature),
        &[node_key.0.as_public_key().clone()],
    )
    .expect("a block manifest signed at server time verifies");
}

#[test]
fn a_content_key_signed_at_server_time_verifies() {
    server_ahead();
    let node_key = CryptoGenerator::generate_private_key().unwrap();
    let content_key = CryptoGenerator::generate_session_key();
    let packet = node_key.encrypt_session_key(&content_key).unwrap();
    let signature = node_key.sign_detached_armored(&content_key.key).unwrap();

    let output =
        NodeCrypto::decrypt_content_key(Some(&node_key), &packet, Some(&signature), &claim(&[]))
            .expect("the content key decrypts");
    assert_eq!(output.data.key, content_key.key);
    assert!(
        output.authorship_verification_failure.is_none(),
        "a content key signed at server time verifies"
    );
}

#[test]
fn a_name_signed_at_server_time_verifies() {
    server_ahead();
    let parent_key = CryptoGenerator::generate_private_key().unwrap();
    let author_key = CryptoGenerator::generate_private_key().unwrap();
    let hash_key = CryptoGenerator::generate_folder_hash_key();
    let (name, _, _) =
        NodeCrypto::encrypt_and_sign_name("report.txt", &hash_key, &parent_key, &author_key)
            .unwrap();

    let (data, _, failure) =
        NodeCrypto::decrypt_message(&name, None, [&parent_key], &claim(&[&author_key]))
            .expect("the name decrypts");
    assert_eq!(data, b"report.txt");
    assert!(failure.is_none(), "a name signed at server time verifies");
}

#[test]
fn a_signature_dated_after_server_time_fails() {
    server_ahead();
    let node_key = CryptoGenerator::generate_private_key().unwrap();
    let manifest = [7u8; 64];
    let late = signed_after_server_time(&node_key, &manifest, 600);
    assert!(
        verify_manifest_signature(
            &manifest,
            Some(&late),
            &[node_key.0.as_public_key().clone()]
        )
        .is_err(),
        "a manifest signature dated after server time fails"
    );

    let content_key = CryptoGenerator::generate_session_key();
    let packet = node_key.encrypt_session_key(&content_key).unwrap();
    let late = signed_after_server_time(&node_key, &content_key.key, 600);
    let output =
        NodeCrypto::decrypt_content_key(Some(&node_key), &packet, Some(&late), &claim(&[]))
            .expect("the content key decrypts");
    assert!(output.authorship_verification_failure.is_some());

    let parent_key = CryptoGenerator::generate_private_key().unwrap();
    let name = encrypted_after_server_time(&parent_key, &node_key, b"report.txt", 600);
    let (data, _, failure) =
        NodeCrypto::decrypt_message(&name, None, [&parent_key], &claim(&[&node_key]))
            .expect("the name decrypts");
    assert_eq!(data, b"report.txt");
    assert!(failure.is_some(), "a name signed after server time fails");
}

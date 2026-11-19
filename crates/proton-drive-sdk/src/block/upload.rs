use crate::block::verify::BlockVerifier;
use crate::client::ProtonDriveClient;
use crate::node::draft::RevisionDraft;
use crate::pgp::PgpArmoredMessage;
use proton_rpgp::{AsPublicKeyRef, pgp::ser::Serialize};
use sha2::Digest;

/// How often a block that fails verification is encrypted again before the upload
/// fails, as in both official SDKs (C# `maxRetries`, JS `MAX_BLOCK_ENCRYPTION_RETRIES`).
pub const MAX_BLOCK_ENCRYPTION_RETRIES: u32 = 1;

pub struct BlockUploadResult {
    pub size: usize,
    pub sha256_digest: Vec<u8>,
}

/// Holds pre-encrypted block data ready for upload.
/// This allows separating encryption (CPU-bound) from upload (I/O-bound).
pub struct EncryptedBlock {
    pub block_number: i32,
    pub plain_size: usize,
    pub encrypted_data: Vec<u8>,
    pub sha256_digest: Vec<u8>,
    pub encrypted_signature: PgpArmoredMessage,
    pub verification_token: Vec<u8>,
}

/// A block's encrypted content and its encrypted signature, before verification.
struct BlockCiphertext {
    encrypted_data: Vec<u8>,
    encrypted_signature: PgpArmoredMessage,
}

/// Signs `plain_data` with the draft's signing key, encrypts the signature to the
/// file key and the data with the content key.
fn encrypt_content(draft: &RevisionDraft, plain_data: &[u8]) -> anyhow::Result<BlockCiphertext> {
    // 1. Sign the plain data
    let signer = proton_rpgp::Signer::default()
        .at_date(crate::server_time::check_now())
        .with_signing_key(&draft.signing_key.0);
    let signature = signer.sign_detached(plain_data, proton_rpgp::DataEncoding::Auto)?;

    // 2. Encrypt the signature using the file key (unsigned, matching official SDK)
    let signature_encryptor = proton_rpgp::Encryptor::default()
        .at_date(crate::server_time::check_now())
        .with_encryption_key(draft.file_key.0.as_public_key());
    let signature_result = signature_encryptor.encrypt(&signature)?;
    let encrypted_signature = PgpArmoredMessage(String::from_utf8(signature_result.armor()?)?);

    // 3. Encrypt the content using the session key
    let sk = draft.content_key.to_rpgp_sk()?;
    let content_encryptor = proton_rpgp::Encryptor::default()
        .at_date(crate::server_time::check_now())
        .with_session_key(sk);
    let encrypted_data = content_encryptor.encrypt(plain_data)?.to_bytes()?;

    Ok(BlockCiphertext {
        encrypted_data,
        encrypted_signature,
    })
}

/// Encrypts a block with `encrypt` and verifies it ([`BlockVerifier::verify_block`]).
/// A block that fails verification is encrypted again, up to
/// [`MAX_BLOCK_ENCRYPTION_RETRIES`] times; then its error, an
/// [`IntegrityException`](crate::error::IntegrityException), is returned. Other
/// errors are returned at once.
fn encrypt_and_verify(
    block_number: i32,
    plain_data: &[u8],
    verifier: &BlockVerifier,
    mut encrypt: impl FnMut() -> anyhow::Result<BlockCiphertext>,
) -> anyhow::Result<EncryptedBlock> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let ciphertext = encrypt()?;
        match verifier.verify_block(&ciphertext.encrypted_data, plain_data) {
            Ok(verification_token) => {
                if attempt > 1 {
                    tracing::warn!(
                        block_number,
                        attempt,
                        "Block verified after encrypting it again"
                    );
                }
                // SHA256 of the ENCRYPTED data
                let sha256_digest = sha2::Sha256::digest(&ciphertext.encrypted_data).to_vec();
                return Ok(EncryptedBlock {
                    block_number,
                    plain_size: plain_data.len(),
                    encrypted_data: ciphertext.encrypted_data,
                    sha256_digest,
                    encrypted_signature: ciphertext.encrypted_signature,
                    verification_token,
                });
            }
            Err(error) if attempt <= MAX_BLOCK_ENCRYPTION_RETRIES => {
                tracing::warn!(
                    block_number,
                    attempt,
                    "Block failed verification, encrypting it again: {error:#}"
                );
            }
            Err(error) => {
                tracing::error!(
                    block_number,
                    attempt,
                    "Block failed verification: {error:#}"
                );
                return Err(error.context(format!(
                    "Block {block_number} failed verification after {attempt} encryptions"
                )));
            }
        }
    }
}

#[derive(Clone)]
pub struct BlockUploader {
    pub queue: crate::node::transfer::TransferQueue,
}

impl BlockUploader {
    pub fn new(max_degree_of_parallelism: usize) -> Self {
        Self {
            queue: crate::node::transfer::TransferQueue::new(max_degree_of_parallelism),
        }
    }

    /// Encrypts a block of data without uploading it.
    /// This is the CPU-bound portion that can be pipelined ahead of uploads.
    #[tracing::instrument(skip(self, draft, plain_data))]
    pub fn encrypt_block(
        &self,
        draft: &RevisionDraft,
        block_number: i32,
        plain_data: &[u8],
    ) -> anyhow::Result<EncryptedBlock> {
        tracing::debug!(block_number, size = plain_data.len(), "Encrypting block");
        encrypt_and_verify(block_number, plain_data, &draft.block_verifier, || {
            encrypt_content(draft, plain_data)
        })
    }

    /// Uploads a pre-encrypted block to storage.
    /// This is the I/O-bound portion.
    #[tracing::instrument(skip(self, client, draft, encrypted_block, on_sent))]
    pub async fn upload_encrypted_block(
        &self,
        client: &ProtonDriveClient,
        draft: &RevisionDraft,
        encrypted_block: EncryptedBlock,
        on_sent: crate::api::storage::BlobProgress,
    ) -> anyhow::Result<BlockUploadResult> {
        let _permit = self.queue.start_block().await?;
        tracing::debug!(
            block_number = encrypted_block.block_number,
            encrypted_size = encrypted_block.encrypted_data.len(),
            "Uploading pre-encrypted block"
        );

        // Prepare Block Upload
        let address = client.account().get_default_address().await?;
        let request = crate::api::block::BlockUploadPreparationRequest {
            address_id: crate::account::AddressId::new(address.address_id),
            volume_id: draft.uid.node_uid.volume_id.clone(),
            link_id: draft.uid.node_uid.link_id.clone(),
            revision_id: draft.uid.revision_id.clone(),
            blocks: vec![crate::api::block::BlockCreationRequest {
                index: encrypted_block.block_number,
                size: encrypted_block.encrypted_data.len() as i32,
                encrypted_signature: encrypted_block.encrypted_signature,
                hash_digest: encrypted_block.sha256_digest.clone(),
                verification_output: crate::api::block::verification::BlockVerificationOutput {
                    token: encrypted_block.verification_token,
                },
            }],
            thumbnails: vec![],
        };

        let response = client.api().files().prepare_block_upload(request).await?;
        let target = response
            .upload_targets
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("No upload target returned"))?;

        // Upload Blob
        client
            .api()
            .storage()
            .upload_blob_with_progress(
                &target.bare_url,
                &target.token,
                encrypted_block.encrypted_data.into(),
                on_sent,
            )
            .await?;

        Ok(BlockUploadResult {
            size: encrypted_block.plain_size,
            sha256_digest: encrypted_block.sha256_digest,
        })
    }

    #[tracing::instrument(skip(self, client, draft, plain_data, on_block_progress))]
    pub async fn upload_content(
        &self,
        client: &ProtonDriveClient,
        draft: &RevisionDraft,
        block_number: i32,
        plain_data: &[u8],
        on_block_progress: Option<&Box<dyn Fn(i64) + Send + Sync>>,
    ) -> anyhow::Result<BlockUploadResult> {
        let _permit = self.queue.start_block().await?;
        tracing::debug!(block_number, size = plain_data.len(), "Uploading block");
        let plain_data_len = plain_data.len();

        // 1. Sign, encrypt and verify
        let EncryptedBlock {
            encrypted_data,
            sha256_digest,
            encrypted_signature,
            verification_token,
            ..
        } = encrypt_and_verify(block_number, plain_data, &draft.block_verifier, || {
            encrypt_content(draft, plain_data)
        })?;

        // 2. Prepare Block Upload
        let address = client.account().get_default_address().await?;
        let request = crate::api::block::BlockUploadPreparationRequest {
            address_id: crate::account::AddressId::new(address.address_id),
            volume_id: draft.uid.node_uid.volume_id.clone(),
            link_id: draft.uid.node_uid.link_id.clone(),
            revision_id: draft.uid.revision_id.clone(),
            blocks: vec![crate::api::block::BlockCreationRequest {
                index: block_number,
                size: encrypted_data.len() as i32,
                encrypted_signature,
                hash_digest: sha256_digest.clone(),
                verification_output: crate::api::block::verification::BlockVerificationOutput {
                    token: verification_token,
                },
            }],
            thumbnails: vec![],
        };

        let response = client.api().files().prepare_block_upload(request).await?;
        let target = response
            .upload_targets
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("No upload target returned"))?;

        // 3. Upload Blob
        client
            .api()
            .storage()
            .upload_blob(&target.bare_url, &target.token, encrypted_data.into())
            .await?;

        if let Some(on_progress) = on_block_progress {
            on_progress(plain_data_len as i64);
        }

        Ok(BlockUploadResult {
            size: plain_data_len,
            sha256_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoGenerator;
    use crate::error::IntegrityException;
    use crate::pgp::PgpSessionKey;

    fn ciphertext(session_key: &PgpSessionKey, plain: &[u8]) -> BlockCiphertext {
        BlockCiphertext {
            encrypted_data: proton_rpgp::Encryptor::default()
                .with_session_key(session_key.to_rpgp_sk().unwrap())
                .encrypt(plain)
                .unwrap()
                .to_bytes()
                .unwrap(),
            encrypted_signature: PgpArmoredMessage(String::new()),
        }
    }

    /// An encryption whose first `bad` results have a flipped bit, as a faulty
    /// memory or CPU might produce.
    fn flaky_encryption(
        session_key: &PgpSessionKey,
        plain: &[u8],
        bad: usize,
        calls: &mut usize,
    ) -> anyhow::Result<BlockCiphertext> {
        *calls += 1;
        let mut result = ciphertext(session_key, plain);
        if *calls <= bad {
            let middle = result.encrypted_data.len() / 2;
            result.encrypted_data[middle] ^= 0x80;
        }
        Ok(result)
    }

    #[test]
    fn a_block_that_fails_verification_once_is_encrypted_again() {
        let key = CryptoGenerator::generate_session_key();
        let verifier = BlockVerifier::new(key.clone(), vec![9; 32]);
        let plain = vec![1u8; 100_000];
        let mut calls = 0;
        let block = encrypt_and_verify(4, &plain, &verifier, || {
            flaky_encryption(&key, &plain, 1, &mut calls)
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(block.block_number, 4);
        assert_eq!(block.plain_size, plain.len());
        assert_eq!(
            block.sha256_digest,
            sha2::Sha256::digest(&block.encrypted_data).to_vec()
        );
        assert_eq!(key.decrypt(&block.encrypted_data).unwrap(), plain);
    }

    #[test]
    fn a_block_that_fails_verification_twice_is_an_integrity_error() {
        let key = CryptoGenerator::generate_session_key();
        let verifier = BlockVerifier::new(key.clone(), vec![9; 32]);
        let plain = vec![1u8; 100_000];
        let mut calls = 0;
        let error = encrypt_and_verify(4, &plain, &verifier, || {
            flaky_encryption(&key, &plain, usize::MAX, &mut calls)
        })
        .err()
        .unwrap();
        assert_eq!(calls, 1 + MAX_BLOCK_ENCRYPTION_RETRIES as usize);
        assert!(
            error.chain().any(|cause| cause.is::<IntegrityException>()),
            "{error:#}"
        );
    }

    #[test]
    fn an_encryption_error_is_not_retried() {
        let key = CryptoGenerator::generate_session_key();
        let verifier = BlockVerifier::new(key, vec![9; 32]);
        let mut calls = 0;
        let error = encrypt_and_verify(1, b"data", &verifier, || {
            calls += 1;
            Err(anyhow::anyhow!("no signing key"))
        })
        .err()
        .unwrap();
        assert_eq!(calls, 1);
        assert!(!error.chain().any(|cause| cause.is::<IntegrityException>()));
    }

    /// The cost of the check per 4 MiB block, against the encryption it follows.
    /// `cargo test --release -p proton-drive-sdk verification_cost -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn verification_cost() {
        let key = CryptoGenerator::generate_session_key();
        let verifier = BlockVerifier::new(key.clone(), vec![9; 32]);
        let plain: Vec<u8> = (0..4 << 20).map(|i: u32| (i * 7 % 251) as u8).collect();
        let rounds = 20;
        let start = std::time::Instant::now();
        let mut blocks = Vec::new();
        for _ in 0..rounds {
            blocks.push(ciphertext(&key, &plain).encrypted_data);
        }
        let encrypt = start.elapsed() / rounds;
        let start = std::time::Instant::now();
        for block in &blocks {
            verifier.verify_block(block, &plain).unwrap();
        }
        let verify = start.elapsed() / rounds;
        println!("per 4 MiB block: encrypt {encrypt:?}, verify {verify:?}");
    }
}

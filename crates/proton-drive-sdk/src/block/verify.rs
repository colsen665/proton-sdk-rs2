use crate::api::block::verification::{
    BlockVerificationApiClient, DefaultBlockVerificationApiClient,
};
use crate::error::IntegrityException;
use crate::node::revision::RevisionUid;
use crate::pgp::{PgpPrivateKey, PgpSessionKey};
use proton_sdk_rs2::auth::TokenCredential;
use reqwest::Url;
use reqwest_middleware::ClientWithMiddleware;

/// Checks each encrypted block before it is uploaded, and computes the token the
/// server checks it against.
///
/// The session key is the one the verification endpoint returns for the revision
/// (its content key packet, decrypted with the node key), so a block encrypted with
/// another key fails here instead of after the commit.
#[derive(Clone)]
pub struct BlockVerifier {
    session_key: PgpSessionKey,
    verification_code: Vec<u8>,
}

impl BlockVerifier {
    pub fn new(session_key: PgpSessionKey, verification_code: Vec<u8>) -> Self {
        Self {
            session_key,
            verification_code,
        }
    }

    /// How many bytes of the encrypted block go into the verification token.
    pub fn data_packet_prefix_max_length(&self) -> usize {
        self.verification_code.len()
    }

    /// Decrypts the whole encrypted block with the verification session key and
    /// compares the result with `plain_data`, then returns the verification token.
    ///
    /// The official SDKs check this before every block upload: C# decrypts a prefix
    /// and compares it with the plaintext's (`BlockVerifierBase.VerifyBlock`), JS
    /// decrypts the whole block "to try to detect bitflips / bad hardware"
    /// (`cryptoService.verifyBlock`). This does both. Decrypting the whole block
    /// checks the packet's integrity tag (MDC or AEAD) over all of it, which a prefix
    /// of a SEIPDv1 packet cannot; the comparison catches a block encrypted from
    /// other data. A failure is an [`IntegrityException`], and the caller encrypts
    /// the block again.
    pub fn verify_block(
        &self,
        encrypted_data: &[u8],
        plain_data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let decrypted = self.session_key.decrypt(encrypted_data).map_err(|error| {
            IntegrityException::new(format!(
                "Block does not decrypt with the verification session key: {error}"
            ))
        })?;
        if decrypted != plain_data {
            return Err(
                IntegrityException::new("Block decrypts to other data than its plaintext").into(),
            );
        }
        Ok(create_verification_token(
            &self.verification_code,
            encrypted_data,
        ))
    }
}

/// The verification code XORed with the encrypted block's first bytes, zero-padded
/// when the block is shorter than the code.
fn create_verification_token(verification_code: &[u8], data_packet_prefix: &[u8]) -> Vec<u8> {
    verification_code
        .iter()
        .enumerate()
        .map(|(i, code)| code ^ data_packet_prefix.get(i).copied().unwrap_or(0))
        .collect()
}

#[async_trait::async_trait]
pub trait BlockVerifierFactory: Send + Sync {
    async fn create(
        &self,
        revision_uid: RevisionUid,
        key: &PgpPrivateKey,
    ) -> anyhow::Result<BlockVerifier>;
}

pub struct DefaultBlockVerifierFactory {
    api_client: Box<dyn BlockVerificationApiClient>,
}

impl DefaultBlockVerifierFactory {
    pub fn new(
        client: ClientWithMiddleware,
        base_url: Url,
        token_credential: Option<TokenCredential>,
    ) -> Self {
        Self {
            api_client: Box::new(DefaultBlockVerificationApiClient::new(
                client,
                base_url,
                token_credential,
            )),
        }
    }
}

#[async_trait::async_trait]
impl BlockVerifierFactory for DefaultBlockVerifierFactory {
    async fn create(
        &self,
        revision_uid: RevisionUid,
        key: &PgpPrivateKey,
    ) -> anyhow::Result<BlockVerifier> {
        let verification_input = self
            .api_client
            .get_verification_input(
                &revision_uid.node_uid.volume_id,
                &revision_uid.node_uid.link_id,
                &revision_uid.revision_id,
            )
            .await?;

        let session_key = key
            .decrypt_session_key(&verification_input.content_key_packet)
            .map_err(|e| anyhow::anyhow!("Node key and session key mismatch: {}", e))?;

        Ok(BlockVerifier::new(
            session_key,
            verification_input.verification_code.unwrap_or_default(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IntegrityException;
    use proton_rpgp::pgp::ser::Serialize;

    fn encrypt(session_key: &PgpSessionKey, plain: &[u8]) -> Vec<u8> {
        proton_rpgp::Encryptor::default()
            .with_session_key(session_key.to_rpgp_sk().unwrap())
            .encrypt(plain)
            .unwrap()
            .to_bytes()
            .unwrap()
    }

    fn verifier_with(session_key: &PgpSessionKey, code: &[u8]) -> BlockVerifier {
        BlockVerifier::new(session_key.clone(), code.to_vec())
    }

    fn is_integrity_error(error: &anyhow::Error) -> bool {
        error.chain().any(|cause| cause.is::<IntegrityException>())
    }

    #[test]
    fn verification_prefix_length_matches_code_length() {
        let key = crate::crypto::CryptoGenerator::generate_session_key();
        assert_eq!(
            verifier_with(&key, &[1; 32]).data_packet_prefix_max_length(),
            32
        );
    }

    #[test]
    fn a_block_that_decrypts_to_its_plaintext_gets_the_token() {
        let key = crate::crypto::CryptoGenerator::generate_session_key();
        let plain = b"block content".repeat(1000);
        let encrypted = encrypt(&key, &plain);
        let code: Vec<u8> = (0..32).collect();
        let token = verifier_with(&key, &code)
            .verify_block(&encrypted, &plain)
            .unwrap();
        let expected: Vec<u8> = code.iter().zip(&encrypted).map(|(c, d)| c ^ d).collect();
        assert_eq!(token, expected);
    }

    #[test]
    fn an_empty_block_verifies() {
        let key = crate::crypto::CryptoGenerator::generate_session_key();
        let encrypted = encrypt(&key, b"");
        assert!(
            verifier_with(&key, &[7; 32])
                .verify_block(&encrypted, b"")
                .is_ok()
        );
    }

    #[test]
    fn a_flipped_bit_anywhere_in_the_block_fails_verification() {
        let key = crate::crypto::CryptoGenerator::generate_session_key();
        let plain = vec![0x5a; 300_000];
        let encrypted = encrypt(&key, &plain);
        for position in [encrypted.len() / 2, encrypted.len() - 30] {
            let mut tampered = encrypted.clone();
            tampered[position] ^= 0x01;
            let error = verifier_with(&key, &[1; 32])
                .verify_block(&tampered, &plain)
                .unwrap_err();
            assert!(is_integrity_error(&error), "{error:#}");
        }
    }

    #[test]
    fn a_block_encrypted_with_another_session_key_fails_verification() {
        let key = crate::crypto::CryptoGenerator::generate_session_key();
        let other = crate::crypto::CryptoGenerator::generate_session_key();
        let plain = b"content".to_vec();
        let encrypted = encrypt(&other, &plain);
        let error = verifier_with(&key, &[1; 32])
            .verify_block(&encrypted, &plain)
            .unwrap_err();
        assert!(is_integrity_error(&error), "{error:#}");
    }

    #[test]
    fn a_block_of_other_plaintext_fails_verification() {
        let key = crate::crypto::CryptoGenerator::generate_session_key();
        let encrypted = encrypt(&key, b"content A");
        for plain in [&b"content B"[..], b"content A ", b"content", b""] {
            let error = verifier_with(&key, &[1; 32])
                .verify_block(&encrypted, plain)
                .unwrap_err();
            assert!(is_integrity_error(&error), "{error:#}");
        }
    }

    #[test]
    fn a_seipdv2_session_key_verifies_its_block() {
        let key = PgpSessionKey {
            algorithm: 0,
            key: crate::crypto::CryptoGenerator::generate_session_key().key,
        };
        let plain = vec![3u8; 200_000];
        let encrypted = encrypt(&key, &plain);
        assert!(
            verifier_with(&key, &[1; 32])
                .verify_block(&encrypted, &plain)
                .is_ok()
        );
    }

    #[test]
    fn verification_token_pads_short_and_truncates_long_prefixes() {
        assert_eq!(create_verification_token(&[1, 1, 1], &[1]), vec![0, 1, 1]);
        assert_eq!(
            create_verification_token(&[1, 1, 1], &[1, 1, 1, 1]),
            vec![0, 0, 0]
        );
        assert_eq!(
            create_verification_token(&[1, 2, 3], &[3, 2, 1]),
            vec![2, 0, 2]
        );
    }
}

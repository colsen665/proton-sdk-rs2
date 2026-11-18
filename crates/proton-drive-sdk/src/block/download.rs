use crate::client::ProtonDriveClient;
use crate::node::download::DataIntegrityException;
use crate::node::revision::RevisionUid;
use crate::pgp::PgpSessionKey;
use sha2::Digest;
use tokio::io::{AsyncWrite, AsyncWriteExt};

const MAX_RETRIES: u32 = 4;

#[derive(Clone)]
pub struct BlockDownloader {
    pub queue: crate::node::transfer::TransferQueue,
}

impl BlockDownloader {
    pub fn new(max_degree_of_parallelism: usize) -> Self {
        Self {
            queue: crate::node::transfer::TransferQueue::new(max_degree_of_parallelism),
        }
    }

    /// Downloads and decrypts one block without checking its hash.
    ///
    /// Prefer [`Self::download_verified`], which also compares the SHA-256 of the
    /// encrypted blob with the hash listed for the block.
    pub async fn download(
        &self,
        client: &ProtonDriveClient,
        revision_uid: RevisionUid,
        index: i32,
        bare_url: String,
        token: String,
        content_key: PgpSessionKey,
        output_stream: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> anyhow::Result<Vec<u8>> {
        self.download_verified(
            client,
            revision_uid,
            index,
            bare_url,
            token,
            &[],
            content_key,
            output_stream,
        )
        .await
    }

    /// Downloads one block, checks its hash, decrypts it and writes the plaintext
    /// to `output_stream`. Returns the SHA-256 digest of the encrypted blob.
    ///
    /// When `expected_hash` is non-empty and differs from the digest of the
    /// downloaded blob, this fails with [`DataIntegrityException`] before anything
    /// is decrypted or written. That error is not retried. An expired target is
    /// refreshed once through the revision block listing.
    #[allow(clippy::too_many_arguments)]
    pub async fn download_verified(
        &self,
        client: &ProtonDriveClient,
        revision_uid: RevisionUid,
        index: i32,
        bare_url: String,
        token: String,
        expected_hash: &[u8],
        content_key: PgpSessionKey,
        output_stream: &mut (dyn AsyncWrite + Unpin + Send),
    ) -> anyhow::Result<Vec<u8>> {
        let _permit = self.queue.start_block().await?;

        let (bytes, digest) = download_with_retries(
            index,
            bare_url,
            token,
            expected_hash,
            |url, token| async move {
                let response = client.api().storage().get_blob_stream(&url, &token).await?;
                Ok(response.bytes().await?.to_vec())
            },
            || refresh_target(client, &revision_uid, index),
            |throttled| {
                if throttled {
                    client.sdk_events().requests_throttled();
                } else {
                    client.sdk_events().requests_unthrottled();
                }
            },
        )
        .await?;

        // Decryption and local I/O failures are not fixed by retrying the same
        // blob target, so they happen after the retry loop.
        let plaintext = content_key.decrypt(&bytes)?;
        output_stream.write_all(&plaintext).await?;
        Ok(digest)
    }
}

/// Compares the SHA-256 digest of a downloaded encrypted block with the hash the
/// API listed for it. An empty `expected` hash is not checked.
pub fn verify_block_hash(
    index: i32,
    expected: &[u8],
    actual: &[u8],
) -> Result<(), DataIntegrityException> {
    if expected.is_empty() || expected == actual {
        return Ok(());
    }
    Err(DataIntegrityException::new(format!(
        "Part of the file appears to be corrupted: block #{index} hash mismatch (expected {}, got {})",
        hex::encode(expected),
        hex::encode(actual)
    )))
}

#[derive(Debug, PartialEq, Eq)]
enum ErrorAction {
    Fail,
    Retry { throttled: bool },
    RefreshTarget,
}

fn classify_error(error: &anyhow::Error, refreshed_target: bool) -> ErrorAction {
    if error.downcast_ref::<DataIntegrityException>().is_some() {
        return ErrorAction::Fail;
    }
    if let Some(http_error) = error.downcast_ref::<crate::error::HttpTransferError>() {
        if http_error.is_expired_target() && !refreshed_target {
            return ErrorAction::RefreshTarget;
        }
        if !http_error.is_retryable() {
            return ErrorAction::Fail;
        }
        return ErrorAction::Retry { throttled: false };
    }
    if error
        .downcast_ref::<crate::error::TooManyRequestsException>()
        .is_some()
    {
        return ErrorAction::Retry { throttled: true };
    }
    if error
        .downcast_ref::<reqwest::Error>()
        .is_some_and(|error| error.is_connect() || error.is_timeout())
    {
        return ErrorAction::Retry { throttled: false };
    }
    ErrorAction::Fail
}

fn retry_delay(last_error: Option<&anyhow::Error>, attempt: u32) -> std::time::Duration {
    last_error
        .and_then(|error| {
            error
                .downcast_ref::<crate::error::TooManyRequestsException>()
                .and_then(|error| error.retry_after)
                .or_else(|| {
                    error
                        .downcast_ref::<crate::error::HttpTransferError>()
                        .and_then(|error| error.retry_after)
                })
        })
        .unwrap_or_else(|| crate::error::retry_backoff_delay(attempt))
}

/// Fetches an encrypted block with retries and checks its hash.
///
/// `fetch(url, token)` returns the encrypted blob, `refresh()` returns a fresh
/// target for an expired one, and `on_throttle(true/false)` reports throttling
/// changes. Returns the encrypted blob and its SHA-256 digest.
async fn download_with_retries<Fetch, FetchFut, Refresh, RefreshFut>(
    index: i32,
    bare_url: String,
    token: String,
    expected_hash: &[u8],
    mut fetch: Fetch,
    mut refresh: Refresh,
    on_throttle: impl Fn(bool),
) -> anyhow::Result<(Vec<u8>, Vec<u8>)>
where
    Fetch: FnMut(String, String) -> FetchFut,
    FetchFut: std::future::Future<Output = anyhow::Result<Vec<u8>>>,
    Refresh: FnMut() -> RefreshFut,
    RefreshFut: std::future::Future<Output = anyhow::Result<Option<(String, String)>>>,
{
    let mut current_url = bare_url;
    let mut current_token = token;
    let mut refreshed_target = false;
    let mut last_error: Option<anyhow::Error> = None;
    let mut was_throttled = false;

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            tokio::time::sleep(retry_delay(last_error.as_ref(), attempt)).await;
        }

        let result = async {
            let bytes = fetch(current_url.clone(), current_token.clone()).await?;
            let digest = sha2::Sha256::digest(&bytes).to_vec();
            verify_block_hash(index, expected_hash, &digest)?;
            Ok::<_, anyhow::Error>((bytes, digest))
        }
        .await;

        match result {
            Ok(downloaded) => {
                if was_throttled {
                    on_throttle(false);
                }
                return Ok(downloaded);
            }
            Err(error) => match classify_error(&error, refreshed_target) {
                ErrorAction::Fail => return Err(error),
                ErrorAction::RefreshTarget => {
                    let Some((url, new_token)) = refresh().await? else {
                        return Err(error);
                    };
                    current_url = url;
                    current_token = new_token;
                    refreshed_target = true;
                    last_error = Some(error);
                }
                ErrorAction::Retry { throttled } => {
                    if throttled {
                        on_throttle(true);
                        was_throttled = true;
                    }
                    last_error = Some(error);
                }
            },
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("block download failed")))
}

async fn refresh_target(
    client: &ProtonDriveClient,
    revision_uid: &RevisionUid,
    index: i32,
) -> anyhow::Result<Option<(String, String)>> {
    let response = client
        .api()
        .files()
        .get_revision(
            revision_uid.node_uid.volume_id.clone(),
            revision_uid.node_uid.link_id.clone(),
            revision_uid.revision_id.clone(),
            Some(index),
            Some(1),
            false,
        )
        .await?;

    Ok(response
        .revision
        .blocks
        .into_iter()
        .find(|block| block.index == index)
        .map(|block| (block.bare_url, block.token)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn sha256(data: &[u8]) -> Vec<u8> {
        sha2::Sha256::digest(data).to_vec()
    }

    async fn run(
        expected_hash: &[u8],
        blob: &'static [u8],
        fetches: &AtomicUsize,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        download_with_retries(
            3,
            "https://storage.test/3".into(),
            "token".into(),
            expected_hash,
            |_, _| async {
                fetches.fetch_add(1, Ordering::SeqCst);
                Ok(blob.to_vec())
            },
            || async { panic!("target must not be refreshed") },
            |_| panic!("must not be throttled"),
        )
        .await
    }

    #[test]
    fn block_hash_check_accepts_match_and_empty_expectation() {
        let digest = sha256(b"blob");
        assert!(verify_block_hash(1, &digest, &digest).is_ok());
        assert!(verify_block_hash(1, &[], &digest).is_ok());
    }

    #[test]
    fn block_hash_check_rejects_mismatch() {
        let error = verify_block_hash(7, &sha256(b"expected"), &sha256(b"actual")).unwrap_err();
        assert!(error.message.contains("block #7"), "{error}");
    }

    #[test]
    fn data_integrity_errors_are_not_retried() {
        let error: anyhow::Error = DataIntegrityException::new("bad block").into();
        assert_eq!(classify_error(&error, false), ErrorAction::Fail);
        assert_eq!(classify_error(&error, true), ErrorAction::Fail);
    }

    #[tokio::test]
    async fn digest_mismatch_fails_with_data_integrity_error_after_one_fetch() {
        let fetches = AtomicUsize::new(0);

        let error = run(&sha256(b"other blob"), b"blob", &fetches)
            .await
            .unwrap_err();

        assert!(
            error.downcast_ref::<DataIntegrityException>().is_some(),
            "{error}"
        );
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn matching_digest_returns_blob_and_digest() {
        let fetches = AtomicUsize::new(0);

        let (bytes, digest) = run(&sha256(b"blob"), b"blob", &fetches).await.unwrap();

        assert_eq!(bytes, b"blob");
        assert_eq!(digest, sha256(b"blob"));
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn empty_expected_hash_skips_the_check() {
        let fetches = AtomicUsize::new(0);

        let (_, digest) = run(&[], b"blob", &fetches).await.unwrap();

        assert_eq!(digest, sha256(b"blob"));
    }
}

use crate::api::block::BlockUploadPreparationRequest;
use crate::api::file::thumbnail::ThumbnailCreationRequest;
use crate::author::Author;
use crate::block::upload::BlockUploadResult;
use crate::client::ProtonDriveClient;
use crate::error::ProtonDriveError;
use crate::links::LinkId;
use crate::meta::AdditionalMetadataProperty;
use crate::node::NodeUid;
use crate::node::download::DownloadState;
use crate::node::draft::RevisionDraft;
use crate::node::file::FileContentDigests;
use crate::node::photo::PhotoUploadContext;
use crate::pgp::PgpArmoredMessage;
use crate::protobuf::SignatureVerificationError;
use crate::protobuf::ThumbnailHeader;
use crate::revision::RevisionId;
use crate::utils::PotentialObject;
use crate::volume::VolumeId;
use anyhow::Context;
use chrono::{DateTime, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use proton_rpgp::AsPublicKeyRef;
use proton_rpgp::Encryptor;
use proton_rpgp::pgp::ser::Serialize as _;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha2::Digest;
use sha2::Sha256;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

pub const REVISION_WRITER_DEFAULT_BLOCK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct DegradedRevision {
    /// Unique identifier combining the parent node UID and the revision ID.
    pub uid: RevisionUid,
    /// When this revision was committed on the server.
    pub creation_time: DateTime<Utc>,
    /// Encrypted size of the revision stored on cloud storage.
    pub size_on_cloud_storage: i64,
    /// Plaintext size declared by the uploader; `None` if unavailable.
    pub claimed_size: Option<i64>,
    /// Content digests declared by the uploader; `None` if decryption of extended attributes failed.
    pub claimed_digests: Option<FileContentDigests>,
    /// Last-modified timestamp declared by the uploader; `None` if unavailable.
    pub claimed_modification_time: Option<DateTime<Utc>>,
    /// Thumbnail descriptors attached to this revision.
    pub thumbnails: Vec<ThumbnailHeader>,
    /// Additional metadata properties that could not be mapped to known fields.
    pub additional_claimed_metadata: Option<Vec<AdditionalMetadataProperty>>,
    /// Authorship claim for the content signature; `None` if the revision has no content block.
    pub content_author: Option<PotentialObject<Author, SignatureVerificationError>>,
    /// `true` when the revision's content key could be decrypted and blocks can be downloaded.
    pub can_decrypt: bool,
    /// Non-fatal errors encountered while decrypting or verifying this revision.
    pub errors: Vec<ProtonDriveError>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Revision {
    /// Unique identifier combining the parent node UID and the revision ID.
    pub uid: RevisionUid,
    /// When this revision was committed on the server.
    pub creation_time: DateTime<Utc>,
    /// Encrypted size of the revision stored on cloud storage.
    pub size_on_cloud_storage: i64,
    /// Plaintext size in bytes declared by the uploader.
    pub claimed_size: Option<i64>,
    /// Content digests declared by the uploader (SHA-1 etc.) for post-download verification.
    pub claimed_digests: FileContentDigests,
    /// Last-modified timestamp declared by the uploader.
    pub claimed_modification_time: Option<DateTime<Utc>>,
    /// Thumbnail descriptors attached to this revision.
    pub thumbnails: Vec<ThumbnailHeader>,
    /// Additional metadata properties that could not be mapped to known fields.
    pub additional_claimed_metadata: Option<Vec<AdditionalMetadataProperty>>,
    /// Authorship claim for the content signature.
    pub content_author: Option<PotentialObject<Author, SignatureVerificationError>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum RevisionState {
    Draft = 0,
    Active = 1,
    Superseded = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionInfo {
    /// Unique identifier combining the parent node UID and the revision ID.
    pub uid: RevisionUid,
    /// Lifecycle state of this revision (draft, active, or superseded).
    pub state: RevisionState,
    /// When the revision was committed on the server.
    pub creation_time: DateTime<Utc>,
    /// Encrypted size of the revision data stored on cloud storage.
    pub size_on_cloud_storage: i64,
    /// Plaintext size in bytes as declared by the uploader; `None` if not provided.
    pub claimed_size: Option<i64>,
    /// Last-modified timestamp declared by the uploader at upload time.
    pub claimed_modification_time: Option<DateTime<Utc>>,
    /// SHA-1 digest of the plaintext content as declared by the uploader.
    pub claimed_sha1: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(try_from = "String", into = "String")]
pub struct RevisionUid {
    pub node_uid: NodeUid,
    pub revision_id: RevisionId,
}

impl RevisionUid {
    pub fn new(node_uid: NodeUid, revision_id: RevisionId) -> Self {
        Self {
            node_uid,
            revision_id,
        }
    }

    pub fn from_parts(volume_id: VolumeId, link_id: LinkId, revision_id: RevisionId) -> Self {
        Self {
            node_uid: NodeUid::new(volume_id, link_id),
            revision_id,
        }
    }

    pub fn try_parse(s: &str) -> Option<Self> {
        // format: {volumeId}~{linkId}~{revisionId}
        let mut parts = s.rsplitn(2, '~');
        let revision_id = parts.next()?;
        let node_uid_str = parts.next()?;
        let node_uid = NodeUid::try_parse(node_uid_str)?;
        Some(Self {
            node_uid,
            revision_id: RevisionId::new(revision_id.to_string()),
        })
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        Self::try_parse(s).ok_or_else(|| format!("Invalid revision UID format: \"{}\"", s))
    }

    pub fn deconstruct(self) -> (NodeUid, RevisionId) {
        (self.node_uid, self.revision_id)
    }
}

impl std::fmt::Display for RevisionUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}~{}", self.node_uid, self.revision_id.raw())
    }
}

impl From<RevisionUid> for String {
    fn from(uid: RevisionUid) -> Self {
        uid.to_string()
    }
}

impl TryFrom<String> for RevisionUid {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        RevisionUid::parse(&s)
    }
}

pub struct RevisionOperations;

impl RevisionOperations {
    pub(crate) async fn open_for_writing(
        client: &ProtonDriveClient,
        draft: RevisionDraft,
        release_blocks_action: Box<dyn Fn(i32) + Send + Sync>,
        expected_size: i64,
        last_modification_time: Option<DateTime<Utc>>,
        additional_metadata: Option<Vec<AdditionalMetadataProperty>>,
        media_info: Option<crate::api::attr::MediaExtendedAttributes>,
        expected_sha1: Option<Vec<u8>>,
        photos: Option<&PhotoUploadContext>,
    ) -> anyhow::Result<RevisionWriter> {
        let file_permit = client.block_uploader().queue.start_file().await?;

        Ok(RevisionWriter {
            client: Arc::new(client.clone()),
            draft,
            release_blocks_action,
            _file_permit: file_permit,
            target_block_size: client.target_block_size(),
            total_written: 0,
            block_number: 1,
            digests: Vec::new(),
            block_sizes: Vec::new(),
            thumbnail_digests: Vec::new(),
            sha1_hasher: sha1::Sha1::default(),
            precomputed_sha1: None,
            expected_size,
            last_modification_time,
            additional_metadata,
            media_info,
            expected_sha1,
            photos: photos.cloned(),
        })
    }

    pub async fn create_download_state(
        client: &ProtonDriveClient,
        revision_uid: RevisionUid,
        release_block_listing_action: Box<dyn Fn(i32) + Send + Sync>,
    ) -> anyhow::Result<DownloadState> {
        tracing::debug!("Getting node metadata for revision_uid={}", revision_uid);
        let _node_metadata = crate::node::operations::NodeOperations::get_node(
            client,
            revision_uid.node_uid.clone(),
        )
        .await
        .context("Failed to get node metadata")?;

        tracing::debug!("Getting secrets for node_uid={}", revision_uid.node_uid);
        let secrets =
            crate::node::file::FileOperations::get_secrets(client, revision_uid.node_uid.clone())
                .await
                .context("Failed to get file secrets")?;

        tracing::debug!(
            "Getting revision blocks for revision_id={}",
            revision_uid.revision_id.raw()
        );
        // The API lists blocks a page at a time; a full page means more follow.
        let page_size = crate::node::download::DEFAULT_BLOCK_PAGE_SIZE;
        let mut revision_response = client
            .api()
            .files()
            .get_revision(
                revision_uid.node_uid.volume_id.clone(),
                revision_uid.node_uid.link_id.clone(),
                revision_uid.revision_id.clone(),
                Some(crate::node::download::MIN_BLOCK_INDEX),
                Some(page_size),
                false,
            )
            .await
            .context("Failed to get revision from API")?;
        let mut page_len = revision_response.revision.blocks.len();
        while let Some(from_index) =
            next_block_page_start(&revision_response.revision.blocks, page_len, page_size)
        {
            let page = client
                .api()
                .files()
                .get_revision(
                    revision_uid.node_uid.volume_id.clone(),
                    revision_uid.node_uid.link_id.clone(),
                    revision_uid.revision_id.clone(),
                    Some(from_index),
                    Some(page_size),
                    false,
                )
                .await
                .context("Failed to get revision blocks from API")?
                .revision
                .blocks;
            page_len = page.len();
            revision_response.revision.blocks.extend(page);
        }
        ensure_contiguous_blocks(&revision_response.revision.blocks)?;

        tracing::debug!(
            "Download state created for revision {:?}: {} blocks, size={}",
            revision_uid.revision_id,
            revision_response.revision.blocks.len(),
            revision_response.revision.revision.size
        );

        release_block_listing_action(1);

        Ok(DownloadState::new(
            revision_uid,
            revision_response.revision,
            secrets.base.key,
            secrets.content_key,
        ))
    }

    pub fn open_for_reading(
        client: &ProtonDriveClient,
        download_state: Arc<DownloadState>,
        release_block_listing_action: Box<dyn Fn(i32) + Send + Sync>,
    ) -> crate::node::download::RevisionReader {
        crate::node::download::RevisionReader::new(
            Arc::new(client.clone()),
            download_state,
            release_block_listing_action,
        )
    }
}

/// Where the next block page starts, or `None` once a short page ended the listing.
fn next_block_page_start(
    blocks: &[crate::api::block::BlockDto],
    last_page_len: usize,
    page_size: i32,
) -> Option<i32> {
    if last_page_len == 0 || last_page_len < page_size as usize {
        return None;
    }
    blocks.last().map(|block| block.index + 1)
}

/// Blocks must run 1, 2, 3, ... so no part of the file is silently skipped.
fn ensure_contiguous_blocks(blocks: &[crate::api::block::BlockDto]) -> anyhow::Result<()> {
    for (position, block) in blocks.iter().enumerate() {
        let expected = crate::node::download::MIN_BLOCK_INDEX + position as i32;
        anyhow::ensure!(
            block.index == expected,
            "revision block listing has block {} where {expected} was expected",
            block.index
        );
    }
    Ok(())
}

pub struct RevisionWriter {
    client: Arc<ProtonDriveClient>,
    draft: RevisionDraft,
    release_blocks_action: Box<dyn Fn(i32) + Send + Sync>,
    _file_permit: tokio::sync::OwnedSemaphorePermit,
    target_block_size: usize,
    total_written: i64,
    block_number: i32,
    digests: Vec<u8>,
    block_sizes: Vec<i32>,
    thumbnail_digests: Vec<u8>,
    sha1_hasher: sha1::Sha1,
    /// Pre-computed SHA1 hash from pipelined write (set by producer task)
    precomputed_sha1: Option<[u8; 20]>,
    expected_size: i64,
    last_modification_time: Option<DateTime<Utc>>,
    additional_metadata: Option<Vec<AdditionalMetadataProperty>>,
    media_info: Option<crate::api::attr::MediaExtendedAttributes>,
    expected_sha1: Option<Vec<u8>>,
    photos: Option<PhotoUploadContext>,
}

/// Upload progress across blocks sent in parallel: finished blocks plus the
/// share of each in-flight block already sent, in plaintext bytes.
struct UploadProgress {
    done: std::sync::atomic::AtomicI64,
    in_flight: std::sync::Mutex<std::collections::HashMap<i32, i64>>,
    expected: i64,
    on_progress: Arc<dyn Fn(i64, i64) + Send + Sync>,
}

impl UploadProgress {
    fn block_sent(&self, block: i32, plain_size: i64, sent: i64, encrypted_size: i64) {
        let share = if encrypted_size > 0 {
            plain_size * sent.min(encrypted_size) / encrypted_size
        } else {
            0
        };
        self.in_flight.lock().unwrap().insert(block, share);
        self.report();
    }

    fn block_done(&self, block: i32, plain_size: i64) {
        self.in_flight.lock().unwrap().remove(&block);
        self.done
            .fetch_add(plain_size, std::sync::atomic::Ordering::SeqCst);
        self.report();
    }

    fn report(&self) {
        let partial: i64 = self.in_flight.lock().unwrap().values().sum();
        let mut total = self.done.load(std::sync::atomic::Ordering::SeqCst) + partial;
        if self.expected > 0 {
            total = total.min(self.expected);
        }
        (self.on_progress)(total, self.expected);
    }
}

fn spawn_block_upload(
    client: Arc<ProtonDriveClient>,
    draft: RevisionDraft,
    encrypted_block: crate::block::upload::EncryptedBlock,
    block_size: i32,
    progress: Arc<UploadProgress>,
) -> tokio::task::JoinHandle<anyhow::Result<(i32, BlockUploadResult, i32)>> {
    tokio::spawn(async move {
        let block_number = encrypted_block.block_number;
        let plain_size = encrypted_block.plain_size as i64;
        let encrypted_size = encrypted_block.encrypted_data.len() as i64;
        let on_sent: crate::api::storage::BlobProgress = {
            let progress = progress.clone();
            Arc::new(move |sent| {
                progress.block_sent(block_number, plain_size, sent, encrypted_size)
            })
        };
        let result = client
            .block_uploader()
            .upload_encrypted_block(&client, &draft, encrypted_block, on_sent)
            .await?;
        progress.block_done(block_number, plain_size);
        Ok((block_number, result, block_size))
    })
}

impl RevisionWriter {
    /// Maximum number of blocks being uploaded concurrently.
    /// Matches the TypeScript SDK's MAX_UPLOADING_BLOCKS = 5.
    const MAX_CONCURRENT_UPLOADS: usize = 5;

    /// Maximum number of pre-encrypted blocks buffered ahead of uploads.
    /// Matches the TypeScript SDK's MAX_BUFFERED_BLOCKS = 15.
    const MAX_BUFFERED_BLOCKS: usize = 15;

    #[tracing::instrument(skip(self, content_stream, on_progress))]
    pub async fn write(
        &mut self,
        mut content_stream: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        on_progress: Arc<dyn Fn(i64, i64) + Send + Sync>,
        mut pause_rx: Option<tokio::sync::watch::Receiver<crate::node::download::ControllerState>>,
    ) -> anyhow::Result<()> {
        use crate::block::upload::EncryptedBlock;
        use tokio::sync::mpsc;

        tracing::debug!(
            expected_size = self.expected_size,
            "Starting pipelined write"
        );

        // Channel to buffer encrypted blocks between producer (encryption) and consumer (upload)
        let (tx, mut rx) = mpsc::channel::<(EncryptedBlock, i32)>(Self::MAX_BUFFERED_BLOCKS);

        // Shared state for collecting results
        let progress = Arc::new(UploadProgress {
            done: std::sync::atomic::AtomicI64::new(0),
            in_flight: std::sync::Mutex::new(std::collections::HashMap::new()),
            expected: self.expected_size,
            on_progress,
        });
        let block_results: Arc<Mutex<Vec<(i32, BlockUploadResult, i32)>>> =
            Arc::new(Mutex::new(Vec::new()));

        // Clone what we need for the producer task
        let client = self.client.clone();
        let draft = self.draft.clone();
        let target_block_size = self.target_block_size;
        let mut producer_pause = pause_rx.clone();

        // Producer task: reads blocks, encrypts them, sends to channel
        // Returns (block_count, sha1_hash)
        let producer = tokio::spawn(async move {
            let mut buffer = vec![0u8; target_block_size];
            let mut current_block = 1i32;
            let mut sha1_hasher = sha1::Sha1::default();

            loop {
                crate::node::download::wait_while_paused(&mut producer_pause).await;
                let mut n = 0;
                while n < target_block_size {
                    let read_bytes = content_stream.read(&mut buffer[n..]).await?;
                    if read_bytes == 0 {
                        break;
                    }
                    n += read_bytes;
                }

                if n == 0 {
                    break;
                }

                let block_data = buffer[..n].to_vec();
                let block_size = n as i32;

                // Update SHA1 hash (sequential, in order)
                sha1::Digest::update(&mut sha1_hasher, &block_data);

                // Encrypt the block (CPU-bound work done in producer)
                let encrypted_block =
                    client
                        .block_uploader()
                        .encrypt_block(&draft, current_block, &block_data)?;

                tracing::trace!(
                    block = current_block,
                    plain_size = n,
                    encrypted_size = encrypted_block.encrypted_data.len(),
                    "Block encrypted, sending to upload queue"
                );

                // Send to upload queue (will block if buffer is full - backpressure)
                if tx.send((encrypted_block, block_size)).await.is_err() {
                    // Receiver dropped, upload failed
                    return Err(anyhow::anyhow!("Upload task terminated unexpectedly"));
                }

                current_block += 1;
            }

            // Finalize the SHA1 hash
            let sha1_final: [u8; 20] = sha1::Digest::finalize(sha1_hasher).into();

            tracing::debug!(blocks_encrypted = current_block - 1, "Producer finished");
            Ok::<(i32, [u8; 20]), anyhow::Error>((current_block - 1, sha1_final))
        });

        // Consumer: receives encrypted blocks and uploads them in parallel
        let mut upload_futures: FuturesUnordered<
            tokio::task::JoinHandle<anyhow::Result<(i32, BlockUploadResult, i32)>>,
        > = FuturesUnordered::new();
        let mut producer_done = false;

        loop {
            // Try to receive more encrypted blocks while we have upload capacity
            while !producer_done && upload_futures.len() < Self::MAX_CONCURRENT_UPLOADS {
                crate::node::download::wait_while_paused(&mut pause_rx).await;
                match rx.try_recv() {
                    Ok((encrypted_block, block_size)) => {
                        upload_futures.push(spawn_block_upload(
                            self.client.clone(),
                            self.draft.clone(),
                            encrypted_block,
                            block_size,
                            progress.clone(),
                        ));
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        // No blocks ready, break to wait for uploads or new blocks
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        producer_done = true;
                        break;
                    }
                }
            }

            // If we have no upload capacity or no blocks ready, wait for an upload to complete
            // or for the channel to have data
            if upload_futures.is_empty() && producer_done {
                // All done
                break;
            }

            if upload_futures.is_empty() {
                // No uploads in progress, wait for producer to send a block
                match rx.recv().await {
                    Some((encrypted_block, block_size)) => {
                        upload_futures.push(spawn_block_upload(
                            self.client.clone(),
                            self.draft.clone(),
                            encrypted_block,
                            block_size,
                            progress.clone(),
                        ));
                    }
                    None => {
                        producer_done = true;
                    }
                }
            } else {
                // Wait for either an upload to complete or a new block to be ready
                tokio::select! {
                    Some(result) = upload_futures.next() => {
                        let (block_num, upload_result, size) = result??;
                        block_results.lock().await.push((block_num, upload_result, size));
                        (self.release_blocks_action)(1);
                    }
                    block_opt = rx.recv(), if !producer_done && upload_futures.len() < Self::MAX_CONCURRENT_UPLOADS => {
                        match block_opt {
                            Some((encrypted_block, block_size)) => {
                                upload_futures.push(spawn_block_upload(
                                    self.client.clone(),
                                    self.draft.clone(),
                                    encrypted_block,
                                    block_size,
                                    progress.clone(),
                                ));
                            }
                            None => {
                                producer_done = true;
                            }
                        }
                    }
                }
            }
        }

        // Wait for producer to finish and check for errors
        let (blocks_encrypted, sha1_hash) = producer.await??;

        // Store the precomputed SHA1 hash from the producer
        self.precomputed_sha1 = Some(sha1_hash);

        // Sort results by block number and collect digests/sizes in order
        let mut results = block_results.lock().await;
        results.sort_by_key(|(block_num, _, _)| *block_num);

        tracing::debug!(
            "Collected {} block upload results, block numbers: {:?}",
            results.len(),
            results.iter().map(|(n, _, _)| *n).collect::<Vec<_>>()
        );

        for (_, result, size) in results.iter() {
            self.digests.extend_from_slice(&result.sha256_digest);
            self.block_sizes.push(*size);
            self.total_written += *size as i64;
        }
        self.block_number = blocks_encrypted + 1;

        tracing::debug!(
            blocks = blocks_encrypted,
            total_written = self.total_written,
            "Pipelined write complete"
        );

        Ok(())
    }
    pub async fn upload_thumbnails(
        &mut self,
        thumbnails: Vec<crate::node::thumbnail::Thumbnail>,
    ) -> anyhow::Result<()> {
        if thumbnails.is_empty() {
            return Ok(());
        }

        let mut requests = Vec::new();
        let mut encrypted_thumbnails = Vec::new();

        let sk = self.draft.content_key.to_rpgp_sk()?;

        for thumb in thumbnails {
            let encryptor = Encryptor::default()
                .at_date(crate::server_time::check_now())
                .with_session_key(sk.clone())
                .with_signing_key(&self.draft.signing_key.0);

            let result = encryptor.encrypt(&thumb.content)?;
            let encrypted_data = result.to_bytes()?;

            let mut hasher = Sha256::new();
            hasher.update(&encrypted_data);
            let hash_digest = hasher.finalize().to_vec();

            requests.push(ThumbnailCreationRequest {
                size: encrypted_data.len() as i32,
                r#type: thumb.r#type,
                hash_digest: hash_digest.clone(),
            });
            encrypted_thumbnails.push((thumb.r#type, encrypted_data, hash_digest));
        }

        let request = BlockUploadPreparationRequest {
            address_id: crate::account::AddressId::new(
                self.draft.membership_address.address_id.clone(),
            ),
            volume_id: self.draft.uid.node_uid.volume_id.clone(),
            link_id: self.draft.uid.node_uid.link_id.clone(),
            revision_id: self.draft.uid.revision_id.clone(),
            blocks: vec![],
            thumbnails: requests,
        };

        let response = self
            .client
            .api()
            .files()
            .prepare_block_upload(request)
            .await?;

        if response.thumbnail_upload_targets.len() != encrypted_thumbnails.len() {
            anyhow::bail!("Mismatch in received thumbnail upload targets");
        }

        for (target, (thumb_type, encrypted_data, hash_digest)) in response
            .thumbnail_upload_targets
            .iter()
            .zip(encrypted_thumbnails)
        {
            tracing::info!(
                thumbnail_type = ?thumb_type,
                url = %target.base.bare_url,
                "Uploading thumbnail blob"
            );

            self.client
                .api()
                .storage()
                .upload_blob(
                    &target.base.bare_url,
                    &target.base.token,
                    bytes::Bytes::from(encrypted_data),
                )
                .await?;

            self.thumbnail_digests.extend_from_slice(&hash_digest);
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn commit(&mut self) -> anyhow::Result<()> {
        use sha1::Digest;

        tracing::info!(
            total_written = self.total_written,
            blocks = self.block_sizes.len(),
            thumbnail_digests = self.thumbnail_digests.len(),
            content_digests_bytes = self.digests.len(),
            block_sizes = ?self.block_sizes,
            "Committing revision"
        );
        let mut manifest = Vec::with_capacity(self.thumbnail_digests.len() + self.digests.len());
        manifest.extend_from_slice(&self.thumbnail_digests);
        manifest.extend_from_slice(&self.digests);
        let manifest_signature = self.draft.signing_key.sign_detached_armored(&manifest)?;

        // Use precomputed SHA1 from pipelined write, or fall back to hasher
        let sha1_digest = if let Some(hash) = self.precomputed_sha1 {
            hash.to_vec()
        } else {
            self.sha1_hasher.clone().finalize().to_vec()
        };

        if self.total_written != self.expected_size {
            self.client
                .telemetry()
                .record_metric(
                    "blockVerificationError".into(),
                    Some(b"content size mismatch".to_vec()),
                )
                .await;
            return Err(crate::error::ContentSizeMismatchIntegrityException {
                uploaded: self.total_written,
                expected: self.expected_size,
            }
            .into());
        }

        let checksum_verified = if let Some(expected) = &self.expected_sha1 {
            if expected != &sha1_digest {
                self.client
                    .telemetry()
                    .record_metric(
                        "blockVerificationError".into(),
                        Some(b"checksum mismatch".to_vec()),
                    )
                    .await;
                return Err(crate::error::ChecksumMismatchIntegrityException {
                    actual: sha1_digest,
                    expected: expected.clone(),
                }
                .into());
            }
            true
        } else {
            false
        };
        let mut additional_metadata = std::collections::HashMap::new();
        if let Some(meta) = &self.additional_metadata {
            for prop in meta {
                additional_metadata.insert(
                    prop.key.clone(),
                    serde_json::Value::String(prop.value.clone()),
                );
            }
        }

        let xattr = crate::api::attr::ExtendedAttributes {
            common: Some(crate::api::attr::CommonExtendedAttributes {
                size: Some(self.total_written),
                modification_time: self.last_modification_time,
                block_sizes: Some(self.block_sizes.clone()),
                digests: Some(crate::api::file::FileContentDigestsDto {
                    sha1: Some(sha1_digest.clone()),
                }),
            }),
            media: self.media_info.clone(),
            additional_metadata,
        };

        let xattr_json = serde_json::to_vec(&xattr)?;

        let xattr_encryptor = Encryptor::default()
            .at_date(crate::server_time::check_now())
            .with_encryption_key(self.draft.file_key.0.as_public_key())
            .with_signing_key(&self.draft.signing_key.0);
        let xattr_result = xattr_encryptor.encrypt(&xattr_json)?;
        let encrypted_xattr = PgpArmoredMessage(String::from_utf8(xattr_result.armor()?)?);

        let request = crate::api::revision::RevisionUpdateRequest {
            manifest_signature,
            signature_email_address: self.draft.membership_address.email_address.clone(),
            checksum_verified,
            extended_attributes: Some(encrypted_xattr),
            photos_attributes: self
                .photos
                .as_ref()
                .map(|photos| photos.attributes(&sha1_digest))
                .transpose()?,
        };

        seal_revision(self.client.api().files().as_ref(), &self.draft.uid, request).await?;

        tracing::info!(
            revision_id = %self.draft.uid.revision_id.raw(),
            "Revision committed successfully"
        );

        Ok(())
    }
}

/// "Incompatible state": the revision is no longer a draft.
const CODE_INCOMPATIBLE_STATE: u32 = 2511;

/// Commits the revision draft `uid` with `request`.
///
/// A commit answered 2511 succeeds when the revision is already active or
/// obsolete, as C# does (`RegularRevisionUploadBackend.CommitAsync`): an
/// earlier attempt went through and its answer was lost, so a retry of the
/// same commit finds the revision sealed. A draft, or a revision that cannot
/// be read, keeps the 2511 error.
async fn seal_revision(
    files: &dyn crate::api::file::FilesApiClient,
    uid: &RevisionUid,
    request: crate::api::revision::RevisionUpdateRequest,
) -> anyhow::Result<()> {
    let error = match files
        .update_revision(
            uid.node_uid.volume_id.clone(),
            uid.node_uid.link_id.clone(),
            uid.revision_id.clone(),
            request,
        )
        .await
        .and_then(|response| response.to_result())
    {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    if crate::error::ApiError::find(&error).and_then(|api| api.code)
        != Some(CODE_INCOMPATIBLE_STATE)
    {
        return Err(error);
    }
    let state = files
        .get_revision(
            uid.node_uid.volume_id.clone(),
            uid.node_uid.link_id.clone(),
            uid.revision_id.clone(),
            None,
            None,
            true,
        )
        .await
        .and_then(|response| {
            response.base.to_result()?;
            Ok(response.revision.revision.state)
        });
    match state {
        Ok(RevisionState::Active | RevisionState::Superseded) => {
            tracing::info!(
                revision_id = %uid.revision_id.raw(),
                "Revision already sealed; the commit is complete"
            );
            Ok(())
        }
        Ok(RevisionState::Draft) => Err(error),
        Err(read_error) => {
            tracing::debug!(error = %read_error, "Failed to read the revision after 2511");
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{UploadProgress, ensure_contiguous_blocks, next_block_page_start};
    use std::sync::Arc;

    #[test]
    fn upload_progress_counts_partly_sent_blocks() {
        let reports = Arc::new(std::sync::Mutex::new(Vec::new()));
        let progress = UploadProgress {
            done: std::sync::atomic::AtomicI64::new(0),
            in_flight: std::sync::Mutex::new(std::collections::HashMap::new()),
            expected: 300,
            on_progress: {
                let reports = reports.clone();
                Arc::new(move |done, total| reports.lock().unwrap().push((done, total)))
            },
        };
        // Two 150-byte blocks whose encrypted forms are 200 bytes.
        progress.block_sent(1, 150, 100, 200);
        progress.block_sent(2, 150, 40, 200);
        progress.block_done(1, 150);
        progress.block_sent(2, 150, 400, 200);
        progress.block_done(2, 150);
        assert_eq!(
            *reports.lock().unwrap(),
            [(75, 300), (105, 300), (180, 300), (300, 300), (300, 300)]
        );
    }
    use crate::api::block::BlockDto;

    fn blocks(indexes: std::ops::RangeInclusive<i32>) -> Vec<BlockDto> {
        indexes
            .map(|index| serde_json::from_value(serde_json::json!({ "Index": index })).unwrap())
            .collect()
    }

    #[test]
    fn block_listing_keeps_paging_past_the_first_full_page() {
        // A 48 MB file has 12 blocks: one full page of 10, then a page of 2.
        let first = blocks(1..=10);
        assert_eq!(next_block_page_start(&first, 10, 10), Some(11));
        let all = blocks(1..=12);
        assert_eq!(next_block_page_start(&all, 2, 10), None);
        assert_eq!(next_block_page_start(&[], 0, 10), None);
    }

    #[test]
    fn block_listing_with_gaps_is_rejected() {
        assert!(ensure_contiguous_blocks(&blocks(1..=12)).is_ok());
        let mut gap = blocks(1..=10);
        gap.extend(blocks(12..=12));
        assert!(ensure_contiguous_blocks(&gap).is_err());
    }
}

#[cfg(test)]
mod seal_tests {
    use super::{RevisionUid, seal_revision};
    use crate::api::file::DefaultFilesApiClient;
    use crate::api::revision::RevisionUpdateRequest;
    use crate::error::ApiError;
    use crate::node::NodeUid;
    use crate::pgp::PgpArmoredSignature;
    use crate::revision::RevisionId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const COMMIT: &str = "PUT /drive/v2/volumes/volume/files/link/revisions/revision HTTP/1.1";
    const READ: &str =
        "GET /drive/v2/volumes/volume/files/link/revisions/revision?NoBlockUrls=1 HTTP/1.1";

    fn revision(state: u32) -> String {
        serde_json::json!({
            "Code": 1000,
            "Revision": {
                "ID": "revision",
                "CreateTime": 1_700_000_000,
                "Size": 3,
                "State": state,
                "Blocks": [],
            },
        })
        .to_string()
    }

    fn not_in_draft() -> String {
        r#"{"Code":2511,"Error":"Revision is not in draft state"}"#.into()
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0, "request ended early");
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]).to_string();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + length {
                    return headers.lines().next().unwrap().to_owned();
                }
            }
        }
    }

    /// Commits against a server that gives `answers` (HTTP status, body) in
    /// turn; returns the result and the request lines it received.
    async fn commit_with(answers: Vec<(u16, String)>) -> (anyhow::Result<()>, Vec<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = reqwest::Url::parse(&format!("http://{}/drive/", listener.local_addr().unwrap()))
            .unwrap();
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in answers {
                let accepted =
                    tokio::time::timeout(std::time::Duration::from_millis(500), listener.accept())
                        .await;
                let Ok(accepted) = accepted else { break };
                let (mut stream, _) = accepted.unwrap();
                requests.push(read_request(&mut stream).await);
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        let files = DefaultFilesApiClient::new(
            reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build(),
            url,
            None,
        );
        let uid = RevisionUid::new(
            NodeUid::from_parts("volume", "link"),
            RevisionId::new("revision".into()),
        );
        let request = RevisionUpdateRequest {
            manifest_signature: PgpArmoredSignature("signature".into()),
            signature_email_address: "user@example.test".into(),
            checksum_verified: true,
            extended_attributes: None,
            photos_attributes: None,
        };
        let result = seal_revision(&files, &uid, request).await;
        (result, server.await.unwrap())
    }

    fn code(result: anyhow::Result<()>) -> Option<u32> {
        ApiError::find(&result.unwrap_err()).and_then(|error| error.code)
    }

    #[tokio::test]
    async fn not_in_draft_succeeds_when_the_revision_is_active_or_obsolete() {
        for state in [1, 2] {
            let (result, requests) =
                commit_with(vec![(422, not_in_draft()), (200, revision(state))]).await;
            result.unwrap();
            assert_eq!(requests, [COMMIT, READ]);
        }
    }

    #[tokio::test]
    async fn not_in_draft_in_a_2xx_answer_is_checked_too() {
        let (result, requests) = commit_with(vec![(200, not_in_draft()), (200, revision(1))]).await;
        result.unwrap();
        assert_eq!(requests, [COMMIT, READ]);
    }

    #[tokio::test]
    async fn not_in_draft_fails_when_the_revision_is_a_draft_or_unreadable() {
        let (result, requests) = commit_with(vec![(422, not_in_draft()), (200, revision(0))]).await;
        assert_eq!(code(result), Some(2511));
        assert_eq!(requests, [COMMIT, READ]);

        let (result, requests) = commit_with(vec![
            (422, not_in_draft()),
            (422, r#"{"Code":2501,"Error":"gone"}"#.into()),
        ])
        .await;
        assert_eq!(code(result), Some(2511));
        assert_eq!(requests, [COMMIT, READ]);
    }

    #[tokio::test]
    async fn other_answers_need_no_read() {
        let (result, requests) =
            commit_with(vec![(200, r#"{"Code":1000}"#.into()), (200, revision(1))]).await;
        result.unwrap();
        assert_eq!(requests, [COMMIT]);

        let (result, requests) = commit_with(vec![
            (422, r#"{"Code":2500,"Error":"exists"}"#.into()),
            (200, revision(1)),
        ])
        .await;
        assert_eq!(code(result), Some(2500));
        assert_eq!(requests, [COMMIT]);

        let (result, requests) = commit_with(vec![
            (200, r#"{"Code":2000,"Error":"invalid"}"#.into()),
            (200, revision(1)),
        ])
        .await;
        assert_eq!(code(result), Some(2000));
        assert_eq!(requests, [COMMIT]);
    }
}

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
    /// Plaintext block sizes declared by the uploader, in block order; `None` if the
    /// extended attributes are absent, unreadable, or do not list them.
    #[serde(default)]
    pub claimed_block_sizes: Option<Vec<i32>>,
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

/// Values the uploader claimed in a revision's encrypted extended attributes (XAttr).
#[derive(Debug, Clone, Default)]
pub(crate) struct ClaimedRevisionAttributes {
    pub size: Option<i64>,
    pub modification_time: Option<DateTime<Utc>>,
    pub sha1: Option<Vec<u8>>,
    pub block_sizes: Option<Vec<i32>>,
    pub additional_metadata: Option<Vec<AdditionalMetadataProperty>>,
}

impl ClaimedRevisionAttributes {
    /// Maps parsed extended attributes to claimed revision values. Top-level keys other
    /// than `Common` and `Media` (the flattened `additional_metadata` map) become
    /// additional metadata, sorted by key; string values are kept verbatim and other
    /// values as JSON text. `Media` stays out because the uploader writes it from its
    /// own typed field, so feeding it back as additional metadata would duplicate it.
    pub(crate) fn from_extended_attributes(xattr: crate::api::attr::ExtendedAttributes) -> Self {
        let crate::api::attr::ExtendedAttributes {
            common,
            additional_metadata,
            ..
        } = xattr;
        let mut additional: Vec<AdditionalMetadataProperty> = additional_metadata
            .into_iter()
            .map(|(key, value)| AdditionalMetadataProperty {
                key,
                value: match value {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                },
            })
            .collect();
        additional.sort_by(|a, b| a.key.cmp(&b.key));

        let (size, modification_time, block_sizes, sha1) = match common {
            Some(c) => (
                c.size,
                c.modification_time,
                c.block_sizes.filter(|s| !s.is_empty()),
                c.digests.and_then(|d| d.sha1),
            ),
            None => (None, None, None, None),
        };

        Self {
            size,
            modification_time,
            sha1,
            block_sizes,
            additional_metadata: (!additional.is_empty()).then_some(additional),
        }
    }

    /// Decrypts a revision XAttr with the node key, verifies its signature against the
    /// content authorship claim, and parses it. A failed signature verification is
    /// logged and the claimed values are still returned, matching the official SDKs.
    pub(crate) fn decrypt(
        message: &PgpArmoredMessage,
        node_key: &crate::pgp::PgpPrivateKey,
        authorship_claim: &crate::node::authorship::AuthorshipClaim,
    ) -> anyhow::Result<Self> {
        let (bytes, _, verification_failure) = crate::node::crypto::NodeCrypto::decrypt_message(
            message,
            None,
            [node_key],
            authorship_claim,
        )
        .map_err(|e| anyhow::anyhow!("failed to decrypt revision extended attributes: {e}"))?;
        if verification_failure.is_some() {
            tracing::warn!(
                author = ?authorship_claim.author.email_address,
                "revision extended attributes signature verification failed"
            );
        }
        let xattr: crate::api::attr::ExtendedAttributes = serde_json::from_slice(&bytes)
            .context("failed to parse revision extended attributes")?;
        Ok(Self::from_extended_attributes(xattr))
    }

    /// Like [`Self::decrypt`], but returns `None` when the XAttr is absent, and logs a
    /// warning and returns `None` when it cannot be decrypted or parsed.
    pub(crate) fn decrypt_optional(
        message: Option<&PgpArmoredMessage>,
        node_key: &crate::pgp::PgpPrivateKey,
        authorship_claim: &crate::node::authorship::AuthorshipClaim,
        revision_uid: &RevisionUid,
    ) -> Option<Self> {
        let message = message?;
        match Self::decrypt(message, node_key, authorship_claim) {
            Ok(attributes) => Some(attributes),
            Err(error) => {
                tracing::warn!(
                    revision = %revision_uid,
                    error = %format!("{error:#}"),
                    "ignoring unreadable revision extended attributes"
                );
                None
            }
        }
    }
}

impl Revision {
    /// Builds the active revision of a decoded file node. Claimed values come from the
    /// revision XAttr; when it is absent or unreadable, the size falls back to the
    /// encrypted size and the modification time to the revision creation time.
    pub(crate) fn from_active_revision_dto(
        node_uid: &NodeUid,
        dto: Option<&crate::api::revision::ActiveRevisionDto>,
        node_key: &crate::pgp::PgpPrivateKey,
        authorship_claim: &crate::node::authorship::AuthorshipClaim,
    ) -> Self {
        let uid = RevisionUid::new(
            node_uid.clone(),
            dto.map(|r| r.id.clone()).unwrap_or_default(),
        );
        let creation_time = dto.map(|r| r.creation_time).unwrap_or_else(Utc::now);
        let size_on_cloud_storage = dto.map(|r| r.storage_quota_consumption).unwrap_or(0);
        let claimed = dto
            .and_then(|r| {
                ClaimedRevisionAttributes::decrypt_optional(
                    r.extended_attributes.as_ref(),
                    node_key,
                    authorship_claim,
                    &uid,
                )
            })
            .unwrap_or_default();
        let thumbnails = dto
            .map(|r| {
                #[allow(deprecated)]
                r.thumbnails
                    .iter()
                    .map(|t| ThumbnailHeader {
                        id: t.id.clone(),
                        r#type: t.r#type as i32,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self {
            uid,
            creation_time,
            size_on_cloud_storage,
            claimed_size: Some(claimed.size.unwrap_or(size_on_cloud_storage)),
            claimed_digests: FileContentDigests { sha1: claimed.sha1 },
            claimed_modification_time: Some(claimed.modification_time.unwrap_or(creation_time)),
            thumbnails,
            additional_claimed_metadata: claimed.additional_metadata,
            content_author: Some(authorship_claim.to_potential_author()),
            claimed_block_sizes: claimed.block_sizes,
        }
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
        let revision_response = client
            .api()
            .files()
            .get_revision(
                revision_uid.node_uid.volume_id.clone(),
                revision_uid.node_uid.link_id.clone(),
                revision_uid.revision_id.clone(),
                Some(crate::node::download::MIN_BLOCK_INDEX),
                Some(crate::node::download::DEFAULT_BLOCK_PAGE_SIZE),
                false,
            )
            .await
            .context("Failed to get revision from API")?;

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
        let uploaded_bytes = Arc::new(std::sync::atomic::AtomicI64::new(0));
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
                        let block_number = encrypted_block.block_number;
                        let plain_size = encrypted_block.plain_size;

                        // Spawn upload task
                        let client = self.client.clone();
                        let draft = self.draft.clone();
                        let on_progress = on_progress.clone();
                        let expected_size = self.expected_size;
                        let uploaded_bytes = uploaded_bytes.clone();

                        let handle = tokio::spawn(async move {
                            let result = client
                                .block_uploader()
                                .upload_encrypted_block(&client, &draft, encrypted_block)
                                .await?;

                            // Update progress
                            let new_total = uploaded_bytes
                                .fetch_add(plain_size as i64, std::sync::atomic::Ordering::SeqCst)
                                + plain_size as i64;
                            on_progress(new_total, expected_size);

                            Ok((block_number, result, block_size))
                        });

                        upload_futures.push(handle);
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
                        let block_number = encrypted_block.block_number;
                        let plain_size = encrypted_block.plain_size;

                        let client = self.client.clone();
                        let draft = self.draft.clone();
                        let on_progress = on_progress.clone();
                        let expected_size = self.expected_size;
                        let uploaded_bytes = uploaded_bytes.clone();

                        let handle = tokio::spawn(async move {
                            let result = client
                                .block_uploader()
                                .upload_encrypted_block(&client, &draft, encrypted_block)
                                .await?;
                            let new_total = uploaded_bytes
                                .fetch_add(plain_size as i64, std::sync::atomic::Ordering::SeqCst)
                                + plain_size as i64;
                            on_progress(new_total, expected_size);
                            Ok((block_number, result, block_size))
                        });
                        upload_futures.push(handle);
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
                                let block_number = encrypted_block.block_number;
                                let plain_size = encrypted_block.plain_size;

                                let client = self.client.clone();
                                let draft = self.draft.clone();
                                let on_progress = on_progress.clone();
                                let expected_size = self.expected_size;
                                let uploaded_bytes = uploaded_bytes.clone();

                                let handle = tokio::spawn(async move {
                                    let result = client
                                        .block_uploader()
                                        .upload_encrypted_block(&client, &draft, encrypted_block)
                                        .await?;
                                    let new_total = uploaded_bytes.fetch_add(plain_size as i64, std::sync::atomic::Ordering::SeqCst)
                                        + plain_size as i64;
                                    on_progress(new_total, expected_size);
                                    Ok((block_number, result, block_size))
                                });
                                upload_futures.push(handle);
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

        self.client
            .api()
            .files()
            .update_revision(
                self.draft.uid.node_uid.volume_id.clone(),
                self.draft.uid.node_uid.link_id.clone(),
                self.draft.uid.revision_id.clone(),
                request,
            )
            .await?;

        tracing::info!(
            revision_id = %self.draft.uid.revision_id.raw(),
            "Revision committed successfully"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoGenerator;
    use crate::node::authorship::AuthorshipClaim;
    use crate::pgp::PgpPrivateKey;
    use chrono::TimeZone;

    /// Encrypts and signs extended attributes the way `RevisionWriter` does on commit.
    fn encrypt_like_uploader(
        xattr: &crate::api::attr::ExtendedAttributes,
        node_key: &PgpPrivateKey,
        signing_key: &PgpPrivateKey,
    ) -> PgpArmoredMessage {
        let xattr_json = serde_json::to_vec(xattr).unwrap();
        let result = Encryptor::default()
            .with_encryption_key(node_key.0.as_public_key())
            .with_signing_key(&signing_key.0)
            .encrypt(&xattr_json)
            .unwrap();
        PgpArmoredMessage(String::from_utf8(result.armor().unwrap()).unwrap())
    }

    fn uploader_xattr(mtime: DateTime<Utc>) -> crate::api::attr::ExtendedAttributes {
        let mut additional_metadata = std::collections::HashMap::new();
        for prop in [AdditionalMetadataProperty {
            key: "pdmount.mode".into(),
            value: "33188".into(),
        }] {
            additional_metadata.insert(prop.key, serde_json::Value::String(prop.value));
        }
        crate::api::attr::ExtendedAttributes {
            common: Some(crate::api::attr::CommonExtendedAttributes {
                size: Some(5_000_123),
                modification_time: Some(mtime),
                block_sizes: Some(vec![4_194_304, 805_819]),
                digests: Some(crate::api::file::FileContentDigestsDto {
                    sha1: Some(vec![0xde, 0xad, 0xbe, 0xef]),
                }),
            }),
            media: None,
            additional_metadata,
        }
    }

    fn active_revision_dto(
        xattr: Option<&PgpArmoredMessage>,
    ) -> crate::api::revision::ActiveRevisionDto {
        serde_json::from_value(serde_json::json!({
            "RevisionID": "revision",
            "CreateTime": 1_700_000_000,
            "EncryptedSize": 5_100_000,
            "Thumbnails": [],
            "XAttr": xattr.map(|m| m.0.clone()),
            "SignatureEmail": "member@example.test",
        }))
        .unwrap()
    }

    fn claim_for(signer: &PgpPrivateKey) -> AuthorshipClaim {
        AuthorshipClaim {
            keys: vec![signer.0.as_public_key().clone()],
            author: Author {
                email_address: Some("member@example.test".into()),
            },
            key_retrieval_error_message: None,
        }
    }

    #[test]
    fn active_revision_takes_claimed_values_from_uploader_xattr() {
        let node_key = CryptoGenerator::generate_private_key().unwrap();
        let address_key = CryptoGenerator::generate_private_key().unwrap();
        let mtime = Utc.timestamp_opt(1_650_000_000, 0).unwrap();
        let message = encrypt_like_uploader(&uploader_xattr(mtime), &node_key, &address_key);
        let dto = active_revision_dto(Some(&message));
        let node_uid = NodeUid::from_parts("volume", "node");

        let revision = Revision::from_active_revision_dto(
            &node_uid,
            Some(&dto),
            &node_key,
            &claim_for(&address_key),
        );

        assert_eq!(revision.uid.to_string(), "volume~node~revision");
        assert_eq!(revision.size_on_cloud_storage, 5_100_000);
        assert_eq!(revision.claimed_size, Some(5_000_123));
        assert_eq!(revision.claimed_modification_time, Some(mtime));
        assert_eq!(
            revision.claimed_digests.sha1,
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert_eq!(revision.claimed_block_sizes, Some(vec![4_194_304, 805_819]));
        let metadata = revision.additional_claimed_metadata.unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].key, "pdmount.mode");
        assert_eq!(metadata[0].value, "33188");
    }

    #[test]
    fn active_revision_without_xattr_keeps_fallback_values() {
        let node_key = CryptoGenerator::generate_private_key().unwrap();
        let dto = active_revision_dto(None);
        let revision = Revision::from_active_revision_dto(
            &NodeUid::from_parts("volume", "node"),
            Some(&dto),
            &node_key,
            &claim_for(&node_key),
        );

        assert_eq!(revision.claimed_size, Some(5_100_000));
        assert_eq!(revision.claimed_modification_time, Some(dto.creation_time));
        assert_eq!(revision.claimed_digests.sha1, None);
        assert_eq!(revision.claimed_block_sizes, None);
        assert!(revision.additional_claimed_metadata.is_none());
    }

    #[test]
    fn unreadable_xattr_keeps_fallback_values_instead_of_failing() {
        let node_key = CryptoGenerator::generate_private_key().unwrap();
        let other_key = CryptoGenerator::generate_private_key().unwrap();
        let mtime = Utc.timestamp_opt(1_650_000_000, 0).unwrap();
        // Encrypted to a different key: decryption with the node key fails.
        let wrong_key = encrypt_like_uploader(&uploader_xattr(mtime), &other_key, &other_key);
        let garbage = PgpArmoredMessage("invalid".into());
        for message in [wrong_key, garbage] {
            let dto = active_revision_dto(Some(&message));
            let revision = Revision::from_active_revision_dto(
                &NodeUid::from_parts("volume", "node"),
                Some(&dto),
                &node_key,
                &claim_for(&node_key),
            );
            assert_eq!(revision.claimed_size, Some(5_100_000));
            assert_eq!(revision.claimed_modification_time, Some(dto.creation_time));
            assert_eq!(revision.claimed_block_sizes, None);
        }
    }

    #[test]
    fn signature_mismatch_still_returns_claimed_values() {
        let node_key = CryptoGenerator::generate_private_key().unwrap();
        let signer = CryptoGenerator::generate_private_key().unwrap();
        let unrelated = CryptoGenerator::generate_private_key().unwrap();
        let mtime = Utc.timestamp_opt(1_650_000_000, 0).unwrap();
        let message = encrypt_like_uploader(&uploader_xattr(mtime), &node_key, &signer);

        let claimed =
            ClaimedRevisionAttributes::decrypt(&message, &node_key, &claim_for(&unrelated))
                .unwrap();

        assert_eq!(claimed.size, Some(5_000_123));
        assert_eq!(claimed.modification_time, Some(mtime));
    }

    #[test]
    fn non_string_additional_metadata_is_kept_as_json_text() {
        let xattr: crate::api::attr::ExtendedAttributes =
            serde_json::from_value(serde_json::json!({
                "Common": {"Size": 1, "BlockSizes": []},
                "Media": {"Width": 10},
                "Location": {"Latitude": 1.5},
                "pdmount.uid": "1000"
            }))
            .unwrap();
        let claimed = ClaimedRevisionAttributes::from_extended_attributes(xattr);
        assert_eq!(claimed.size, Some(1));
        assert_eq!(claimed.block_sizes, None);
        let metadata = claimed.additional_metadata.unwrap();
        let pairs: Vec<_> = metadata
            .iter()
            .map(|p| (p.key.as_str(), p.value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [("Location", r#"{"Latitude":1.5}"#), ("pdmount.uid", "1000")]
        );
    }
}

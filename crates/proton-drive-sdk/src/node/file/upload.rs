use crate::client::ProtonDriveClient;
use crate::meta::AdditionalMetadataProperty;
use crate::node::NodeUid;
use crate::node::download::ControllerState;
use crate::node::draft::RevisionDraftProvider;
use crate::node::photo::{PhotoUploadContext, PhotosFileUploadMetadata};
use crate::node::revision::{RevisionOperations, RevisionUid};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::sync::watch;

/// The feature flag that enables small uploads (C# `FeatureFlags.DriveSmallFileUpload`).
/// The uploader asks the client's `FeatureFlagProvider`, which the application supplies;
/// the default provider has every flag off, as in both official SDKs.
pub const DRIVE_SMALL_FILE_UPLOAD: &str = "DriveSmallFileUpload";

/// A file and its thumbnails, plus 10 % for encryption, must stay under this to be
/// uploaded in one request (C# `RevisionUploadBackendFactory`, JS `SMALL_FILE_SIZE_LIMIT`).
const SMALL_UPLOAD_SIZE_LIMIT: i64 = 128 * 1024;
const SMALL_UPLOAD_ENCRYPTION_OVERHEAD: f64 = 1.1;

/// Whether a failed small upload may go on as a regular one: only a clean conflict, where
/// the server committed nothing (C# `FileUploader.IsSmallUploadFallbackException`). The
/// draft path then removes a stale draft of this client, or fails with the same error.
/// Any other failure after the request was sent is returned: the small upload creates and
/// commits at once and is not idempotent.
fn is_small_upload_fallback(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<crate::node::draft::NodeWithSameNameExistsError>()
            || cause.is::<crate::node::draft::RevisionDraftConflictError>()
    })
}

#[derive(serde::Serialize)]
struct UploadPerformanceTelemetry {
    route: &'static str,
    file_size_class: &'static str,
    block_count_class: &'static str,
    total_time_ms: u128,
    active_time_ms: u128,
    throughput_kib_per_second: u64,
    validation_outcome: &'static str,
}

fn upload_classes(size: i64, blocks: i32) -> (&'static str, &'static str) {
    let size_class = if blocks > 1 {
        "multi"
    } else if size < 128 * 1024 {
        "small"
    } else {
        "single"
    };
    let block_class = if blocks > 4 {
        "many"
    } else if blocks > 1 {
        "few"
    } else {
        "single"
    };
    (size_class, block_class)
}

/// Identifies the node and the revision that a completed upload committed.
///
/// For a new file, `node_uid` is the newly created file node; for a new revision of an
/// existing file, it is that file's node. `revision_uid` is always the revision created
/// by this upload, so a sync client can recognise its own revisions in the event stream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UploadResult {
    pub node_uid: NodeUid,
    pub revision_uid: RevisionUid,
}

impl UploadResult {
    pub(crate) fn from_revision_uid(revision_uid: RevisionUid) -> Self {
        Self {
            node_uid: revision_uid.node_uid.clone(),
            revision_uid,
        }
    }
}

pub struct UploadController {
    state_tx: watch::Sender<ControllerState>,
    sdk_events: Arc<crate::events::SdkEvents>,
}

impl UploadController {
    pub fn is_paused(&self) -> bool {
        *self.state_tx.borrow() == ControllerState::Paused
    }

    pub fn pause(&self) {
        self.sdk_events.transfers_paused();
        let _ = self.state_tx.send(ControllerState::Paused);
    }

    pub fn resume(&self) {
        self.sdk_events.transfers_resumed();
        let _ = self.state_tx.send(ControllerState::Running);
    }
}

pub struct FileUploader {
    client: Arc<ProtonDriveClient>,
    revision_draft_provider: Box<dyn RevisionDraftProvider>,
    remaining_number_of_blocks: AtomicI32,
    size: i64,
    last_modification_time: Option<DateTime<Utc>>,
    additional_metadata: Option<Vec<AdditionalMetadataProperty>>,
    media_info: Option<crate::api::attr::MediaExtendedAttributes>,
    expected_sha1: Option<Vec<u8>>,
    photos: Option<PhotoUploadContext>,
    state_tx: watch::Sender<ControllerState>,
    request_started: Instant,
    /// Whether the upload went up in one request (`files/small`, `revisions/small`).
    used_small_upload: AtomicBool,
}

impl FileUploader {
    pub async fn create(
        client: &ProtonDriveClient,
        revision_draft_provider: Box<dyn RevisionDraftProvider>,
        size: i64,
        last_modification_time: Option<std::time::SystemTime>,
        additional_metadata: Option<Vec<AdditionalMetadataProperty>>,
        media_info: Option<crate::api::attr::MediaExtendedAttributes>,
    ) -> anyhow::Result<Self> {
        let request_started = Instant::now();
        let expected_number_of_blocks = (size + 4 * 1024 * 1024 - 1) / (4 * 1024 * 1024);
        client
            .revision_creation_semaphore()
            .acquire(expected_number_of_blocks as usize)
            .await?;

        let (state_tx, _) = watch::channel(ControllerState::Running);
        Ok(Self {
            client: Arc::new(client.clone()),
            revision_draft_provider,
            remaining_number_of_blocks: AtomicI32::new(expected_number_of_blocks as i32),
            size,
            last_modification_time: last_modification_time.map(DateTime::from),
            additional_metadata,
            media_info,
            expected_sha1: None,
            photos: None,
            state_tx,
            request_started,
            used_small_upload: AtomicBool::new(false),
        })
    }

    pub fn controller(&self) -> UploadController {
        UploadController {
            state_tx: self.state_tx.clone(),
            sdk_events: self.client.sdk_events().clone(),
        }
    }

    /// When set, commit fails with [`ChecksumMismatchIntegrityException`] if the uploaded content SHA-1 differs.
    pub fn set_expected_sha1(&mut self, sha1: Vec<u8>) {
        self.expected_sha1 = Some(sha1);
    }

    /// Sets the width, height and duration stored in the revision's extended attributes.
    pub fn set_media_info(&mut self, media_info: crate::api::attr::MediaExtendedAttributes) {
        self.media_info = Some(media_info);
    }

    pub(crate) fn set_photos_metadata(
        &mut self,
        metadata: PhotosFileUploadMetadata,
        hash_key: Vec<u8>,
    ) {
        self.photos = Some(PhotoUploadContext { metadata, hash_key });
    }

    /// Uploads the content and commits the revision, returning the node's UID.
    ///
    /// Use [`Self::upload_from_stream_with_revision`] to also obtain the committed revision's UID.
    pub async fn upload_from_stream(
        &self,
        content_stream: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        thumbnails: Vec<crate::node::thumbnail::Thumbnail>,
        on_progress: Box<dyn Fn(i64, i64) + Send + Sync>,
    ) -> anyhow::Result<NodeUid> {
        self.upload_from_stream_with_revision(content_stream, thumbnails, on_progress)
            .await
            .map(|result| result.node_uid)
    }

    /// Uploads the content and commits the revision, returning both the node's UID and the
    /// UID of the revision created by this upload.
    pub async fn upload_from_stream_with_revision(
        &self,
        content_stream: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        thumbnails: Vec<crate::node::thumbnail::Thumbnail>,
        on_progress: Box<dyn Fn(i64, i64) + Send + Sync>,
    ) -> anyhow::Result<UploadResult> {
        let active_started = Instant::now();
        let result = self
            .upload_from_stream_inner(content_stream, thumbnails, on_progress)
            .await;
        let active_time = active_started.elapsed();
        let blocks = ((self.size + 4 * 1024 * 1024 - 1) / (4 * 1024 * 1024)) as i32;
        let (file_size_class, block_count_class) = upload_classes(self.size, blocks);
        let validation_outcome = match (&result, self.expected_sha1.is_some()) {
            (Ok(_), true) => "verified",
            (Ok(_), false) => "not_requested",
            (Err(error), _)
                if error
                    .downcast_ref::<crate::error::ChecksumMismatchIntegrityException>()
                    .is_some()
                    || error
                        .downcast_ref::<crate::error::ContentSizeMismatchIntegrityException>()
                        .is_some() =>
            {
                "failed"
            }
            (Err(_), _) => "not_completed",
        };
        let payload = UploadPerformanceTelemetry {
            route: if self.used_small_upload.load(Ordering::Relaxed) {
                "small"
            } else {
                "block"
            },
            file_size_class,
            block_count_class,
            total_time_ms: self.request_started.elapsed().as_millis(),
            active_time_ms: active_time.as_millis(),
            throughput_kib_per_second: if active_time.is_zero() {
                0
            } else {
                (self.size.max(0) as f64 / 1024.0 / active_time.as_secs_f64()) as u64
            },
            validation_outcome,
        };
        if let Ok(payload) = serde_json::to_vec(&payload) {
            self.client
                .telemetry()
                .record_metric("uploadPerformance".into(), Some(payload))
                .await;
        }
        if let Err(e) = &result {
            self.client
                .telemetry()
                .record_metric("uploadError".into(), Some(e.to_string().into_bytes()))
                .await;
        }
        result
    }

    async fn upload_from_stream_inner(
        &self,
        mut content_stream: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        thumbnails: Vec<crate::node::thumbnail::Thumbnail>,
        on_progress: Box<dyn Fn(i64, i64) + Send + Sync>,
    ) -> anyhow::Result<UploadResult> {
        if self.small_upload_applies(&thumbnails).await {
            // At most one byte more than a small upload holds, so a stream longer than
            // announced is noticed; the bytes read go to the draft path when it is taken.
            let mut content = Vec::new();
            (&mut content_stream)
                .take(SMALL_UPLOAD_SIZE_LIMIT as u64 + 1)
                .read_to_end(&mut content)
                .await?;
            if content.len() as i64 == self.size {
                match self.upload_small(&content, &thumbnails).await {
                    Ok(Some(result)) => {
                        on_progress(self.size, self.size);
                        return Ok(result);
                    }
                    Ok(None) => {}
                    Err(error) if is_small_upload_fallback(&error) => {
                        tracing::warn!(
                            "Small upload refused, falling back to the regular upload: {error:#}"
                        );
                    }
                    Err(error) => return Err(error),
                }
            }
            content_stream = Box::new(std::io::Cursor::new(content).chain(content_stream));
        }

        let draft = self.revision_draft_provider.get_draft(self.size).await?;
        let draft_uid = draft.uid.clone();
        let mut writer = match self
            .write_draft(draft, content_stream, thumbnails, on_progress)
            .await
        {
            Ok(writer) => writer,
            Err(error) => {
                // An abandoned draft keeps its name taken, so a retry would get a renamed copy.
                if let Err(cleanup) = self.revision_draft_provider.delete_draft(&draft_uid).await {
                    tracing::warn!(error = %error, cleanup = %cleanup, "failed to delete upload draft");
                }
                return Err(error);
            }
        };
        // A failed commit may still have been applied, so its draft is never deleted.
        writer.commit().await?;
        Ok(UploadResult::from_revision_uid(draft_uid))
    }

    /// Whether this upload may go up in one request: not a photo, at most one block,
    /// under [`SMALL_UPLOAD_SIZE_LIMIT`] with its thumbnails and the encryption overhead,
    /// and [`DRIVE_SMALL_FILE_UPLOAD`] on (C# `RevisionUploadBackendFactory.CanUseSmallUploadAsync`).
    async fn small_upload_applies(&self, thumbnails: &[crate::node::thumbnail::Thumbnail]) -> bool {
        if self.photos.is_some()
            || self.size < 0
            || self.size > self.client.target_block_size() as i64
        {
            return false;
        }
        let thumbnails_size: i64 = thumbnails.iter().map(|t| t.content.len() as i64).sum();
        if (self.size + thumbnails_size) as f64 * SMALL_UPLOAD_ENCRYPTION_OVERHEAD
            >= SMALL_UPLOAD_SIZE_LIMIT as f64
        {
            return false;
        }
        match self
            .client
            .feature_flag_provider()
            .is_enabled(DRIVE_SMALL_FILE_UPLOAD.to_string())
            .await
        {
            Ok(enabled) => enabled,
            Err(error) => {
                tracing::warn!("Feature flag {DRIVE_SMALL_FILE_UPLOAD} unavailable: {error:#}");
                false
            }
        }
    }

    /// Uploads `content` and the thumbnails in one request, when the draft provider
    /// supports it: the file (or revision) is created and committed at once, with its
    /// block, thumbnails, manifest signature and extended attributes as a commit has them.
    /// `None` when the provider has no small upload to offer.
    async fn upload_small(
        &self,
        content: &[u8],
        thumbnails: &[crate::node::thumbnail::Thumbnail],
    ) -> anyhow::Result<Option<UploadResult>> {
        use crate::api::file::{
            SmallFileUploadMetadata, SmallRevisionUploadMetadata, SmallUploadContentMetadata,
            SmallUploadParts,
        };
        use crate::node::draft::SmallUploadTarget;
        use sha1::Digest;

        let Some(small) = self.revision_draft_provider.get_small_upload().await? else {
            return Ok(None);
        };
        let _file_permit = self.client.block_uploader().queue.start_file().await?;

        let sha1_digest = sha1::Sha1::digest(content).to_vec();
        let checksum_verified = match &self.expected_sha1 {
            Some(expected) if *expected != sha1_digest => {
                return Err(crate::error::ChecksumMismatchIntegrityException {
                    actual: sha1_digest,
                    expected: expected.clone(),
                }
                .into());
            }
            Some(_) => true,
            None => false,
        };

        let block = if content.is_empty() {
            None
        } else {
            Some(crate::block::upload::encrypt_small_upload_block(
                crate::block::upload::BlockKeys {
                    file_key: &small.file_key,
                    content_key: &small.content_key,
                    signing_key: &small.signing_key,
                },
                &small.block_verifier()?,
                content,
            )?)
        };
        let mut encrypted_thumbnails = Vec::new();
        for thumbnail in thumbnails {
            let (data, digest) = crate::node::revision::encrypt_thumbnail(
                &small.content_key,
                &small.signing_key,
                &thumbnail.content,
            )?;
            encrypted_thumbnails.push((thumbnail.r#type, data, digest));
        }

        let manifest = crate::node::download::build_revision_manifest(
            encrypted_thumbnails
                .iter()
                .map(|(thumbnail_type, _, digest)| (*thumbnail_type, digest.as_slice())),
            block.iter().map(|block| block.sha256_digest.as_slice()),
        );
        let extended_attributes = crate::node::revision::encrypt_extended_attributes(
            &small.file_key,
            &small.signing_key,
            crate::node::revision::ContentAttributes {
                size: self.size,
                modification_time: self.last_modification_time,
                block_sizes: block.iter().map(|block| block.plain_size as i32).collect(),
                sha1: sha1_digest,
                media_info: self.media_info.clone(),
                additional_metadata: self.additional_metadata.as_deref(),
            },
        )?;
        let content_metadata = SmallUploadContentMetadata {
            manifest_signature: small.signing_key.sign_detached_armored(&manifest)?,
            checksum_verified,
            signature_email_address: small.membership_address.email_address.clone(),
            content_block_encrypted_signature: block
                .as_ref()
                .map(|block| block.encrypted_signature.clone()),
            content_block_verification_token: block
                .as_ref()
                .map(|block| block.verification_token.clone()),
            extended_attributes,
        };
        let parts = SmallUploadParts {
            content_block: block.map(|block| block.encrypted_data),
            thumbnails: encrypted_thumbnails
                .into_iter()
                .map(|(thumbnail_type, data, _)| (thumbnail_type, data))
                .collect(),
        };

        let files = self.client.api().files();
        let revision_uid = match small.target {
            SmallUploadTarget::NewFile { volume_id, request } => {
                let metadata =
                    SmallFileUploadMetadata::from_draft_request(&request, content_metadata);
                let response = files
                    .upload_small_file(volume_id.clone(), metadata, parts)
                    .await
                    .map_err(|error| crate::node::draft::small_upload_conflict(error, true))?;
                RevisionUid::new(
                    NodeUid::new(volume_id, response.link_id),
                    response.revision_id,
                )
            }
            SmallUploadTarget::Revision {
                node_uid,
                current_revision_id,
            } => {
                let metadata = SmallRevisionUploadMetadata {
                    current_revision_id,
                    content: content_metadata,
                };
                let response = files
                    .upload_small_revision(
                        node_uid.volume_id.clone(),
                        node_uid.link_id.clone(),
                        metadata,
                        parts,
                    )
                    .await
                    .map_err(|error| crate::node::draft::small_upload_conflict(error, false))?;
                RevisionUid::new(node_uid, response.revision_id)
            }
        };
        self.used_small_upload.store(true, Ordering::Relaxed);
        Ok(Some(UploadResult::from_revision_uid(revision_uid)))
    }

    async fn write_draft(
        &self,
        draft: crate::node::draft::RevisionDraft,
        content_stream: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        thumbnails: Vec<crate::node::thumbnail::Thumbnail>,
        on_progress: Box<dyn Fn(i64, i64) + Send + Sync>,
    ) -> anyhow::Result<crate::node::revision::RevisionWriter> {
        let on_progress_arc: Arc<dyn Fn(i64, i64) + Send + Sync> = Arc::from(on_progress);

        let release_blocks_action = Box::new(|_| {});

        let mut writer = RevisionOperations::open_for_writing(
            &self.client,
            draft,
            release_blocks_action,
            self.size,
            self.last_modification_time,
            self.additional_metadata.clone(),
            self.media_info.clone(),
            self.expected_sha1.clone(),
            self.photos.as_ref(),
        )
        .await?;

        writer.upload_thumbnails(thumbnails).await?;

        writer
            .write(
                content_stream,
                on_progress_arc,
                Some(self.state_tx.subscribe()),
            )
            .await?;
        Ok(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::{UploadResult, upload_classes};
    use crate::node::NodeUid;
    use crate::node::revision::RevisionUid;
    use crate::revision::RevisionId;

    #[test]
    fn upload_result_carries_draft_revision_and_its_node() {
        let draft_uid = RevisionUid::new(
            NodeUid::from_parts("volume", "file-link"),
            RevisionId::new("new-revision".into()),
        );

        let result = UploadResult::from_revision_uid(draft_uid.clone());

        assert_eq!(result.revision_uid, draft_uid);
        assert_eq!(result.node_uid, NodeUid::from_parts("volume", "file-link"));
    }

    /// A draft provider that records the size it is asked for and refuses.
    struct RecordingDraftProvider(std::sync::Arc<parking_lot::Mutex<Vec<i64>>>);

    #[async_trait::async_trait]
    impl crate::node::draft::RevisionDraftProvider for RecordingDraftProvider {
        async fn get_draft(
            &self,
            intended_upload_size: i64,
        ) -> anyhow::Result<crate::node::draft::RevisionDraft> {
            self.0.lock().push(intended_upload_size);
            anyhow::bail!("no draft in this test")
        }

        async fn delete_draft(&self, _: &RevisionUid) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_draft_is_asked_for_with_the_upload_size() {
        let (client, _) = crate::test_support::client().await;
        let sizes = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let uploader = super::FileUploader::create(
            &client,
            Box::new(RecordingDraftProvider(sizes.clone())),
            1_234_567,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let error = uploader
            .upload_from_stream(
                Box::new(tokio::io::empty()),
                Vec::new(),
                Box::new(|_, _| {}),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("no draft in this test"));
        assert_eq!(*sizes.lock(), vec![1_234_567]);
    }

    #[test]
    fn upload_classification_matches_route_buckets() {
        assert_eq!(upload_classes(127 * 1024, 1), ("small", "single"));
        assert_eq!(upload_classes(128 * 1024, 1), ("single", "single"));
        assert_eq!(upload_classes(8 * 1024 * 1024, 2), ("multi", "few"));
        assert_eq!(upload_classes(24 * 1024 * 1024, 6), ("multi", "many"));
    }
}

impl Drop for FileUploader {
    fn drop(&mut self) {
        let remaining = self.remaining_number_of_blocks.swap(0, Ordering::SeqCst);
        if remaining > 0 {
            self.client
                .revision_creation_semaphore()
                .release(remaining as usize);
        }
    }
}

#[cfg(test)]
mod small_upload_tests {
    use super::FileUploader;
    use crate::api::revision::RevisionConflict;
    use crate::error::ApiError;
    use crate::node::NodeUid;
    use crate::node::draft::{
        NodeWithSameNameExistsError, RevisionDraft, RevisionDraftConflictError,
        RevisionDraftProvider, SmallUpload, SmallUploadTarget,
    };
    use crate::node::revision::RevisionUid;
    use crate::node::thumbnail::{Thumbnail, ThumbnailType};
    use crate::pgp::{PgpArmoredMessage, PgpArmoredPrivateKey, PgpArmoredSignature};
    use crate::revision::RevisionId;
    use parking_lot::Mutex;
    use proton_rpgp::AsPublicKeyRef;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A provider whose small upload has real keys and whose draft path fails as
    /// `draft_error` says, as the draft code would for the same server state.
    struct Provider {
        target: fn() -> SmallUploadTarget,
        draft_error: fn() -> anyhow::Error,
        draft_sizes: Arc<Mutex<Vec<i64>>>,
        keys: Arc<Mutex<Option<crate::pgp::PgpSessionKey>>>,
    }

    #[async_trait::async_trait]
    impl RevisionDraftProvider for Provider {
        async fn get_draft(&self, intended_upload_size: i64) -> anyhow::Result<RevisionDraft> {
            self.draft_sizes.lock().push(intended_upload_size);
            Err((self.draft_error)())
        }

        async fn get_small_upload(&self) -> anyhow::Result<Option<SmallUpload>> {
            let file_key = crate::crypto::CryptoGenerator::generate_private_key()?;
            let content_key = crate::crypto::CryptoGenerator::generate_session_key();
            let content_key_packet = proton_rpgp::Encryptor::default()
                .with_encryption_key(file_key.0.as_public_key())
                .encrypt_session_key(&content_key.to_rpgp_sk()?)?;
            *self.keys.lock() = Some(content_key.clone());
            let mut target = (self.target)();
            if let SmallUploadTarget::NewFile { request, .. } = &mut target {
                // A new file's packet is the one its draft request carries.
                request.content_key_packet = content_key_packet.clone();
            }
            Ok(Some(SmallUpload {
                file_key,
                content_key,
                signing_key: crate::crypto::CryptoGenerator::generate_private_key()?,
                membership_address: proton_sdk_rs2::protobuf::Address {
                    email_address: "member@example.test".into(),
                    ..Default::default()
                },
                content_key_packet,
                target,
            }))
        }

        async fn delete_draft(&self, _: &RevisionUid) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn new_file() -> SmallUploadTarget {
        SmallUploadTarget::NewFile {
            volume_id: crate::volume::VolumeId::new("volume".into()),
            request: Box::new(crate::api::file::FileCreationRequest {
                base: crate::api::node::NodeCreationRequest {
                    name: PgpArmoredMessage("encrypted name".into()),
                    name_hash_digest: vec![0xab, 0xcd],
                    parent_link_id: crate::links::LinkId::new("parent".into()),
                    passphrase: PgpArmoredMessage("passphrase".into()),
                    passphrase_signature: PgpArmoredSignature("passphrase signature".into()),
                    key: PgpArmoredPrivateKey("node key".into()),
                },
                media_type: "text/plain".into(),
                content_key_packet: Vec::new(),
                content_key_signature: PgpArmoredSignature("content key signature".into()),
                signature_email_address: "member@example.test".into(),
                client_uid: Some("test-client".into()),
                intended_upload_size: None,
            }),
        }
    }

    fn revision() -> SmallUploadTarget {
        SmallUploadTarget::Revision {
            node_uid: NodeUid::from_parts("volume", "file"),
            current_revision_id: RevisionId::new("base".into()),
        }
    }

    fn api_error(status: u16, body: &str) -> ApiError {
        ApiError::from_http(
            reqwest::StatusCode::from_u16(status).unwrap(),
            &reqwest::header::HeaderMap::new(),
            body,
        )
    }

    /// The name conflict the draft path reports for a real collision.
    fn name_taken() -> anyhow::Error {
        NodeWithSameNameExistsError {
            conflict: None,
            source: api_error(422, r#"{"Code":2500,"Error":"exists"}"#),
        }
        .into()
    }

    /// The revision conflict the draft path reports for a stale base (P11).
    fn base_changed() -> anyhow::Error {
        RevisionDraftConflictError {
            conflict: Some(RevisionConflict {
                link_id: None,
                revision_id: Some(RevisionId::new("newer".into())),
                draft_revision_id: None,
                draft_client_uid: None,
            }),
            source: api_error(422, r#"{"Code":2500,"Error":"changed"}"#),
        }
        .into()
    }

    struct Server {
        url: reqwest::Url,
        requests: tokio::task::JoinHandle<Vec<Vec<u8>>>,
    }

    /// Answers each request with the next of `answers` (status, body), then
    /// expects no more.
    async fn server(answers: Vec<(u16, &'static str)>) -> Server {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = reqwest::Url::parse(&format!("http://{}/drive/", listener.local_addr().unwrap()))
            .unwrap();
        let requests = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in answers {
                let (mut stream, _) = listener.accept().await.unwrap();
                requests.push(receive(&mut stream).await);
                let answer = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(answer.as_bytes()).await.unwrap();
            }
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "an unexpected request"
            );
            requests
        });
        Server { url, requests }
    }

    async fn receive(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut buffer = [0; 65536];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0, "request ended early");
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: ")?.parse().ok())
                    .expect("a content length");
                if bytes.len() >= end + 4 + length {
                    return bytes;
                }
            }
        }
    }

    /// The parts of a multipart request: (name, body).
    fn parts(request: &[u8]) -> Vec<(String, Vec<u8>)> {
        let text = String::from_utf8_lossy(request);
        let boundary = text
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .contains("multipart/form-data")
                    .then(|| line.split("boundary=").nth(1).unwrap().trim().to_string())
            })
            .expect("a multipart request");
        let delimiter = format!("--{boundary}");
        let body_start = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let body = &request[body_start..];
        let mut result = Vec::new();
        let mut rest = body;
        while let Some(start) = find(rest, delimiter.as_bytes()) {
            rest = &rest[start + delimiter.len()..];
            if rest.starts_with(b"--") {
                break;
            }
            let header_end = find(rest, b"\r\n\r\n").unwrap();
            let headers = String::from_utf8_lossy(&rest[..header_end]).to_string();
            let name = headers
                .split("name=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .to_string();
            let content = &rest[header_end + 4..];
            let end = find(content, format!("\r\n{delimiter}").as_bytes()).unwrap();
            result.push((name, content[..end].to_vec()));
            rest = &content[end..];
        }
        result
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    struct Run {
        result: anyhow::Result<super::UploadResult>,
        requests: Vec<Vec<u8>>,
        draft_sizes: Vec<i64>,
        content_key: Option<crate::pgp::PgpSessionKey>,
    }

    async fn upload(
        flag: bool,
        target: fn() -> SmallUploadTarget,
        draft_error: fn() -> anyhow::Error,
        content: Vec<u8>,
        thumbnails: Vec<Thumbnail>,
        answers: Vec<(u16, &'static str)>,
    ) -> Run {
        let server = server(answers).await;
        let client = crate::test_support::client_at(
            server.url.clone(),
            Arc::new(crate::test_support::FixedFeatureFlags(flag)),
        );
        let draft_sizes = Arc::new(Mutex::new(Vec::new()));
        let keys = Arc::new(Mutex::new(None));
        let provider = Provider {
            target,
            draft_error,
            draft_sizes: draft_sizes.clone(),
            keys: keys.clone(),
        };
        let uploader = FileUploader::create(
            &client,
            Box::new(provider),
            content.len() as i64,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let result = uploader
            .upload_from_stream_with_revision(
                Box::new(std::io::Cursor::new(content)),
                thumbnails,
                Box::new(|_, _| {}),
            )
            .await;
        let requests = server.requests.await.unwrap();
        let draft_sizes = draft_sizes.lock().clone();
        let content_key = keys.lock().clone();
        Run {
            result,
            requests,
            draft_sizes,
            content_key,
        }
    }

    const CREATED: &str = r#"{"Code":1000,"LinkID":"new-link","RevisionID":"new-revision"}"#;
    const NAME_CONFLICT: &str = r#"{"Code":2500,"Error":"A file or folder with that name already exists","Details":{"ConflictLinkID":"other"}}"#;

    #[tokio::test]
    async fn a_small_file_goes_up_in_one_request() {
        let content = b"small file content".repeat(50);
        let thumbnail = Thumbnail {
            r#type: ThumbnailType::Thumbnail,
            content: vec![7; 100],
        };
        let run = upload(
            true,
            new_file,
            name_taken,
            content.clone(),
            vec![thumbnail],
            vec![(200, CREATED)],
        )
        .await;
        // The new node and the revision this upload made (P6).
        assert_eq!(
            run.result.unwrap(),
            super::UploadResult::from_revision_uid(RevisionUid::new(
                NodeUid::from_parts("volume", "new-link"),
                RevisionId::new("new-revision".into()),
            ))
        );
        assert!(run.draft_sizes.is_empty(), "no draft");
        let request = &run.requests[0];
        assert!(request.starts_with(b"POST /drive/v2/volumes/volume/files/small HTTP/1.1"));
        let parts = parts(request);
        let names: Vec<_> = parts.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["Metadata", "ContentBlock", "ThumbnailBlockType_1"]);
        let metadata: serde_json::Value = serde_json::from_slice(&parts[0].1).unwrap();
        assert_eq!(metadata["Name"], "encrypted name");
        assert_eq!(metadata["NameHash"], "abcd");
        assert_eq!(metadata["ParentLinkID"], "parent");
        assert_eq!(metadata["NodeKey"], "node key");
        assert_eq!(metadata["MIMEType"], "text/plain");
        assert_eq!(metadata["SignatureEmail"], "member@example.test");
        assert_eq!(metadata["ChecksumVerified"], false);
        assert!(metadata["Photo"].is_null());
        assert!(metadata["ContentKeyPacket"].is_string());
        assert!(
            metadata["ManifestSignature"]
                .as_str()
                .unwrap()
                .contains("PGP SIGNATURE")
        );
        assert!(metadata["XAttr"].as_str().unwrap().contains("PGP MESSAGE"));
        assert!(
            metadata["ContentBlockEncSignature"]
                .as_str()
                .unwrap()
                .contains("PGP MESSAGE")
        );
        assert!(metadata.get("ClientUID").is_none() && metadata.get("Hash").is_none());
        // The block decrypts to the content, and its token is the code XOR its prefix.
        let block = &parts[1].1;
        assert_eq!(run.content_key.unwrap().decrypt(block).unwrap(), content);
        let token = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            metadata["ContentBlockVerificationToken"].as_str().unwrap(),
        )
        .unwrap();
        let packet = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            metadata["ContentKeyPacket"].as_str().unwrap(),
        )
        .unwrap();
        let code = &packet[packet.len() - 32..];
        let expected: Vec<u8> = code.iter().zip(block).map(|(c, b)| c ^ b).collect();
        assert_eq!(token, expected);
    }

    #[tokio::test]
    async fn a_small_revision_goes_up_in_one_request() {
        let run = upload(
            true,
            revision,
            base_changed,
            b"new content".to_vec(),
            Vec::new(),
            vec![(
                200,
                r#"{"Code":1000,"LinkID":"file","RevisionID":"new-revision"}"#,
            )],
        )
        .await;
        assert_eq!(
            run.result.unwrap().revision_uid,
            RevisionUid::new(
                NodeUid::from_parts("volume", "file"),
                RevisionId::new("new-revision".into())
            )
        );
        let request = &run.requests[0];
        assert!(
            request
                .starts_with(b"POST /drive/v2/volumes/volume/files/file/revisions/small HTTP/1.1")
        );
        let metadata: serde_json::Value = serde_json::from_slice(&parts(request)[0].1).unwrap();
        assert_eq!(metadata["CurrentRevisionID"], "base");
        assert!(metadata.get("Name").is_none());
    }

    #[tokio::test]
    async fn an_empty_small_file_has_no_content_block() {
        let run = upload(
            true,
            new_file,
            name_taken,
            Vec::new(),
            Vec::new(),
            vec![(200, CREATED)],
        )
        .await;
        assert!(run.result.is_ok());
        let parts = parts(&run.requests[0]);
        assert_eq!(parts.len(), 1);
        let metadata: serde_json::Value = serde_json::from_slice(&parts[0].1).unwrap();
        assert!(metadata["ContentBlockVerificationToken"].is_null());
        assert!(metadata["ContentBlockEncSignature"].is_null());
    }

    /// A name taken on the server: the small upload is refused cleanly, the draft
    /// path runs and reports the conflict as it always has.
    #[tokio::test]
    async fn a_name_conflict_falls_back_to_the_draft_and_its_error() {
        let run = upload(
            true,
            new_file,
            name_taken,
            b"content".to_vec(),
            Vec::new(),
            vec![(422, NAME_CONFLICT)],
        )
        .await;
        let error = run.result.unwrap_err();
        assert!(
            error
                .downcast_ref::<NodeWithSameNameExistsError>()
                .is_some(),
            "{error:#}"
        );
        assert_eq!(run.requests.len(), 1);
        assert_eq!(run.draft_sizes, vec![7]);
    }

    /// A stale base revision: the draft path reports the revision conflict (P11).
    #[tokio::test]
    async fn a_revision_conflict_falls_back_to_the_draft_and_its_error() {
        let run = upload(
            true,
            revision,
            base_changed,
            b"content".to_vec(),
            Vec::new(),
            vec![(
                422,
                r#"{"Code":2500,"Error":"changed","Details":{"ConflictRevisionID":"newer"}}"#,
            )],
        )
        .await;
        let error = run.result.unwrap_err();
        let conflict = error
            .downcast_ref::<RevisionDraftConflictError>()
            .expect("a revision conflict");
        assert_eq!(
            conflict.conflict.as_ref().unwrap().revision_id,
            Some(RevisionId::new("newer".into()))
        );
        assert_eq!(run.draft_sizes, vec![7]);
    }

    /// A failure after the request was sent may have been applied: no second
    /// upload, no draft.
    #[tokio::test]
    async fn a_server_error_is_returned_without_a_second_upload() {
        let run = upload(
            true,
            new_file,
            name_taken,
            b"content".to_vec(),
            Vec::new(),
            vec![(503, r#"{"Code":503,"Error":"unavailable"}"#)],
        )
        .await;
        let error = run.result.unwrap_err();
        assert_eq!(ApiError::find(&error).unwrap().http_status, Some(503));
        assert!(
            error
                .downcast_ref::<NodeWithSameNameExistsError>()
                .is_none()
        );
        assert_eq!(run.requests.len(), 1);
        assert!(run.draft_sizes.is_empty());
    }

    #[tokio::test]
    async fn without_the_feature_flag_the_draft_path_is_taken() {
        let run = upload(
            false,
            new_file,
            name_taken,
            b"content".to_vec(),
            Vec::new(),
            vec![],
        )
        .await;
        assert!(run.result.is_err());
        assert!(run.requests.is_empty());
        assert_eq!(run.draft_sizes, vec![7]);
    }

    #[tokio::test]
    async fn a_file_over_the_limit_takes_the_draft_path() {
        // 120 000 bytes and 10 % overhead are over 128 KiB.
        let run = upload(
            true,
            new_file,
            name_taken,
            vec![1; 120_000],
            Vec::new(),
            vec![],
        )
        .await;
        assert!(run.result.is_err());
        assert!(run.requests.is_empty());
        assert_eq!(run.draft_sizes, vec![120_000]);
        // So is a small file whose thumbnails take it over.
        let thumbnail = Thumbnail {
            r#type: ThumbnailType::Preview,
            content: vec![1; 120_000],
        };
        let run = upload(
            true,
            new_file,
            name_taken,
            vec![1; 10],
            vec![thumbnail],
            vec![],
        )
        .await;
        assert!(run.requests.is_empty());
        assert_eq!(run.draft_sizes, vec![10]);
    }
}

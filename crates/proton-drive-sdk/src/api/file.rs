pub mod photos;
pub mod thumbnail;

use crate::api::ApiResponse;
use crate::api::block::{BlockUploadPreparationRequest, BlockUploadPreparationResponse};
use crate::api::file::thumbnail::{ThumbnailBlockListRequest, ThumbnailBlockListResponse};
use crate::api::node::NodeCreationRequest;
use crate::api::revision::{
    ActiveRevisionDto, RevisionCreationRequest, RevisionCreationResponse, RevisionListResponse,
    RevisionResponse, RevisionUpdateRequest,
};
use crate::links::LinkId;
use crate::pgp::{PgpArmoredMessage, PgpArmoredPrivateKey, PgpArmoredSignature};
use crate::revision::RevisionId;
use crate::volume::VolumeId;
use anyhow::Context;
use async_trait::async_trait;
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FileContentDigestsDto {
    #[serde(rename = "SHA1")]
    #[serde(default, with = "crate::utils::serde::forgiving_hex_bytes_opt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct FileCreationIdentifiers {
    #[serde(rename = "ID")]
    pub link_id: LinkId,

    #[serde(rename = "RevisionID")]
    pub revision_id: RevisionId,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FileCreationRequest {
    #[serde(flatten)]
    pub base: NodeCreationRequest,

    #[serde(rename = "MIMEType")]
    pub media_type: String,

    #[serde(with = "crate::utils::serde::base64_bytes")]
    pub content_key_packet: Vec<u8>,

    #[serde(rename = "ContentKeyPacketSignature")]
    pub content_key_signature: PgpArmoredSignature,

    #[serde(rename = "ClientUID")]
    pub client_uid: Option<String>,

    pub intended_upload_size: Option<i64>,

    #[serde(rename = "SignatureAddress")]
    pub signature_email_address: String,
}

#[derive(Debug, Deserialize)]
pub struct FileCreationResponse {
    #[serde(flatten)]
    pub base: ApiResponse,

    #[serde(rename = "File")]
    pub identifiers: FileCreationIdentifiers,
}

impl FileCreationResponse {
    pub fn is_success(&self) -> bool {
        self.base.is_success()
    }
}

/// The content fields of a small upload's metadata, shared by a new file and a new
/// revision (`cs/client/cs/src/Proton.Drive.Sdk/Api/Files/SmallFileUploadMetadataRequest.cs`,
/// `SmallRevisionUploadMetadataRequest.cs`).
#[derive(Debug, Clone, Serialize)]
pub struct SmallUploadContentMetadata {
    #[serde(rename = "ManifestSignature")]
    pub manifest_signature: PgpArmoredSignature,

    #[serde(rename = "ChecksumVerified")]
    pub checksum_verified: bool,

    #[serde(rename = "SignatureEmail")]
    pub signature_email_address: String,

    /// The content block's signature, encrypted to the file key; none for an empty file.
    #[serde(rename = "ContentBlockEncSignature")]
    pub content_block_encrypted_signature: Option<PgpArmoredMessage>,

    /// The content block's verification token; none for an empty file.
    #[serde(
        rename = "ContentBlockVerificationToken",
        with = "crate::utils::serde::base64_bytes_opt"
    )]
    pub content_block_verification_token: Option<Vec<u8>>,

    #[serde(rename = "XAttr")]
    pub extended_attributes: PgpArmoredMessage,
}

/// Metadata of a small new file: the fields of its draft and of its commit, sent in one
/// request (`POST v2/volumes/{volumeID}/files/small`).
#[derive(Debug, Clone, Serialize)]
pub struct SmallFileUploadMetadata {
    #[serde(rename = "Name")]
    pub name: PgpArmoredMessage,

    #[serde(rename = "NameHash")]
    #[serde(with = "crate::utils::serde::forgiving_hex_bytes")]
    pub name_hash_digest: Vec<u8>,

    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: LinkId,

    #[serde(rename = "NodePassphrase")]
    pub passphrase: PgpArmoredMessage,

    #[serde(rename = "NodePassphraseSignature")]
    pub passphrase_signature: PgpArmoredSignature,

    #[serde(rename = "NodeKey")]
    pub key: PgpArmoredPrivateKey,

    #[serde(rename = "MIMEType")]
    pub media_type: String,

    #[serde(
        rename = "ContentKeyPacket",
        with = "crate::utils::serde::base64_bytes"
    )]
    pub content_key_packet: Vec<u8>,

    #[serde(rename = "ContentKeyPacketSignature")]
    pub content_key_signature: PgpArmoredSignature,

    #[serde(flatten)]
    pub content: SmallUploadContentMetadata,

    /// Required by the server for files that are not photos too; always null here.
    #[serde(rename = "Photo")]
    pub photo: Option<()>,
}

impl SmallFileUploadMetadata {
    /// The small upload of what `draft` would create, with the content fields.
    pub fn from_draft_request(
        draft: &FileCreationRequest,
        content: SmallUploadContentMetadata,
    ) -> Self {
        Self {
            name: draft.base.name.clone(),
            name_hash_digest: draft.base.name_hash_digest.clone(),
            parent_link_id: draft.base.parent_link_id.clone(),
            passphrase: draft.base.passphrase.clone(),
            passphrase_signature: draft.base.passphrase_signature.clone(),
            key: draft.base.key.clone(),
            media_type: draft.media_type.clone(),
            content_key_packet: draft.content_key_packet.clone(),
            content_key_signature: draft.content_key_signature.clone(),
            content,
            photo: None,
        }
    }
}

/// Metadata of a small new revision
/// (`POST v2/volumes/{volumeID}/files/{linkID}/revisions/small`).
#[derive(Debug, Clone, Serialize)]
pub struct SmallRevisionUploadMetadata {
    /// The revision this one replaces, checked as a draft's `CurrentRevisionID`.
    #[serde(rename = "CurrentRevisionID")]
    pub current_revision_id: RevisionId,

    #[serde(flatten)]
    pub content: SmallUploadContentMetadata,
}

/// The encrypted parts sent with a small upload's metadata.
#[derive(Debug, Clone, Default)]
pub struct SmallUploadParts {
    /// The one content block; none for an empty file.
    pub content_block: Option<Vec<u8>>,
    /// Encrypted thumbnails, at most one per type.
    pub thumbnails: Vec<(crate::node::thumbnail::ThumbnailType, Vec<u8>)>,
}

#[derive(Debug, Deserialize)]
pub struct SmallUploadResponse {
    #[serde(flatten)]
    pub base: ApiResponse,

    #[serde(rename = "LinkID")]
    pub link_id: LinkId,

    #[serde(rename = "RevisionID")]
    pub revision_id: RevisionId,
}

/// The multipart body of a small upload, as the official SDKs send it: `Metadata` (JSON),
/// `ContentBlock` and `ThumbnailBlockType_<type>`, each with its name as file name.
fn small_upload_form(
    metadata: &impl Serialize,
    parts: SmallUploadParts,
) -> anyhow::Result<reqwest::multipart::Form> {
    use reqwest::multipart::{Form, Part};
    let part = |data: Vec<u8>, name: &str, mime: &str| {
        Part::bytes(data).file_name(name.to_string()).mime_str(mime)
    };
    let mut form = Form::new().part(
        "Metadata",
        part(
            serde_json::to_vec(metadata)?,
            "Metadata",
            "application/json",
        )?,
    );
    if let Some(block) = parts.content_block {
        form = form.part(
            "ContentBlock",
            part(block, "ContentBlock", "application/octet-stream")?,
        );
    }
    let mut seen = std::collections::HashSet::new();
    for (thumbnail_type, data) in parts.thumbnails {
        anyhow::ensure!(
            seen.insert(thumbnail_type as u32),
            "Duplicate thumbnail types"
        );
        let name = format!("ThumbnailBlockType_{}", thumbnail_type as u32);
        form = form.part(name.clone(), part(data, &name, "application/octet-stream")?);
    }
    Ok(form)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FileDto {
    pub media_type: String,

    #[serde(rename = "TotalEncryptedSize")]
    pub total_size_on_storage: i64,

    #[serde(with = "crate::utils::serde::base64_bytes")]
    pub content_key_packet: Vec<u8>,

    #[serde(rename = "ContentKeyPacketSignature")]
    pub content_key_signature: Option<PgpArmoredSignature>,

    pub active_revision: Option<ActiveRevisionDto>,
}

#[async_trait]
pub trait FilesApiClient: Send + Sync {
    async fn create_file(
        &self,
        volume_id: VolumeId,
        request: FileCreationRequest,
    ) -> anyhow::Result<FileCreationResponse>;

    async fn create_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        request: RevisionCreationRequest,
    ) -> anyhow::Result<RevisionCreationResponse>;

    async fn prepare_block_upload(
        &self,
        request: BlockUploadPreparationRequest,
    ) -> anyhow::Result<BlockUploadPreparationResponse>;

    async fn update_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        revision_id: RevisionId,
        request: RevisionUpdateRequest,
    ) -> anyhow::Result<ApiResponse>;

    async fn get_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        revision_id: RevisionId,
        from_block_index: Option<i32>,
        page_size: Option<i32>,
        without_block_urls: bool,
    ) -> anyhow::Result<RevisionResponse>;

    async fn get_thumbnail_blocks(
        &self,
        volume_id: VolumeId,
        thumbnail_ids: Vec<String>,
    ) -> anyhow::Result<ThumbnailBlockListResponse>;

    async fn get_revisions(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
    ) -> anyhow::Result<RevisionListResponse>;

    async fn restore_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        revision_id: RevisionId,
    ) -> anyhow::Result<ApiResponse>;

    async fn delete_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        revision_id: RevisionId,
    ) -> anyhow::Result<ApiResponse>;

    /// Creates and commits a small new file in one request. Not idempotent: the caller
    /// must not repeat it after an answer it did not get.
    async fn upload_small_file(
        &self,
        volume_id: VolumeId,
        metadata: SmallFileUploadMetadata,
        parts: SmallUploadParts,
    ) -> anyhow::Result<SmallUploadResponse>;

    /// Creates and commits a small new revision in one request. Not idempotent.
    async fn upload_small_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        metadata: SmallRevisionUploadMetadata,
        parts: SmallUploadParts,
    ) -> anyhow::Result<SmallUploadResponse>;
}
use proton_sdk_rs2::auth::TokenCredential;

use super::parse_json_response;

pub struct DefaultFilesApiClient {
    client: ClientWithMiddleware,
    base_url: reqwest::Url,
    token_credential: Option<TokenCredential>,
}

impl DefaultFilesApiClient {
    pub fn new(
        client: ClientWithMiddleware,
        base_url: reqwest::Url,
        token_credential: Option<TokenCredential>,
    ) -> Self {
        Self {
            client,
            base_url,
            token_credential,
        }
    }

    async fn add_auth_headers(
        &self,
        mut builder: reqwest_middleware::RequestBuilder,
    ) -> anyhow::Result<reqwest_middleware::RequestBuilder> {
        if let Some(credential) = &self.token_credential {
            let (access_token, _) = credential.get_tokens().await?;
            builder = builder.header("Authorization", format!("Bearer {}", access_token));
            builder = builder.header("x-pm-uid", credential.session_id().raw());
        }
        Ok(builder)
    }
}

#[async_trait]
impl FilesApiClient for DefaultFilesApiClient {
    #[tracing::instrument(skip(self, request))]
    async fn create_file(
        &self,
        volume_id: VolumeId,
        request: FileCreationRequest,
    ) -> anyhow::Result<FileCreationResponse> {
        tracing::debug!(volume_id = %volume_id.raw(), "Creating file");
        let url = self
            .base_url
            .join(&format!("v2/volumes/{}/files", volume_id.raw()))?;
        let builder = self.client.post(url).json(&request);
        let builder = self.add_auth_headers(builder).await?;
        let resp = parse_json_response::<FileCreationResponse>(builder.send().await?).await?;
        tracing::info!(link_id = %resp.identifiers.link_id.raw(), revision_id = %resp.identifiers.revision_id.raw(), "File created");
        Ok(resp)
    }

    #[tracing::instrument(skip(self, request))]
    async fn create_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        request: RevisionCreationRequest,
    ) -> anyhow::Result<RevisionCreationResponse> {
        tracing::debug!(volume_id = %volume_id.raw(), link_id = %link_id.raw(), "Creating revision");
        let url = self.base_url.join(&format!(
            "v2/volumes/{}/files/{}/revisions",
            volume_id.raw(),
            link_id.raw()
        ))?;
        let builder = self.client.post(url).json(&request);
        let builder = self.add_auth_headers(builder).await?;
        let resp = parse_json_response::<RevisionCreationResponse>(builder.send().await?).await?;
        tracing::info!(revision_id = %resp.identity.revision_id.raw(), "Revision created");
        Ok(resp)
    }

    #[tracing::instrument(skip(self, request))]
    async fn prepare_block_upload(
        &self,
        request: BlockUploadPreparationRequest,
    ) -> anyhow::Result<BlockUploadPreparationResponse> {
        tracing::debug!("Preparing block upload");
        let url = self.base_url.join("blocks")?;
        let builder = self.client.post(url).json(&request);
        let builder = self.add_auth_headers(builder).await?;
        let resp =
            parse_json_response::<BlockUploadPreparationResponse>(builder.send().await?).await?;
        tracing::info!(
            blocks = resp.upload_targets.len(),
            thumbnails = resp.thumbnail_upload_targets.len(),
            "Block upload prepared"
        );
        Ok(resp)
    }

    #[tracing::instrument(skip(self, request))]
    async fn update_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        revision_id: RevisionId,
        request: RevisionUpdateRequest,
    ) -> anyhow::Result<ApiResponse> {
        tracing::debug!(volume_id = %volume_id.raw(), link_id = %link_id.raw(), revision_id = %revision_id.raw(), "Sealing revision");
        let url = self.base_url.join(&format!(
            "v2/volumes/{}/files/{}/revisions/{}",
            volume_id.raw(),
            link_id.raw(),
            revision_id.raw()
        ))?;
        let builder = self.client.put(url).json(&request);
        let builder = self.add_auth_headers(builder).await?;
        let resp = parse_json_response::<ApiResponse>(builder.send().await?).await?;
        if resp.is_success() {
            tracing::info!("Revision sealed successfully");
        } else {
            tracing::warn!(code = resp.code.0, error = ?resp.error_message, "Revision sealing failed");
        }
        Ok(resp)
    }

    async fn get_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        revision_id: RevisionId,
        from_block_index: Option<i32>,
        page_size: Option<i32>,
        without_block_urls: bool,
    ) -> anyhow::Result<RevisionResponse> {
        let mut path = format!(
            "v2/volumes/{}/files/{}/revisions/{}?",
            volume_id.raw(),
            link_id.raw(),
            revision_id.raw()
        );

        if let Some(idx) = from_block_index {
            path.push_str(&format!("FromBlockIndex={}&", idx));
        }

        if let Some(size) = page_size {
            path.push_str(&format!("PageSize={}&", size));
        }

        path.push_str(&format!(
            "NoBlockUrls={}",
            if without_block_urls { 1 } else { 0 }
        ));

        let url = self.base_url.join(&path)?;
        let builder = self.client.get(url);
        let builder = self.add_auth_headers(builder).await?;

        parse_json_response::<RevisionResponse>(builder.send().await?).await
    }

    async fn get_revisions(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
    ) -> anyhow::Result<RevisionListResponse> {
        let url = self.base_url.join(&format!(
            "v2/volumes/{}/files/{}/revisions",
            volume_id.raw(),
            link_id.raw(),
        ))?;
        let builder = self.client.get(url);
        let builder = self.add_auth_headers(builder).await?;
        parse_json_response::<RevisionListResponse>(builder.send().await?).await
    }

    async fn restore_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        revision_id: RevisionId,
    ) -> anyhow::Result<ApiResponse> {
        let url = self.base_url.join(&format!(
            "v2/volumes/{}/files/{}/revisions/{}/restore",
            volume_id.raw(),
            link_id.raw(),
            revision_id.raw(),
        ))?;
        let builder = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_LENGTH, 0);
        let builder = self.add_auth_headers(builder).await?;
        parse_json_response::<ApiResponse>(builder.send().await?).await
    }

    async fn delete_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        revision_id: RevisionId,
    ) -> anyhow::Result<ApiResponse> {
        let url = self.base_url.join(&format!(
            "v2/volumes/{}/files/{}/revisions/{}",
            volume_id.raw(),
            link_id.raw(),
            revision_id.raw()
        ))?;
        let builder = self.client.delete(url);
        let builder = self.add_auth_headers(builder).await?;
        parse_json_response::<ApiResponse>(builder.send().await?).await
    }

    #[tracing::instrument(skip(self, metadata, parts))]
    async fn upload_small_file(
        &self,
        volume_id: VolumeId,
        metadata: SmallFileUploadMetadata,
        parts: SmallUploadParts,
    ) -> anyhow::Result<SmallUploadResponse> {
        let url = self
            .base_url
            .join(&format!("v2/volumes/{}/files/small", volume_id.raw()))?;
        let builder = self
            .client
            .post(url)
            .multipart(small_upload_form(&metadata, parts)?);
        let builder = self.add_auth_headers(builder).await?;
        let resp = parse_json_response::<SmallUploadResponse>(builder.send().await?).await?;
        tracing::info!(link_id = %resp.link_id.raw(), revision_id = %resp.revision_id.raw(), "Small file uploaded");
        Ok(resp)
    }

    #[tracing::instrument(skip(self, metadata, parts))]
    async fn upload_small_revision(
        &self,
        volume_id: VolumeId,
        link_id: LinkId,
        metadata: SmallRevisionUploadMetadata,
        parts: SmallUploadParts,
    ) -> anyhow::Result<SmallUploadResponse> {
        let url = self.base_url.join(&format!(
            "v2/volumes/{}/files/{}/revisions/small",
            volume_id.raw(),
            link_id.raw()
        ))?;
        let builder = self
            .client
            .post(url)
            .multipart(small_upload_form(&metadata, parts)?);
        let builder = self.add_auth_headers(builder).await?;
        let resp = parse_json_response::<SmallUploadResponse>(builder.send().await?).await?;
        tracing::info!(revision_id = %resp.revision_id.raw(), "Small revision uploaded");
        Ok(resp)
    }

    async fn get_thumbnail_blocks(
        &self,
        volume_id: VolumeId,
        thumbnail_ids: Vec<String>,
    ) -> anyhow::Result<ThumbnailBlockListResponse> {
        let url = self
            .base_url
            .join(&format!("volumes/{}/thumbnails", volume_id.raw()))?;

        tracing::debug!(
            "Fetching thumbnail blocks: url={}, thumbnail_ids={:?}",
            url,
            thumbnail_ids
        );

        let builder = self.client.post(url).json(&ThumbnailBlockListRequest {
            thumbnail_ids: thumbnail_ids.clone(),
        });
        let builder = self.add_auth_headers(builder).await?;
        let response = builder.send().await?;

        let status = response.status();
        let body_text = response
            .text()
            .await
            .unwrap_or_else(|_| "<failed to read body>".to_string());

        if !status.is_success() {
            tracing::warn!(
                "Thumbnail blocks API returned error: status={}, body={}",
                status,
                body_text
            );
            anyhow::bail!(
                "Thumbnail blocks API failed with status {}: {}",
                status,
                body_text
            );
        }

        let parsed: ThumbnailBlockListResponse = serde_json::from_str(&body_text)
            .context("Failed to parse thumbnail blocks response")?;

        tracing::debug!("Parsed {} thumbnail blocks", parsed.blocks.len());

        Ok(parsed)
    }
}

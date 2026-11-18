use std::fmt::Display;

use futures::stream::{FuturesUnordered, StreamExt};

use crate::author::Author;
use crate::client::ProtonDriveClient;
use crate::error::ProtonDriveError;
use crate::links::LinkId;
use crate::node::file::{
    DegradedFileMetadata, DegradedFileNode, DegradedFileSecrets, FileMetadata, FileNode,
    FileOrFileDraftNode, FileSecrets,
};
use crate::node::folder::{
    DegradedFolderMetadata, DegradedFolderNode, DegradedFolderSecrets, FolderMetadata, FolderNode,
    FolderSecrets,
};
use crate::node::secrets::{DegradedNodeSecrets, ShareAndKey};
use crate::pgp::{PgpPrivateKey, PgpSessionKey};
#[allow(deprecated)]
use crate::protobuf::SignatureVerificationError;
use crate::share::ShareId;
use crate::utils::PotentialObject;
use crate::volume::VolumeId;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod authorship;
pub mod crypto;
pub mod download;
pub mod file;
pub mod folder;
pub mod photo;
pub mod revision;
pub mod secrets;
pub mod thumbnail;
pub mod transfer;

pub mod draft;
pub mod operations;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DegradedNode {
    Folder(DegradedFolderNode),
    File(DegradedFileNode),
    Photo(DegradedFileNode),
    Album(DegradedFolderNode),
}

impl DegradedNode {
    pub fn uid(&self) -> &NodeUid {
        match self {
            DegradedNode::Folder(n) | DegradedNode::Album(n) => &n.base.uid,
            DegradedNode::File(n) | DegradedNode::Photo(n) => &n.base.uid,
        }
    }

    pub fn parent_uid(&self) -> Option<&NodeUid> {
        match self {
            Self::Folder(n) | Self::Album(n) => n.base.parent_uid.as_ref(),
            Self::File(n) | Self::Photo(n) => n.base.parent_uid.as_ref(),
        }
    }

    pub fn tree_event_scope_id(&self) -> String {
        self.uid().volume_id.raw().to_string()
    }

    pub fn set_parent_uid(&mut self, parent_uid: Option<NodeUid>) {
        match self {
            Self::Folder(n) | Self::Album(n) => n.base.parent_uid = parent_uid,
            Self::File(n) | Self::Photo(n) => n.base.parent_uid = parent_uid,
        }
    }

    pub fn set_name(&mut self, name: String) {
        match self {
            Self::Folder(n) | Self::Album(n) => n.base.name = PotentialObject::Node(name),
            Self::File(n) | Self::Photo(n) => n.base.name = PotentialObject::Node(name),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DegradedNodeBase {
    pub uid: NodeUid,
    pub parent_uid: Option<NodeUid>,
    pub name: PotentialObject<String, ProtonDriveError>,
    pub name_author: PotentialObject<Author, SignatureVerificationError>,
    pub creation_time: DateTime<Utc>,
    pub trash_time: Option<DateTime<Utc>>,
    pub author: PotentialObject<Author, SignatureVerificationError>,
    pub owned_by: OwnedBy,
    pub errors: Vec<ProtonDriveError>,
}

#[derive(Debug, Clone)]
pub enum DegradedNodeAndSecrets {
    File(DegradedFileNode, DegradedFileSecrets),
    Folder(DegradedFolderNode, DegradedFolderSecrets),
}

impl DegradedNodeAndSecrets {
    pub fn try_get_file_else_folder(
        self,
    ) -> Result<(DegradedFileNode, DegradedFileSecrets), (DegradedFolderNode, DegradedFolderSecrets)>
    {
        match self {
            Self::File(n, s) => Ok((n, s)),
            Self::Folder(n, s) => Err((n, s)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DegradedNodeMetadata {
    pub inner: DegradedNodeAndSecrets,
    pub membership_share_id: Option<ShareId>,
    pub name_hash_digest: Vec<u8>,
}

impl DegradedNodeMetadata {
    pub fn from_file(m: DegradedFileMetadata) -> Self {
        Self {
            inner: DegradedNodeAndSecrets::File(m.node, m.secrets),
            membership_share_id: m.membership_share_id,
            name_hash_digest: m.name_hash_digest,
        }
    }

    pub fn from_folder(m: DegradedFolderMetadata) -> Self {
        Self {
            inner: DegradedNodeAndSecrets::Folder(m.node, m.secrets),
            membership_share_id: m.membership_share_id,
            name_hash_digest: m.name_hash_digest,
        }
    }

    pub fn node(&self) -> DegradedNode {
        match &self.inner {
            DegradedNodeAndSecrets::File(n, _) => DegradedNode::File(n.clone()),
            DegradedNodeAndSecrets::Folder(n, _) => DegradedNode::Folder(n.clone()),
        }
    }

    pub fn deconstruct(
        self,
    ) -> (
        DegradedNode,
        DegradedNodeAndSecrets,
        Option<ShareId>,
        Vec<u8>,
    ) {
        let node = self.node();
        (
            node,
            self.inner,
            self.membership_share_id,
            self.name_hash_digest,
        )
    }

    pub fn try_get_file_else_folder(
        self,
    ) -> Result<(DegradedFileNode, DegradedFileSecrets), (DegradedFolderNode, DegradedFolderSecrets)>
    {
        self.inner.try_get_file_else_folder()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(try_from = "String", into = "String")]
pub struct NodeUid {
    pub volume_id: VolumeId,
    pub link_id: LinkId,
}

#[derive(Debug)]
pub struct NodeMoveResult {
    pub uid: NodeUid,
    pub result: anyhow::Result<()>,
}

/// Outcome of copying one node; `result` holds the UID of the new copy.
#[derive(Debug)]
pub struct NodeCopyResult {
    pub uid: NodeUid,
    pub result: anyhow::Result<NodeUid>,
}

pub const PROTON_DOC_MEDIA_TYPE: &str = "application/vnd.proton.doc";
pub const PROTON_SHEET_MEDIA_TYPE: &str = "application/vnd.proton.sheet";

impl NodeUid {
    pub fn new(volume_id: VolumeId, link_id: LinkId) -> Self {
        Self { volume_id, link_id }
    }

    /// Builds a node UID from raw volume and link/node IDs (`volumeId~linkId`).
    pub fn from_parts(volume_id: impl Into<String>, link_id: impl Into<String>) -> Self {
        Self::new(VolumeId::new(volume_id.into()), LinkId::new(link_id.into()))
    }

    pub fn try_parse(s: &str) -> Option<Self> {
        let (volume, link) = s.split_once('~')?;
        Some(Self {
            volume_id: VolumeId::new(volume.to_string()),
            link_id: LinkId::new(link.to_string()),
        })
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        Self::try_parse(s).ok_or_else(|| format!("Invalid node UID format: \"{}\"", s))
    }

    pub fn raw(&self) -> String {
        format!("{}~{}", self.volume_id.raw(), self.link_id.raw())
    }
}

impl std::fmt::Display for NodeUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}~{}", self.volume_id.raw(), self.link_id.raw())
    }
}

impl From<NodeUid> for String {
    fn from(uid: NodeUid) -> Self {
        uid.to_string()
    }
}

impl TryFrom<String> for NodeUid {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        NodeUid::parse(&s)
    }
}

pub fn is_proton_document(media_type: Option<&str>) -> bool {
    media_type == Some(PROTON_DOC_MEDIA_TYPE)
}

pub fn is_proton_sheet(media_type: Option<&str>) -> bool {
    media_type == Some(PROTON_SHEET_MEDIA_TYPE)
}

/// Proton Drive / Docs web URL for a node, matching the JS SDK `getNodeUrl`.
pub fn node_web_url(
    share_id: &str,
    node_uid: &NodeUid,
    is_file: bool,
    media_type: Option<&str>,
) -> String {
    if is_proton_document(media_type) || is_proton_sheet(media_type) {
        let kind = if is_proton_document(media_type) {
            "doc"
        } else {
            "sheet"
        };
        return format!(
            "https://docs.proton.me/doc?type={}&mode=open&volumeId={}&linkId={}",
            kind,
            node_uid.volume_id.raw(),
            node_uid.link_id.raw()
        );
    }
    let kind = if is_file { "file" } else { "folder" };
    format!(
        "https://drive.proton.me/{}/{}/{}",
        share_id,
        kind,
        node_uid.link_id.raw()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_parts_round_trips() {
        let uid = NodeUid::from_parts("vol", "link");
        assert_eq!(uid.raw(), "vol~link");
        assert_eq!(NodeUid::parse("vol~link").unwrap(), uid);
    }

    #[test]
    fn node_web_url_docs_and_drive() {
        let uid = NodeUid::from_parts("vol", "link");
        assert_eq!(
            node_web_url("share", &uid, true, Some(PROTON_DOC_MEDIA_TYPE)),
            "https://docs.proton.me/doc?type=doc&mode=open&volumeId=vol&linkId=link"
        );
        assert_eq!(
            node_web_url("share", &uid, true, Some(PROTON_SHEET_MEDIA_TYPE)),
            "https://docs.proton.me/doc?type=sheet&mode=open&volumeId=vol&linkId=link"
        );
        assert_eq!(
            node_web_url("share", &uid, true, Some("text/plain")),
            "https://drive.proton.me/share/file/link"
        );
        assert_eq!(
            node_web_url("share", &uid, false, None),
            "https://drive.proton.me/share/folder/link"
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeType {
    Folder,
    File,
    Photo,
    Album,
}

impl Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Node {
    Folder(FolderNode),
    File(FileNode),
    Photo(FileNode),
    Album(FolderNode),
}

impl Node {
    pub fn uid(&self) -> &NodeUid {
        match self {
            Node::Folder(n) | Node::Album(n) => &n.base.uid,
            Node::File(n) | Node::Photo(n) => &n.base.base.uid,
        }
    }

    pub fn base(&self) -> &NodeBase {
        match self {
            Node::Folder(n) | Node::Album(n) => &n.base,
            Node::File(n) | Node::Photo(n) => &n.base.base,
        }
    }

    /// Returns the type of the current Node, in the case you do not want to match it.
    pub fn ty(&self) -> NodeType {
        match self {
            Node::Folder(_) => NodeType::Folder,
            Node::File(_) => NodeType::File,
            Node::Photo(_) => NodeType::Photo,
            Node::Album(_) => NodeType::Album,
        }
    }

    pub fn set_parent_uid(&mut self, parent_uid: Option<NodeUid>) {
        match self {
            Node::Folder(n) | Node::Album(n) => n.base.parent_uid = parent_uid,
            Node::File(n) | Node::Photo(n) => n.base.base.parent_uid = parent_uid,
        }
    }

    pub fn set_name(&mut self, name: String) {
        match self {
            Node::Folder(n) | Node::Album(n) => n.base.name = name,
            Node::File(n) | Node::Photo(n) => n.base.base.name = name,
        }
    }
}

// Conversions from specific node types to the `Node` enum
impl From<FolderNode> for Node {
    fn from(node: FolderNode) -> Self {
        Node::Folder(node)
    }
}

impl From<FileNode> for Node {
    fn from(node: FileNode) -> Self {
        Node::File(node)
    }
}

// Conversions to `NodeUid` for use with functions like `enumerate_folder_children`
impl From<&Node> for NodeUid {
    fn from(node: &Node) -> Self {
        node.uid().clone()
    }
}

impl From<Node> for NodeUid {
    fn from(node: Node) -> Self {
        node.uid().clone()
    }
}

impl From<&FolderNode> for NodeUid {
    fn from(node: &FolderNode) -> Self {
        node.base.uid.clone()
    }
}

impl From<FolderNode> for NodeUid {
    fn from(node: FolderNode) -> Self {
        node.base.uid
    }
}

impl From<&FileNode> for NodeUid {
    fn from(node: &FileNode) -> Self {
        node.base.base.uid.clone()
    }
}

impl From<FileNode> for NodeUid {
    fn from(node: FileNode) -> Self {
        node.base.base.uid
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeBase {
    pub uid: NodeUid,
    pub parent_uid: Option<NodeUid>,
    pub name: String,
    pub creation_time: DateTime<Utc>,
    pub trash_time: Option<DateTime<Utc>>,
    pub name_author: PotentialObject<Author, SignatureVerificationError>,
    pub author: PotentialObject<Author, SignatureVerificationError>,
    pub owned_by: Option<OwnedBy>,
    #[serde(default)]
    pub is_shared: bool,
    #[serde(default)]
    pub is_shared_by_url: bool,
    #[serde(default)]
    pub direct_role: NodeMemberRole,
    #[serde(default)]
    pub membership: Option<NodeMembership>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeMemberRole {
    #[default]
    Inherited,
    Viewer,
    Editor,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMembership {
    pub role: NodeMemberRole,
    pub invite_time: DateTime<Utc>,
    /// Who invited the user, verified by the inviter's signature of the
    /// member key packet.
    pub shared_by: PotentialObject<Author, SignatureVerificationError>,
    /// Which of the user's addresses accepted the invitation, verified by its
    /// signature of the share passphrase's session key. If it is degraded, the
    /// acceptance may be forged; the official clients warn before trusting
    /// the shared content, and do not hide it.
    #[serde(default = "membership_data_not_loaded")]
    pub accepted_by: PotentialObject<Author, SignatureVerificationError>,
}

const MEMBERSHIP_DATA_NOT_LOADED: &str = "Failed to load the membership data";

/// `accepted_by` of a membership cached before it was checked.
fn membership_data_not_loaded() -> PotentialObject<Author, SignatureVerificationError> {
    PotentialObject::Degraded(SignatureVerificationError {
        claimed_author: None,
        message: MEMBERSHIP_DATA_NOT_LOADED.into(),
    })
}

impl NodeBase {
    pub fn tree_event_scope_id(&self) -> String {
        self.uid.volume_id.raw().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSecrets {
    pub key: PgpPrivateKey,
    /// The decrypted passphrase bytes (plaintext of the NodePassphrase PGP message).
    pub passphrase_session_key: PgpSessionKey,
    /// The actual AES session key from the NodePassphrase PKESK packet, preserved for
    /// reuse during move operations (matches `passphraseSessionKey` in the JS SDK).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase_pgp_session_key: Option<PgpSessionKey>,
    pub name_session_key: PgpSessionKey,
    #[serde(rename = "passphrase")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passphrase_for_anonymous_move: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub enum NodeAndSecrets {
    File(FileNode, FileSecrets),
    Folder(FolderNode, FolderSecrets),
}

impl NodeAndSecrets {
    pub fn try_get_file_else_folder(
        self,
    ) -> Result<(FileNode, FileSecrets), (FolderNode, FolderSecrets)> {
        match self {
            Self::File(n, s) => Ok((n, s)),
            Self::Folder(n, s) => Err((n, s)),
        }
    }

    pub fn parent_uid(&self) -> Option<&NodeUid> {
        match self {
            Self::File(n, _) => n.base.base.parent_uid.as_ref(),
            Self::Folder(n, _) => n.base.parent_uid.as_ref(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeMetadata {
    pub inner: NodeAndSecrets,
    pub membership_share_id: Option<ShareId>,
    pub name_hash_digest: Vec<u8>,
}

impl NodeMetadata {
    pub fn from_file(m: FileMetadata) -> Self {
        Self {
            inner: NodeAndSecrets::File(m.node, m.secrets),
            membership_share_id: m.membership_share_id,
            name_hash_digest: m.name_hash_digest,
        }
    }

    pub fn from_folder(m: FolderMetadata) -> Self {
        Self {
            inner: NodeAndSecrets::Folder(m.node, m.secrets),
            membership_share_id: m.membership_share_id,
            name_hash_digest: m.name_hash_digest,
        }
    }

    pub fn node(&self) -> Node {
        match &self.inner {
            NodeAndSecrets::File(n, _) => Node::File(n.clone()),
            NodeAndSecrets::Folder(n, _) => Node::Folder(n.clone()),
        }
    }

    pub fn try_get_file_else_folder(
        self,
    ) -> Result<(FileNode, FileSecrets), (FolderNode, FolderSecrets)> {
        self.inner.try_get_file_else_folder()
    }

    pub fn deconstruct(self) -> (Node, NodeAndSecrets, Option<ShareId>, Vec<u8>) {
        let node = self.node();
        (
            node,
            self.inner,
            self.membership_share_id,
            self.name_hash_digest,
        )
    }
}

pub type NodeMetadataResult = PotentialObject<NodeMetadata, DegradedNodeMetadata>;

impl NodeMetadataResult {
    pub fn get_node_or_throw(self) -> anyhow::Result<Node> {
        let metadata = self.result()?;
        Ok(metadata.node())
    }

    pub fn get_folder_node_or_throw(self) -> anyhow::Result<FolderNode> {
        let metadata = self.result()?;
        match metadata.try_get_file_else_folder() {
            Ok((file, _)) => anyhow::bail!("Expected folder, got file: {}", file.base.base.uid),
            Err((folder, _)) => Ok(folder),
        }
    }

    pub fn get_folder_secrets_or_throw(self) -> anyhow::Result<FolderSecrets> {
        let metadata = self.result()?;
        match metadata.try_get_file_else_folder() {
            Ok((file, _)) => anyhow::bail!("Expected folder, got file: {}", file.base.base.uid),
            Err((_, secrets)) => Ok(secrets),
        }
    }

    pub fn try_get_folder_secrets_else_error(self) -> anyhow::Result<FolderSecrets> {
        match self {
            PotentialObject::Node(m) => match m.inner {
                crate::node::NodeAndSecrets::File(_, _) => {
                    anyhow::bail!("Node is a file, not a folder")
                }
                crate::node::NodeAndSecrets::Folder(_, s) => Ok(s),
            },
            PotentialObject::Degraded(_) => {
                anyhow::bail!("Degraded node has no folder secrets")
            }
        }
    }

    pub fn to_secrets_result(
        self,
    ) -> PotentialObject<NodeSecrets, crate::node::secrets::DegradedNodeSecrets> {
        match self {
            PotentialObject::Node(m) => {
                let secrets = match m.inner {
                    NodeAndSecrets::File(_, s) => s.base,
                    NodeAndSecrets::Folder(_, s) => s.base,
                };
                PotentialObject::Node(secrets)
            }
            PotentialObject::Degraded(m) => {
                let secrets = match m.inner {
                    crate::node::DegradedNodeAndSecrets::File(_, s) => s.base,
                    crate::node::DegradedNodeAndSecrets::Folder(_, s) => s.base,
                };
                PotentialObject::Degraded(secrets)
            }
        }
    }

    pub fn to_node_result(self) -> PotentialObject<Node, DegradedNode> {
        match self {
            PotentialObject::Node(m) => PotentialObject::Node(m.node()),
            PotentialObject::Degraded(m) => PotentialObject::Degraded(m.node()),
        }
    }
}

pub struct NodeBatchLoader {
    inner: crate::utils::batch::BatchLoaderBase<
        crate::links::LinkId,
        PotentialObject<Node, DegradedNode>,
        NodeBatchLoaderImpl,
    >,
}

struct NodeBatchLoaderImpl {
    client: std::sync::Arc<ProtonDriveClient>,
    volume_id: VolumeId,
    parent_key: Option<crate::pgp::PgpPrivateKey>,
}

#[async_trait]
impl crate::utils::batch::BatchLoader<crate::links::LinkId, PotentialObject<Node, DegradedNode>>
    for NodeBatchLoaderImpl
{
    async fn load_batch(
        &self,
        ids: Vec<crate::links::LinkId>,
    ) -> anyhow::Result<Vec<PotentialObject<Node, DegradedNode>>> {
        let response = self
            .client
            .api()
            .links()
            .get_details(self.volume_id.clone(), ids)
            .await?;

        let client = self.client.clone();
        let volume_id = self.volume_id.clone();
        let parent_key = self.parent_key.clone();

        let mut futs: FuturesUnordered<_> = response
            .links
            .into_iter()
            .map(|link_details| {
                let c = client.clone();
                let vid = volume_id.clone();
                let pk = parent_key.clone();
                async move {
                    DtoToMetadataConverter::convert_dto_to_node_metadata_with_client(
                        &c,
                        vid,
                        link_details,
                        pk.as_ref(),
                    )
                    .await
                    .map(|r| r.to_node_result())
                }
            })
            .collect();

        let mut results = Vec::new();
        while let Some(result) = futs.next().await {
            results.push(result?);
        }

        Ok(results)
    }
}

impl NodeBatchLoader {
    pub fn new(
        client: std::sync::Arc<ProtonDriveClient>,
        volume_id: VolumeId,
        parent_key: Option<crate::pgp::PgpPrivateKey>,
    ) -> Self {
        Self {
            inner: crate::utils::batch::BatchLoaderBase::new(
                NodeBatchLoaderImpl {
                    client,
                    volume_id,
                    parent_key,
                },
                50,
            ),
        }
    }

    pub async fn queue_and_try_load_batch(
        &mut self,
        id: crate::links::LinkId,
    ) -> anyhow::Result<Vec<PotentialObject<Node, DegradedNode>>> {
        self.inner.queue_and_try_load_batch(id).await
    }

    pub async fn load_remaining(
        &mut self,
    ) -> anyhow::Result<Vec<PotentialObject<Node, DegradedNode>>> {
        self.inner.load_remaining().await
    }
}

pub struct VolumeTrashBatchLoader {
    inner: crate::utils::batch::BatchLoaderBase<
        crate::links::LinkId,
        PotentialObject<Node, DegradedNode>,
        VolumeTrashBatchLoaderImpl,
    >,
}

struct VolumeTrashBatchLoaderImpl {
    client: std::sync::Arc<ProtonDriveClient>,
    volume_id: VolumeId,
    share_key: crate::pgp::PgpPrivateKey,
    parent_keys: tokio::sync::Mutex<
        std::collections::HashMap<crate::links::LinkId, crate::pgp::PgpPrivateKey>,
    >,
}

#[async_trait]
impl crate::utils::batch::BatchLoader<crate::links::LinkId, PotentialObject<Node, DegradedNode>>
    for VolumeTrashBatchLoaderImpl
{
    async fn load_batch(
        &self,
        ids: Vec<crate::links::LinkId>,
    ) -> anyhow::Result<Vec<PotentialObject<Node, DegradedNode>>> {
        let response = self
            .client
            .api()
            .links()
            .get_details(self.volume_id.clone(), ids.clone())
            .await?;

        // Collect unique parent IDs that are not yet cached.
        let mut missing_parent_ids: Vec<crate::links::LinkId> = {
            let parent_keys = self.parent_keys.lock().await;
            response
                .links
                .iter()
                .filter_map(|ld| ld.link.parent_id.clone())
                .filter(|pid| !parent_keys.contains_key(pid))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect()
        };

        // Fetch all missing parent secrets in parallel.
        if !missing_parent_ids.is_empty() {
            let mut fetch_futs: FuturesUnordered<_> = missing_parent_ids
                .drain(..)
                .map(|parent_id| {
                    let client = self.client.clone();
                    let volume_id = self.volume_id.clone();
                    async move {
                        let secrets = crate::node::folder::FolderOperations::get_secrets(
                            &client,
                            NodeUid::new(volume_id, parent_id.clone()),
                        )
                        .await?;
                        anyhow::Ok((parent_id, secrets.base.key))
                    }
                })
                .collect();

            let mut parent_keys = self.parent_keys.lock().await;
            while let Some(result) = fetch_futs.next().await {
                let (id, key) = result?;
                parent_keys.entry(id).or_insert(key);
            }
        }

        // Now decrypt all links in parallel (parent keys are all cached).
        let client = self.client.clone();
        let volume_id = self.volume_id.clone();
        let share_key = self.share_key.clone();

        let mut decrypt_futs: FuturesUnordered<_> = {
            let parent_keys = self.parent_keys.lock().await;
            response
                .links
                .into_iter()
                .map(|link_details| {
                    let parent_key = if let Some(pid) = &link_details.link.parent_id {
                        parent_keys
                            .get(pid)
                            .cloned()
                            .unwrap_or_else(|| share_key.clone())
                    } else {
                        share_key.clone()
                    };
                    let c = client.clone();
                    let vid = volume_id.clone();
                    async move {
                        DtoToMetadataConverter::convert_dto_to_node_metadata_with_client(
                            &c,
                            vid,
                            link_details,
                            Some(&parent_key),
                        )
                        .await
                        .map(|r| r.to_node_result())
                    }
                })
                .collect()
        };

        let mut results = Vec::new();
        while let Some(result) = decrypt_futs.next().await {
            results.push(result?);
        }

        Ok(results)
    }
}

impl VolumeTrashBatchLoader {
    pub fn new(
        client: std::sync::Arc<ProtonDriveClient>,
        volume_id: VolumeId,
        share_key: crate::pgp::PgpPrivateKey,
    ) -> Self {
        Self {
            inner: crate::utils::batch::BatchLoaderBase::new(
                VolumeTrashBatchLoaderImpl {
                    client,
                    volume_id,
                    share_key,
                    parent_keys: tokio::sync::Mutex::new(std::collections::HashMap::new()),
                },
                50,
            ),
        }
    }

    pub async fn queue_and_try_load_batch(
        &mut self,
        id: crate::links::LinkId,
    ) -> anyhow::Result<Vec<PotentialObject<Node, DegradedNode>>> {
        self.inner.queue_and_try_load_batch(id).await
    }

    pub async fn load_remaining(
        &mut self,
    ) -> anyhow::Result<Vec<PotentialObject<Node, DegradedNode>>> {
        self.inner.load_remaining().await
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OwnedBy {
    pub email: Option<String>,
    pub organisation: Option<String>,
}

pub struct DtoToMetadataConverter;

impl DtoToMetadataConverter {
    pub async fn get_fresh_node_metadata(
        client: &ProtonDriveClient,
        uid: crate::node::NodeUid,
        known_share_and_key: Option<ShareAndKey>,
    ) -> anyhow::Result<NodeMetadataResult> {
        let response = client
            .api()
            .links()
            .get_details(uid.volume_id.clone(), vec![uid.link_id.clone()])
            .await?;

        if response.links.is_empty() {
            anyhow::bail!("Node not found: {}", uid);
        }

        let link_details = response.links[0].clone();
        let parent_key = if let Some(share) = known_share_and_key {
            Some(share.key)
        } else {
            Self::resolve_parent_key(client, uid.volume_id.clone(), &link_details).await?
        };

        let metadata = Self::convert_dto_to_node_metadata_with_client(
            client,
            uid.volume_id.clone(),
            link_details,
            parent_key.as_ref(),
        )
        .await?;

        // Cache the metadata and secrets
        if let PotentialObject::Node(m) = &metadata {
            client
                .cache()
                .entities()
                .set_node(
                    m.node().uid().clone(),
                    metadata.clone().to_node_result(),
                    m.membership_share_id.clone(),
                    m.name_hash_digest.clone(),
                )
                .await?;
            match &m.inner {
                NodeAndSecrets::Folder(_, secrets) => {
                    client
                        .cache()
                        .secrets()
                        .set_folder_secrets(
                            m.node().uid().clone(),
                            PotentialObject::Node(secrets.clone()),
                        )
                        .await?;
                }
                NodeAndSecrets::File(_, secrets) => {
                    client
                        .cache()
                        .secrets()
                        .set_file_secrets(
                            m.node().uid().clone(),
                            PotentialObject::Node(secrets.clone()),
                        )
                        .await?;
                }
            }
        }

        Ok(metadata)
    }

    async fn resolve_parent_key(
        client: &ProtonDriveClient,
        volume_id: VolumeId,
        link_details: &crate::api::links::LinkDetailsDto,
    ) -> anyhow::Result<Option<PgpPrivateKey>> {
        if let Some(parent_id) = &link_details.link.parent_id {
            let parent_uid = NodeUid::new(volume_id, parent_id.clone());
            let secrets = Box::pin(crate::node::folder::FolderOperations::get_secrets(
                client, parent_uid,
            ))
            .await?;
            return Ok(Some(secrets.base.key));
        }

        let share_id = match &link_details.sharing {
            Some(sharing) => Some(sharing.share_id.clone()),
            None => {
                client
                    .cache()
                    .entities()
                    .try_get_my_files_share_id()
                    .await?
            }
        };
        if let Some(share_id) = share_id {
            let share_and_key =
                crate::share_ops::ShareOperations::get_share(client, share_id).await?;
            return Ok(Some(share_and_key.key));
        }

        Ok(None)
    }

    pub async fn convert_dto_to_node_metadata_with_client(
        client: &ProtonDriveClient,
        volume_id: VolumeId,
        link_details: crate::api::links::LinkDetailsDto,
        parent_key: Option<&PgpPrivateKey>,
    ) -> anyhow::Result<NodeMetadataResult> {
        Self::convert_dto_to_node_metadata_inner(
            client.account().clone(),
            client.cache().entities().as_ref(),
            client.cache().secrets().as_ref(),
            volume_id,
            link_details,
            parent_key,
            Some(client),
        )
        .await
    }

    pub async fn convert_dto_to_node_metadata(
        account_client: std::sync::Arc<dyn crate::account::AccountClient>,
        _entity_cache: &dyn crate::cache::entity::DriveEntityCache,
        _secret_cache: &dyn crate::cache::secret::DriveSecretCache,
        _volume_id: crate::volume::VolumeId,
        link_details: crate::api::links::LinkDetailsDto,
        parent_key: Option<&PgpPrivateKey>,
    ) -> anyhow::Result<NodeMetadataResult> {
        Self::convert_dto_to_node_metadata_inner(
            account_client,
            _entity_cache,
            _secret_cache,
            _volume_id,
            link_details,
            parent_key,
            None,
        )
        .await
    }

    async fn convert_dto_to_node_metadata_inner(
        account_client: std::sync::Arc<dyn crate::account::AccountClient>,
        _entity_cache: &dyn crate::cache::entity::DriveEntityCache,
        _secret_cache: &dyn crate::cache::secret::DriveSecretCache,
        _volume_id: crate::volume::VolumeId,
        link_details: crate::api::links::LinkDetailsDto,
        parent_key: Option<&PgpPrivateKey>,
        metric_client: Option<&ProtonDriveClient>,
    ) -> anyhow::Result<NodeMetadataResult> {
        let link_dto = link_details.link.clone();
        let is_shared = link_details.sharing.is_some();
        let is_shared_by_url = link_details
            .sharing
            .as_ref()
            .is_some_and(|sharing| sharing.share_url_id.is_some());
        let metric_item = crate::telemetry::MetricItem::from_link(_volume_id.clone(), &link_dto);
        let (direct_role, membership) = Self::build_membership_info(
            account_client.clone(),
            _entity_cache,
            &_volume_id,
            link_details.membership.as_ref(),
        )
        .await?;
        if let (Some(client), Some(membership), Some(dto)) = (
            metric_client,
            membership.as_ref(),
            link_details.membership.as_ref(),
        ) {
            for (field, author) in [
                ("membershipInviter", &membership.shared_by),
                ("membershipInvitee", &membership.accepted_by),
            ] {
                let PotentialObject::Degraded(error) = author else {
                    continue;
                };
                // Shown, not refused, as the official clients do; logged once
                // per node and field.
                if client
                    .integrity_reporter()
                    .first_warning(&metric_item.uid, field)
                {
                    tracing::warn!(
                        node = %metric_item.uid,
                        field,
                        error = %error.message,
                        "Failed to verify the membership of a shared node"
                    );
                }
                let item = crate::telemetry::MetricItem {
                    uid: metric_item.uid.clone(),
                    creation_time: Some(dto.invite_time),
                    third_party: None,
                    sdk: None,
                };
                client
                    .integrity_reporter()
                    .report_unchecked(client, &item, field, Some(&error.message), true, None)
                    .await;
            }
        }
        let parent_key_result: Result<Vec<PgpPrivateKey>, String> = match parent_key {
            Some(k) => Ok(vec![k.clone()]),
            None => {
                // Try to find parent key from cache
                if let Some(parent_id) = &link_dto.parent_id {
                    tracing::debug!(parent_link_id = %parent_id.raw(), "Looking up parent folder key");
                    let parent_uid = NodeUid::new(_volume_id.clone(), parent_id.clone());
                    if let Some(secrets) = _secret_cache.try_get_folder_secrets(parent_uid).await? {
                        match secrets {
                            PotentialObject::Node(s) => {
                                tracing::debug!("Found parent folder key in cache");
                                Ok(vec![s.base.key])
                            }
                            PotentialObject::Degraded(_) => {
                                tracing::debug!("Parent folder key is degraded");
                                Err("Parent folder key is degraded".to_string())
                            }
                        }
                    } else {
                        tracing::debug!(
                            parent_link_id = %parent_id.raw(),
                            "Parent folder key NOT found in cache"
                        );
                        Err(format!(
                            "Parent folder key for {:?} not found in cache",
                            parent_id
                        ))
                    }
                } else {
                    // Root folder - need share key
                    tracing::debug!("Looking up share key for root folder");
                    if let Some(sharing) = &link_details.sharing {
                        if let Some(share_key) = _secret_cache
                            .try_get_share_key(sharing.share_id.clone())
                            .await?
                        {
                            tracing::debug!(
                                share_id = %sharing.share_id.raw(),
                                "Found share key in cache"
                            );
                            Ok(vec![share_key])
                        } else {
                            tracing::debug!(
                                share_id = %sharing.share_id.raw(),
                                "Share key NOT found in cache"
                            );
                            Err(format!(
                                "Share key for {:?} not found in cache",
                                sharing.share_id
                            ))
                        }
                    } else {
                        // Fallback to My Files share?
                        if let Some(share_id) = _entity_cache.try_get_my_files_share_id().await? {
                            tracing::debug!(
                                share_id = %share_id.raw(),
                                "Falling back to My Files share key"
                            );
                            if let Some(share_key) =
                                _secret_cache.try_get_share_key(share_id).await?
                            {
                                Ok(vec![share_key])
                            } else {
                                Err("My Files share key not found in cache".to_string())
                            }
                        } else {
                            tracing::debug!(
                                "No parent key, no sharing, and no My Files fallback available"
                            );
                            Err("Parent key not provided and no sharing info available".to_string())
                        }
                    }
                }
            }
        };

        let had_parent_key = parent_key_result.is_ok();
        match link_dto.r#type {
            crate::api::links::LinkType::Folder | crate::api::links::LinkType::Album => {
                let folder_dto = link_details
                    .folder
                    .clone()
                    .or(link_details.album.clone())
                    .ok_or_else(|| anyhow::anyhow!("Folder DTO missing"))?;
                let decryption = crate::node::crypto::NodeCrypto::decrypt_folder(
                    account_client,
                    &link_dto,
                    folder_dto.hash_key.as_ref(),
                    parent_key_result,
                )
                .await;

                if let Some(client) = metric_client {
                    let reporter = client.integrity_reporter();
                    reporter
                        .report_link(
                            client,
                            &metric_item,
                            &decryption.link,
                            had_parent_key,
                            link_dto.name_signature_email_address.as_deref(),
                        )
                        .await;
                    reporter
                        .report_output(
                            client,
                            &metric_item,
                            "nodeHashKey",
                            &decryption.hash_key,
                            link_dto.signature_email_address.as_deref(),
                        )
                        .await;
                }

                let uid = NodeUid::new(_volume_id.clone(), link_dto.id.clone());
                let parent_uid = link_dto
                    .parent_id
                    .map(|id| NodeUid::new(_volume_id.clone(), id));

                if let (Ok(name), Ok(_hash_key), Ok(node_key)) = (
                    &decryption.link.name,
                    &decryption.hash_key,
                    &decryption.link.node_key,
                ) {
                    let node_base = NodeBase {
                        uid: uid.clone(),
                        parent_uid,
                        name: name.data.clone(),
                        creation_time: link_dto.creation_time,
                        trash_time: link_dto.trash_time,
                        name_author: PotentialObject::Node(crate::author::Author {
                            email_address: link_dto.name_signature_email_address.clone(),
                        }),
                        author: PotentialObject::Node(crate::author::Author {
                            email_address: link_dto.signature_email_address.clone(),
                        }),
                        owned_by: link_dto.owned_by.as_ref().map(|o| OwnedBy {
                            email: o.email.clone(),
                            organisation: o.organization.clone(),
                        }),
                        is_shared,
                        is_shared_by_url,
                        direct_role,
                        membership: membership.clone(),
                    };

                    let passphrase_decryption_output = decryption.link.passphrase.map_err(|e| {
                        anyhow::anyhow!("Failed to decrypt folder passphrase: {}", e)
                    })?;
                    let passphrase_session_key = passphrase_decryption_output.data.clone();
                    let passphrase_pgp_session_key =
                        passphrase_decryption_output
                            .session_key
                            .map(|sk| PgpSessionKey {
                                algorithm: u8::from(sk.algorithm().unwrap_or(
                                    proton_rpgp::pgp::crypto::sym::SymmetricKeyAlgorithm::AES256,
                                )),
                                key: sk.as_ref().to_vec(),
                            });

                    let is_anonymous = link_dto.signature_email_address.is_none();
                    let secrets = FolderSecrets {
                        base: NodeSecrets {
                            key: node_key.clone(),
                            passphrase_session_key: passphrase_session_key.clone(),
                            passphrase_pgp_session_key: passphrase_pgp_session_key.clone(),
                            name_session_key: name.session_key.as_ref().map(|sk| PgpSessionKey {
                                algorithm: u8::from(sk.algorithm().unwrap_or(proton_rpgp::pgp::crypto::sym::SymmetricKeyAlgorithm::AES128)),
                                key: sk.as_ref().to_vec(),
                            }).unwrap_or_else(|| PgpSessionKey { algorithm: 9, key: vec![0; 32] }),
                            passphrase_for_anonymous_move: if is_anonymous { Some(passphrase_session_key.key) } else { None },
                        },
                        hash_key: _hash_key.data.clone(),
                    };

                    Ok(PotentialObject::Node(NodeMetadata {
                        inner: NodeAndSecrets::Folder(FolderNode { base: node_base }, secrets),
                        membership_share_id: link_details
                            .sharing
                            .as_ref()
                            .map(|s| s.share_id.clone()),
                        name_hash_digest: link_dto.name_hash_digest,
                    }))
                } else {
                    Err(anyhow::anyhow!("Decryption failed for folder"))
                }
            }
            crate::api::links::LinkType::File => {
                // Photo nodes in the Photos volume carry their file metadata in the
                // `photo` field (PhotoDto) rather than the `file` field (FileDto).
                // PhotoDto.base IS a FileDto via `#[serde(flatten)]`, so we can
                // use it directly as a fallback.
                let photo_dto_base = link_details.photo.map(|p| p.base);
                let file_dto = link_details
                    .file
                    .or(photo_dto_base)
                    .ok_or_else(|| anyhow::anyhow!("File DTO missing"))?;

                let parent_err = parent_key_result.as_ref().err().cloned();
                let decryption = crate::node::crypto::NodeCrypto::decrypt_file(
                    account_client,
                    &link_dto,
                    &file_dto,
                    parent_key_result,
                )
                .await;

                if let Some(client) = metric_client {
                    let reporter = client.integrity_reporter();
                    reporter
                        .report_link(
                            client,
                            &metric_item,
                            &decryption.link,
                            had_parent_key,
                            link_dto.name_signature_email_address.as_deref(),
                        )
                        .await;
                    reporter
                        .report_output(
                            client,
                            &metric_item,
                            "nodeContentKey",
                            &decryption.content_key,
                            link_dto.signature_email_address.as_deref(),
                        )
                        .await;
                }

                let uid = NodeUid::new(_volume_id.clone(), link_dto.id.clone());
                if let (Some(client), Some(revision), Ok(key)) = (
                    metric_client,
                    file_dto.active_revision.as_ref(),
                    &decryption.link.node_key,
                ) {
                    client
                        .integrity_reporter()
                        .report_active_revision_attributes(
                            client,
                            &uid,
                            revision,
                            key,
                            &decryption.content_authorship_claim,
                        )
                        .await;
                }
                let parent_uid = link_dto.parent_id.map(|id| NodeUid::new(_volume_id, id));

                let name_err = decryption.link.name.as_ref().err().cloned();
                let content_err = decryption.content_key.as_ref().err().cloned();
                let node_err = decryption.link.node_key.as_ref().err().cloned();

                if let (Ok(name), Ok(_content_key), Ok(node_key)) = (
                    decryption.link.name,
                    decryption.content_key,
                    decryption.link.node_key,
                ) {
                    let node_base = NodeBase {
                        uid: uid.clone(),
                        parent_uid,
                        name: name.data,
                        creation_time: link_dto.creation_time,
                        trash_time: link_dto.trash_time,
                        name_author: PotentialObject::Node(crate::author::Author {
                            email_address: link_dto.name_signature_email_address.clone(),
                        }),
                        author: PotentialObject::Node(crate::author::Author {
                            email_address: link_dto.signature_email_address.clone(),
                        }),
                        owned_by: link_dto.owned_by.as_ref().map(|o| OwnedBy {
                            email: o.email.clone(),
                            organisation: o.organization.clone(),
                        }),
                        is_shared,
                        is_shared_by_url,
                        direct_role,
                        membership,
                    };

                    let passphrase_decryption_output = decryption
                        .link
                        .passphrase
                        .map_err(|e| anyhow::anyhow!("Failed to decrypt file passphrase: {}", e))?;
                    let passphrase_session_key = passphrase_decryption_output.data.clone();
                    let passphrase_pgp_session_key =
                        passphrase_decryption_output
                            .session_key
                            .map(|sk| PgpSessionKey {
                                algorithm: u8::from(sk.algorithm().unwrap_or(
                                    proton_rpgp::pgp::crypto::sym::SymmetricKeyAlgorithm::AES256,
                                )),
                                key: sk.as_ref().to_vec(),
                            });

                    let is_anonymous = link_dto.signature_email_address.is_none();
                    let secrets = FileSecrets {
                        base: NodeSecrets {
                            key: node_key.clone(),
                            passphrase_session_key: passphrase_session_key.clone(),
                            passphrase_pgp_session_key: passphrase_pgp_session_key.clone(),
                            name_session_key: name.session_key.as_ref().map(|sk| PgpSessionKey {
                                algorithm: u8::from(sk.algorithm().unwrap_or(proton_rpgp::pgp::crypto::sym::SymmetricKeyAlgorithm::AES128)),
                                key: sk.as_ref().to_vec(),
                            }).unwrap_or_else(|| PgpSessionKey { algorithm: 9, key: vec![0; 32] }),
                            passphrase_for_anonymous_move: if is_anonymous { Some(passphrase_session_key.key) } else { None },
                        },
                        content_key: _content_key.data,
                    };

                    Ok(PotentialObject::Node(NodeMetadata {
                        inner: NodeAndSecrets::File(
                            FileNode {
                                base: FileOrFileDraftNode {
                                    base: node_base,
                                    media_type: file_dto.media_type.clone(),
                                },
                                active_revision: crate::node::revision::Revision {
                                    uid: crate::node::revision::RevisionUid {
                                        node_uid: uid.clone(),
                                        revision_id: file_dto
                                            .active_revision
                                            .as_ref()
                                            .map(|r| r.id.clone())
                                            .unwrap_or_default(),
                                    },
                                    creation_time: file_dto
                                        .active_revision
                                        .as_ref()
                                        .map(|r| r.creation_time)
                                        .unwrap_or_else(|| Utc::now()),
                                    size_on_cloud_storage: file_dto
                                        .active_revision
                                        .as_ref()
                                        .map(|r| r.storage_quota_consumption)
                                        .unwrap_or(0),
                                    claimed_size: Some(
                                        file_dto
                                            .active_revision
                                            .as_ref()
                                            .map(|r| r.storage_quota_consumption)
                                            .unwrap_or(0),
                                    ),
                                    claimed_digests: crate::node::file::FileContentDigests {
                                        sha1: None,
                                    },
                                    claimed_modification_time: Some(
                                        file_dto
                                            .active_revision
                                            .as_ref()
                                            .map(|r| r.creation_time)
                                            .unwrap_or_else(|| Utc::now()),
                                    ),
                                    thumbnails: file_dto
                                        .active_revision
                                        .as_ref()
                                        .map(|r| {
                                            #[allow(deprecated)]
                                            r.thumbnails
                                                .iter()
                                                .map(|t| crate::protobuf::ThumbnailHeader {
                                                    id: t.id.clone(),
                                                    r#type: t.r#type as i32,
                                                })
                                                .collect()
                                        })
                                        .unwrap_or_default(),
                                    additional_claimed_metadata: None,
                                    content_author: Some(
                                        decryption.content_authorship_claim.to_potential_author(),
                                    ),
                                },
                                total_size_on_cloud_storage: file_dto.total_size_on_storage,
                            },
                            secrets,
                        ),
                        membership_share_id: link_details
                            .sharing
                            .as_ref()
                            .map(|s| s.share_id.clone()),
                        name_hash_digest: link_dto.name_hash_digest,
                    }))
                } else {
                    Err(anyhow::anyhow!(
                        "Decryption failed for file parent_key={:?} name={:?} content={:?} node={:?}",
                        parent_err,
                        name_err,
                        content_err,
                        node_err
                    ))
                }
            }
        }
    }

    async fn build_membership_info(
        account: std::sync::Arc<dyn crate::account::AccountClient>,
        entity_cache: &dyn crate::cache::entity::DriveEntityCache,
        volume_id: &VolumeId,
        dto: Option<&crate::api::share::ShareMembershipSummaryDto>,
    ) -> anyhow::Result<(NodeMemberRole, Option<NodeMembership>)> {
        let own_volume = entity_cache.try_get_main_volume_id().await?.as_ref() == Some(volume_id)
            || entity_cache.try_get_photos_volume_id().await?.as_ref() == Some(volume_id);
        let role = dto.map_or(NodeMemberRole::Inherited, |membership| {
            if membership
                .permissions
                .contains(crate::api::share::ShareMemberPermissions::ADMIN)
            {
                NodeMemberRole::Admin
            } else if membership
                .permissions
                .contains(crate::api::share::ShareMemberPermissions::WRITE)
            {
                NodeMemberRole::Editor
            } else {
                NodeMemberRole::Viewer
            }
        });
        let direct_role = if own_volume {
            NodeMemberRole::Admin
        } else {
            role
        };
        let Some(dto) = dto else {
            return Ok((direct_role, None));
        };

        let (claim, accepted_by) = futures::join!(
            crate::node::authorship::AuthorshipClaim::create(
                account.clone(),
                dto.inviter_email_address.as_deref(),
            ),
            Self::verify_membership_acceptance(account.as_ref(), dto),
        );
        let verified = match (
            dto.member_share_passphrase_key_packet.as_ref(),
            dto.inviter_share_passphrase_key_packet_signature.as_ref(),
        ) {
            (Some(packet), Some(signature)) if !claim.keys.is_empty() => {
                proton_rpgp::Verifier::default()
                    .with_verification_keys(claim.keys.iter())
                    .with_verification_context(proton_rpgp::VerificationContext::new_required(
                        "drive.share-member.inviter".into(),
                    ))
                    .verify_detached(
                        packet,
                        signature.0.as_bytes(),
                        proton_rpgp::DataEncoding::Armored,
                    )
                    .is_ok()
            }
            _ => false,
        };
        let shared_by = if verified {
            PotentialObject::Node(claim.author)
        } else {
            PotentialObject::Degraded(SignatureVerificationError {
                claimed_author: Some(crate::protobuf::Author {
                    email_address: claim.author.email_address.unwrap_or_default(),
                }),
                message: "membership inviter signature could not be verified".into(),
            })
        };
        Ok((
            direct_role,
            Some(NodeMembership {
                role,
                invite_time: dto.invite_time,
                shared_by,
                accepted_by,
            }),
        ))
    }

    /// Checks the member's acceptance of the invitation as the JS SDK does
    /// (`verifyMembershipInvitee`): the member key packet is decrypted with
    /// the keys of the accepting address (`AddressID`), and the acceptance
    /// signature over its session key is verified with that address's public
    /// keys in the `drive.share-member.member` context.
    async fn verify_membership_acceptance(
        account: &dyn crate::account::AccountClient,
        dto: &crate::api::share::ShareMembershipSummaryDto,
    ) -> PotentialObject<Author, SignatureVerificationError> {
        let degraded = |claimed_author: Option<&str>, message: &str| {
            PotentialObject::Degraded(SignatureVerificationError {
                claimed_author: claimed_author.map(|email| crate::protobuf::Author {
                    email_address: email.to_owned(),
                }),
                message: message.into(),
            })
        };
        let (Some(address_id), Some(packet), Some(signature)) = (
            dto.address_id.as_ref(),
            dto.member_share_passphrase_key_packet.as_ref(),
            dto.invitee_share_passphrase_session_key_signature.as_ref(),
        ) else {
            return degraded(None, MEMBERSHIP_DATA_NOT_LOADED);
        };

        let (email, decryption_keys) = match futures::try_join!(
            account.get_address(address_id),
            account.get_address_private_keys(address_id),
        ) {
            Ok((address, keys)) => (address.email_address, keys),
            Err(error) => {
                tracing::debug!(error = %error, "Failed to get the invitee's address keys");
                return degraded(None, "Failed to get invitee keys");
            }
        };
        let verification_keys = match account.get_address_public_keys(&email).await {
            Ok(keys) => keys,
            Err(error) => {
                tracing::debug!(error = %error, "Failed to get the invitee's public keys");
                return degraded(Some(&email), "Failed to get invitee keys");
            }
        };
        let Some(session_key) = decryption_keys.iter().find_map(|key| {
            crate::pgp::PgpPrivateKey(key.clone())
                .decrypt_session_key(packet)
                .ok()
        }) else {
            return degraded(Some(&email), "Failed to verify membership");
        };
        let verified = !verification_keys.is_empty()
            && proton_rpgp::Verifier::default()
                .with_verification_keys(verification_keys.iter())
                .with_verification_context(proton_rpgp::VerificationContext::new_required(
                    crate::sharing::SIGNING_MEMBER.into(),
                ))
                .verify_detached(
                    &session_key.key,
                    signature.0.as_bytes(),
                    proton_rpgp::DataEncoding::Armored,
                )
                .is_ok();
        if verified {
            PotentialObject::Node(Author {
                email_address: Some(email),
            })
        } else {
            degraded(
                Some(&email),
                "membership acceptance signature could not be verified",
            )
        }
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;
    use crate::account::{AccountClient, AddressId};
    use crate::api::share::ShareMembershipSummaryDto;
    use crate::crypto::CryptoGenerator;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use proton_rpgp::{DataEncoding, PublicKey, SignatureContext, Signer};
    use proton_sdk_rs2::protobuf::Address;

    const INVITEE: &str = "invitee@example.test";

    /// The member's own address `address` and the public keys of `INVITEE`.
    struct Invitee {
        key: PgpPrivateKey,
        published: Vec<PublicKey>,
        address_keys_fail: bool,
    }

    #[async_trait]
    impl AccountClient for Invitee {
        async fn get_address(&self, id: &AddressId) -> anyhow::Result<Address> {
            anyhow::ensure!(id.raw() == "address", "unknown address");
            Ok(Address {
                address_id: id.raw().into(),
                email_address: INVITEE.into(),
                ..Default::default()
            })
        }

        async fn get_default_address(&self) -> anyhow::Result<Address> {
            unreachable!()
        }

        async fn get_address_primary_private_key(
            &self,
            _: &AddressId,
        ) -> anyhow::Result<proton_rpgp::PrivateKey> {
            unreachable!()
        }

        async fn get_address_private_keys(
            &self,
            id: &AddressId,
        ) -> anyhow::Result<Vec<proton_rpgp::PrivateKey>> {
            anyhow::ensure!(!self.address_keys_fail, "keys unavailable");
            anyhow::ensure!(id.raw() == "address", "unknown address");
            Ok(vec![self.key.0.clone()])
        }

        async fn get_address_public_keys(&self, email: &str) -> anyhow::Result<Vec<PublicKey>> {
            anyhow::ensure!(email == INVITEE, "unknown email");
            Ok(self.published.clone())
        }

        async fn get_user_keys(&self) -> anyhow::Result<Vec<proton_rpgp::PrivateKey>> {
            unreachable!()
        }

        async fn get_user_storage_info(&self) -> anyhow::Result<(i64, i64)> {
            unreachable!()
        }
    }

    fn invitee() -> Invitee {
        let key = CryptoGenerator::generate_private_key().unwrap();
        Invitee {
            published: vec![PublicKey::from(&key.0)],
            key,
            address_keys_fail: false,
        }
    }

    /// A membership whose key packet is for `invitee`, its session key signed
    /// by `signer` in `context` (as `accept_invitation` signs it).
    fn membership(
        invitee: &Invitee,
        signer: &PgpPrivateKey,
        context: &str,
        address_id: Option<&str>,
    ) -> ShareMembershipSummaryDto {
        let session_key = CryptoGenerator::generate_session_key();
        let packet = invitee.key.encrypt_session_key(&session_key).unwrap();
        let signature = Signer::default()
            .at_date(crate::server_time::check_now())
            .with_signing_key(&signer.0)
            .with_signature_context(SignatureContext::new(context.into(), true))
            .sign_detached(&session_key.key, DataEncoding::Armored)
            .unwrap();
        serde_json::from_value(serde_json::json!({
            "ShareID": "share",
            "MembershipID": "membership",
            "AddressID": address_id,
            "Permissions": 4,
            "InviteTime": 1_727_000_000,
            "InviterEmail": "owner@example.test",
            "MemberSharePassphraseKeyPacket": STANDARD.encode(packet),
            "InviteeSharePassphraseSessionKeySignature": String::from_utf8(signature).unwrap(),
        }))
        .unwrap()
    }

    async fn accepted_by(
        invitee: &Invitee,
        dto: &ShareMembershipSummaryDto,
    ) -> PotentialObject<Author, SignatureVerificationError> {
        DtoToMetadataConverter::verify_membership_acceptance(invitee, dto).await
    }

    fn degraded(
        result: PotentialObject<Author, SignatureVerificationError>,
    ) -> (Option<String>, String) {
        match result {
            PotentialObject::Node(author) => panic!("verified as {author:?}"),
            PotentialObject::Degraded(error) => (
                error.claimed_author.map(|author| author.email_address),
                error.message,
            ),
        }
    }

    #[tokio::test]
    async fn the_members_acceptance_verifies() {
        let invitee = invitee();
        let dto = membership(
            &invitee,
            &invitee.key,
            crate::sharing::SIGNING_MEMBER,
            Some("address"),
        );
        match accepted_by(&invitee, &dto).await {
            PotentialObject::Node(author) => {
                assert_eq!(author.email_address.as_deref(), Some(INVITEE));
            }
            PotentialObject::Degraded(error) => panic!("not verified: {}", error.message),
        }
    }

    #[tokio::test]
    async fn another_key_or_context_is_degraded_with_the_claimed_member() {
        let invitee = invitee();
        let other = CryptoGenerator::generate_private_key().unwrap();
        for dto in [
            membership(
                &invitee,
                &other,
                crate::sharing::SIGNING_MEMBER,
                Some("address"),
            ),
            membership(
                &invitee,
                &invitee.key,
                "drive.share-member.inviter",
                Some("address"),
            ),
        ] {
            assert_eq!(
                degraded(accepted_by(&invitee, &dto).await),
                (
                    Some(INVITEE.to_string()),
                    "membership acceptance signature could not be verified".to_string()
                )
            );
        }
    }

    #[tokio::test]
    async fn a_packet_for_another_key_is_degraded() {
        let invitee = invitee();
        let stranger = Invitee {
            key: CryptoGenerator::generate_private_key().unwrap(),
            published: invitee.published.clone(),
            address_keys_fail: false,
        };
        let dto = membership(
            &stranger,
            &invitee.key,
            crate::sharing::SIGNING_MEMBER,
            Some("address"),
        );
        assert_eq!(
            degraded(accepted_by(&invitee, &dto).await),
            (
                Some(INVITEE.to_string()),
                "Failed to verify membership".to_string()
            )
        );
    }

    #[tokio::test]
    async fn missing_data_or_keys_are_degraded() {
        let mut invitee = invitee();
        let dto = membership(&invitee, &invitee.key, crate::sharing::SIGNING_MEMBER, None);
        assert_eq!(
            degraded(accepted_by(&invitee, &dto).await),
            (None, MEMBERSHIP_DATA_NOT_LOADED.to_string())
        );

        let dto = membership(
            &invitee,
            &invitee.key,
            crate::sharing::SIGNING_MEMBER,
            Some("address"),
        );
        invitee.address_keys_fail = true;
        assert_eq!(
            degraded(accepted_by(&invitee, &dto).await),
            (None, "Failed to get invitee keys".to_string())
        );

        invitee.address_keys_fail = false;
        invitee.published.clear();
        assert_eq!(
            degraded(accepted_by(&invitee, &dto).await),
            (
                Some(INVITEE.to_string()),
                "membership acceptance signature could not be verified".to_string()
            )
        );
    }

    #[test]
    fn a_membership_cached_without_the_acceptance_reads_as_unchecked() {
        let membership: NodeMembership = serde_json::from_value(serde_json::json!({
            "role": "viewer",
            "invite_time": "2024-09-22T10:13:20Z",
            "shared_by": { "Node": { "email_address": "owner@example.test" } },
        }))
        .unwrap();
        assert_eq!(
            degraded(membership.accepted_by),
            (None, MEMBERSHIP_DATA_NOT_LOADED.to_string())
        );
    }
}

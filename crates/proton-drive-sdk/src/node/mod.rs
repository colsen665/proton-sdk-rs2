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

    #[tokio::test]
    async fn in_batches_sends_one_request_per_batch() {
        let ids: Vec<LinkId> = (0..120).map(|i| LinkId::new(format!("link{i}"))).collect();
        let mut sizes = Vec::new();
        let batches = in_batches(ids.clone(), FRESH_NODES_BATCH_SIZE, |batch| {
            sizes.push(batch.len());
            async move { Ok(batch) }
        })
        .await
        .unwrap();
        assert_eq!(sizes, [50, 50, 20]);
        assert_eq!(batches.concat(), ids);
    }

    #[tokio::test]
    async fn in_batches_sends_nothing_for_no_ids() {
        let mut calls = 0;
        let batches: Vec<()> = in_batches(Vec::new(), FRESH_NODES_BATCH_SIZE, |_| {
            calls += 1;
            async { Ok(()) }
        })
        .await
        .unwrap();
        assert!(batches.is_empty());
        assert_eq!(calls, 0);
    }

    #[tokio::test]
    async fn in_batches_stops_at_the_first_error() {
        let ids: Vec<LinkId> = (0..120).map(|i| LinkId::new(format!("link{i}"))).collect();
        let mut calls = 0;
        let result: anyhow::Result<Vec<()>> = in_batches(ids, FRESH_NODES_BATCH_SIZE, |_| {
            calls += 1;
            async { anyhow::bail!("429") }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }

    /// Folder link details encrypted to `parent_key`, as `FolderOperations::create`
    /// makes them, named like the link.
    fn folder_link_details(
        id: &str,
        parent: &str,
        parent_key: &PgpPrivateKey,
    ) -> crate::api::links::LinkDetailsDto {
        use crate::crypto::CryptoGenerator;
        use crate::node::crypto::NodeCrypto;
        let folder_key = CryptoGenerator::generate_private_key().unwrap();
        let passphrase = CryptoGenerator::generate_passphrase();
        let locked_key = folder_key
            .to_armored_private_key(Some(passphrase.as_bytes()))
            .unwrap();
        let (encrypted_passphrase, passphrase_signature, _) =
            NodeCrypto::encrypt_and_sign_passphrase(passphrase.as_bytes(), parent_key, parent_key)
                .unwrap();
        let (name, name_hash, _) = NodeCrypto::encrypt_and_sign_name(
            id,
            &CryptoGenerator::generate_folder_hash_key(),
            parent_key,
            parent_key,
        )
        .unwrap();
        let hash_key = NodeCrypto::encrypt_folder_hash_key(
            &folder_key,
            &CryptoGenerator::generate_folder_hash_key(),
            parent_key,
        )
        .unwrap();
        serde_json::from_value(serde_json::json!({
            "Link": {
                "LinkID": id, "ParentLinkID": parent, "Type": 1, "State": 1,
                "CreateTime": 1_600_000_000, "ModifyTime": 1_600_000_000,
                "Name": name.0, "NameHash": hex::encode(name_hash),
                "NodeKey": locked_key.0, "NodePassphrase": encrypted_passphrase.0,
                "NodePassphraseSignature": passphrase_signature.unwrap().0
            },
            "Folder": { "NodeHashKey": hash_key.0 }
        }))
        .unwrap()
    }

    /// File link details whose name, passphrase and key are not readable (they would be
    /// encrypted to the parent's key, which is not there).
    fn file_link_details(id: &str, parent: &str) -> crate::api::links::LinkDetailsDto {
        serde_json::from_value(serde_json::json!({
            "Link": {
                "LinkID": id, "ParentLinkID": parent, "Type": 2, "State": 1,
                "CreateTime": 1_600_000_000, "ModifyTime": 1_600_000_000,
                "Name": "name", "NameHash": "abcd", "NodeKey": "key",
                "NodePassphrase": "passphrase", "MIMEType": "text/plain"
            },
            "File": {
                "MediaType": "text/plain", "TotalEncryptedSize": 42, "ContentKeyPacket": ""
            }
        }))
        .unwrap()
    }

    async fn cache_folder_secrets(
        client: &ProtonDriveClient,
        link: &str,
        secrets: PotentialObject<FolderSecrets, DegradedFolderSecrets>,
    ) {
        client
            .cache()
            .secrets()
            .set_folder_secrets(NodeUid::from_parts("volume", link), secrets)
            .await
            .unwrap();
    }

    fn degraded_folder_secrets() -> DegradedFolderSecrets {
        DegradedFolderSecrets {
            base: DegradedNodeSecrets {
                key: None,
                passphrase_session_key: None,
                name_session_key: None,
            },
            hash_key: None,
        }
    }

    /// M6.0.3 V-3: a link whose parent folder's secrets are degraded used to fail the
    /// whole batch, and with it every event page that named the link.
    #[tokio::test]
    async fn a_link_under_a_degraded_parent_is_degraded_and_the_batch_goes_on() {
        let (client, _) = crate::test_support::client().await;
        let good_key = crate::crypto::CryptoGenerator::generate_private_key().unwrap();
        cache_folder_secrets(
            &client,
            "good",
            PotentialObject::Node(FolderSecrets {
                base: NodeSecrets {
                    key: good_key.clone(),
                    passphrase_session_key: crate::crypto::CryptoGenerator::generate_session_key(),
                    passphrase_pgp_session_key: None,
                    name_session_key: crate::crypto::CryptoGenerator::generate_session_key(),
                    passphrase_for_anonymous_move: None,
                },
                hash_key: vec![],
            }),
        )
        .await;
        cache_folder_secrets(
            &client,
            "bad",
            PotentialObject::Degraded(degraded_folder_secrets()),
        )
        .await;

        let results = DtoToMetadataConverter::decode_fresh_links(
            &client,
            VolumeId::new("volume".into()),
            vec![
                folder_link_details("before", "good", &good_key),
                file_link_details("orphan", "bad"),
                folder_link_details("after", "good", &good_key),
            ],
        )
        .await
        .expect("one undecryptable parent must not fail the batch");

        let names: Vec<_> = results
            .iter()
            .map(|result| match result {
                PotentialObject::Node(m) => m.node().base().name.clone(),
                PotentialObject::Degraded(m) => {
                    format!("degraded {}", m.node().uid().link_id.raw())
                }
            })
            .collect();
        assert_eq!(names, ["before", "degraded orphan", "after"]);

        let PotentialObject::Degraded(orphan) = &results[1] else {
            unreachable!()
        };
        assert_eq!(orphan.name_hash_digest, [0xab, 0xcd]);
        let DegradedNodeAndSecrets::File(file, secrets) = &orphan.inner else {
            panic!("expected a degraded file, got {:?}", orphan.inner);
        };
        assert_eq!(
            file.base.parent_uid,
            Some(NodeUid::from_parts("volume", "bad"))
        );
        assert_eq!(file.total_storage_quota_usage, 42);
        assert_eq!(file.media_type, "text/plain");
        assert!(secrets.base.key.is_none());
        assert_eq!(
            file.base
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["Cryptography error: Parent folder key is degraded"]
        );

        // The decoded nodes are cached; the degraded one is not (its parent may
        // decrypt later).
        let entities = client.cache().entities();
        for (link, cached) in [("before", true), ("orphan", false), ("after", true)] {
            let entry = entities
                .try_get_node(NodeUid::from_parts("volume", link))
                .await
                .unwrap();
            assert_eq!(entry.is_some(), cached, "{link}");
        }
    }

    fn good_folder_secrets(key: &PgpPrivateKey) -> FolderSecrets {
        FolderSecrets {
            base: NodeSecrets {
                key: key.clone(),
                passphrase_session_key: crate::crypto::CryptoGenerator::generate_session_key(),
                passphrase_pgp_session_key: None,
                name_session_key: crate::crypto::CryptoGenerator::generate_session_key(),
                passphrase_for_anonymous_move: None,
            },
            hash_key: vec![],
        }
    }

    /// The link's name, or `degraded <link id>` (`<name>` when its name decrypted).
    fn listed_name(result: &PotentialObject<Node, DegradedNode>) -> String {
        match result {
            PotentialObject::Node(node) => node.base().name.clone(),
            PotentialObject::Degraded(node) => {
                let base = match node {
                    DegradedNode::Folder(n) | DegradedNode::Album(n) => &n.base,
                    DegradedNode::File(n) | DegradedNode::Photo(n) => &n.base,
                };
                match &base.name {
                    PotentialObject::Node(name) => format!("degraded <{name}>"),
                    PotentialObject::Degraded(_) => {
                        format!("degraded {}", node.uid().link_id.raw())
                    }
                }
            }
        }
    }

    /// R1 (P26): one child that does not decrypt by itself (its passphrase is encrypted
    /// to another key, or its hash key is unreadable) used to fail the whole listing.
    #[tokio::test]
    async fn a_listed_child_that_does_not_decrypt_is_degraded_and_the_listing_goes_on() {
        let (client, _) = crate::test_support::client().await;
        let folder_key = crate::crypto::CryptoGenerator::generate_private_key().unwrap();
        let other_key = crate::crypto::CryptoGenerator::generate_private_key().unwrap();
        let mut bad_hash_key = folder_link_details("badhash", "folder", &folder_key);
        bad_hash_key.folder.as_mut().unwrap().hash_key =
            Some(crate::pgp::PgpArmoredMessage("not a message".into()));

        let mut results = DtoToMetadataConverter::decode_listed_links(
            &client,
            &VolumeId::new("volume".into()),
            vec![
                folder_link_details("a-good", "folder", &folder_key),
                folder_link_details("b-stranger", "folder", &other_key),
                bad_hash_key,
                folder_link_details("d-good", "folder", &folder_key),
            ],
            Some(&folder_key),
        )
        .await
        .expect("one undecryptable child must not fail the listing");
        results.sort_by_key(|result| match result {
            PotentialObject::Node(node) => node.uid().link_id.raw().to_string(),
            PotentialObject::Degraded(node) => node.uid().link_id.raw().to_string(),
        });

        let names: Vec<_> = results.iter().map(listed_name).collect();
        assert_eq!(
            names,
            [
                "a-good",
                "degraded b-stranger",
                "degraded <badhash>",
                "d-good"
            ]
        );
        let PotentialObject::Degraded(DegradedNode::Folder(stranger)) = &results[1] else {
            unreachable!()
        };
        assert_eq!(
            stranger.base.parent_uid,
            Some(NodeUid::from_parts("volume", "folder"))
        );
        assert!(
            stranger.base.errors.iter().any(|error| error
                .to_string()
                .contains("Failed to decrypt node passphrase")),
            "{:?}",
            stranger.base.errors
        );
        let PotentialObject::Degraded(DegradedNode::Folder(bad_hash)) = &results[2] else {
            unreachable!()
        };
        assert!(
            bad_hash
                .base
                .errors
                .iter()
                .any(|error| error.to_string().contains("Failed to decrypt hash key")),
            "{:?}",
            bad_hash.base.errors
        );
    }

    /// R1 (P26): in the fresh batch, a link that does not decrypt by itself under a
    /// readable parent is degraded and not cached; the others are decoded and cached.
    #[tokio::test]
    async fn a_fresh_link_that_does_not_decrypt_by_itself_is_degraded() {
        let (client, _) = crate::test_support::client().await;
        let good_key = crate::crypto::CryptoGenerator::generate_private_key().unwrap();
        let other_key = crate::crypto::CryptoGenerator::generate_private_key().unwrap();
        cache_folder_secrets(
            &client,
            "good",
            PotentialObject::Node(good_folder_secrets(&good_key)),
        )
        .await;

        let results = DtoToMetadataConverter::decode_fresh_links(
            &client,
            VolumeId::new("volume".into()),
            vec![
                folder_link_details("before", "good", &good_key),
                folder_link_details("stranger", "good", &other_key),
                folder_link_details("after", "good", &good_key),
            ],
        )
        .await
        .expect("one undecryptable link must not fail the batch");

        let names: Vec<_> = results
            .into_iter()
            .map(|result| listed_name(&result.to_node_result()))
            .collect();
        assert_eq!(names, ["before", "degraded stranger", "after"]);
        let entities = client.cache().entities();
        for (link, cached) in [("before", true), ("stranger", false), ("after", true)] {
            let entry = entities
                .try_get_node(NodeUid::from_parts("volume", link))
                .await
                .unwrap();
            assert_eq!(entry.is_some(), cached, "{link}");
        }
    }

    /// A single node read keeps its contract: a node that does not decrypt is an
    /// `UndecryptableNodeError`, not a degraded node.
    #[tokio::test]
    async fn a_single_undecryptable_node_is_still_an_error() {
        let (client, _) = crate::test_support::client().await;
        let parent_key = crate::crypto::CryptoGenerator::generate_private_key().unwrap();
        let other_key = crate::crypto::CryptoGenerator::generate_private_key().unwrap();
        let error = DtoToMetadataConverter::convert_dto_to_node_metadata_with_client(
            &client,
            VolumeId::new("volume".into()),
            folder_link_details("stranger", "parent", &other_key),
            Some(&parent_key),
        )
        .await
        .unwrap_err();
        assert!(crate::error::UndecryptableNodeError::is_cause_of(&error));
        assert_eq!(error.to_string(), "Decryption failed for folder");
    }

    /// Folder link details under `parent_key` whose name is signed by `name_signer`;
    /// the passphrase is signed by the parent key and the hash key by the node key, as an
    /// anonymous upload signs them, and `email` is the claimed author of both.
    fn signed_folder_link(
        id: &str,
        parent_key: &PgpPrivateKey,
        name_signer: &PgpPrivateKey,
        email: Option<&str>,
    ) -> crate::api::links::LinkDetailsDto {
        use crate::crypto::CryptoGenerator;
        use crate::node::crypto::NodeCrypto;
        let folder_key = CryptoGenerator::generate_private_key().unwrap();
        let passphrase = CryptoGenerator::generate_passphrase();
        let locked_key = folder_key
            .to_armored_private_key(Some(passphrase.as_bytes()))
            .unwrap();
        let (encrypted_passphrase, passphrase_signature, _) =
            NodeCrypto::encrypt_and_sign_passphrase(passphrase.as_bytes(), parent_key, parent_key)
                .unwrap();
        let (name, name_hash, _) = NodeCrypto::encrypt_and_sign_name(
            id,
            &CryptoGenerator::generate_folder_hash_key(),
            parent_key,
            name_signer,
        )
        .unwrap();
        let hash_key = NodeCrypto::encrypt_folder_hash_key(
            &folder_key,
            &CryptoGenerator::generate_folder_hash_key(),
            &folder_key,
        )
        .unwrap();
        serde_json::from_value(serde_json::json!({
            "Link": {
                "LinkID": id, "ParentLinkID": "parent", "Type": 1, "State": 1,
                "CreateTime": 1_600_000_000, "ModifyTime": 1_600_000_000,
                "Name": name.0, "NameHash": hex::encode(name_hash),
                "NodeKey": locked_key.0, "NodePassphrase": encrypted_passphrase.0,
                "NodePassphraseSignature": passphrase_signature.unwrap().0,
                "SignatureEmail": email, "NameSignatureEmail": email
            },
            "Folder": { "NodeHashKey": hash_key.0 }
        }))
        .unwrap()
    }

    async fn authors(
        client: &ProtonDriveClient,
        link: crate::api::links::LinkDetailsDto,
        parent_key: &PgpPrivateKey,
    ) -> (String, bool, bool) {
        let node = DtoToMetadataConverter::convert_dto_to_node_metadata_with_client(
            client,
            VolumeId::new("volume".into()),
            link,
            Some(parent_key),
        )
        .await
        .expect("the node decodes")
        .get_node_or_throw()
        .unwrap();
        let base = node.base().clone();
        (
            base.name,
            matches!(base.name_author, PotentialObject::Node(_)),
            matches!(base.author, PotentialObject::Node(_)),
        )
    }

    /// R8 (P27): a signature that does not verify is kept on the node as a degraded
    /// author, as the official SDKs keep it; the node itself still decodes.
    #[tokio::test]
    async fn verification_failures_are_kept_on_the_node() {
        let (client, _) = crate::test_support::client().await;
        let parent_key = crate::crypto::CryptoGenerator::generate_private_key().unwrap();
        let stranger = crate::crypto::CryptoGenerator::generate_private_key().unwrap();

        let signed = signed_folder_link("signed", &parent_key, &parent_key, None);
        assert_eq!(
            authors(&client, signed, &parent_key).await,
            ("signed".into(), true, true)
        );
        let renamed = signed_folder_link("renamed", &parent_key, &stranger, None);
        assert_eq!(
            authors(&client, renamed, &parent_key).await,
            ("renamed".into(), false, true),
            "a name signed by a stranger is not verified"
        );
    }

    /// R8 (P27): a named author whose keys cannot be had verifies nothing, so the node's
    /// and the name's author are unverified (the test account answers no keys).
    #[tokio::test]
    async fn a_named_author_without_keys_is_not_verified() {
        let (client, _) = crate::test_support::client().await;
        let parent_key = crate::crypto::CryptoGenerator::generate_private_key().unwrap();
        let link = signed_folder_link(
            "named",
            &parent_key,
            &parent_key,
            Some("author@example.test"),
        );
        assert_eq!(
            authors(&client, link, &parent_key).await,
            ("named".into(), false, false)
        );
    }

    /// The error of a degraded folder's secrets is told apart by type, not by its text.
    #[tokio::test]
    async fn degraded_folder_secrets_are_an_undecryptable_node_error() {
        let (client, _) = crate::test_support::client().await;
        cache_folder_secrets(
            &client,
            "bad",
            PotentialObject::Degraded(degraded_folder_secrets()),
        )
        .await;
        let error = crate::node::folder::FolderOperations::get_secrets(
            &client,
            NodeUid::from_parts("volume", "bad"),
        )
        .await
        .unwrap_err();
        assert!(crate::error::UndecryptableNodeError::is_cause_of(&error));
        assert!(crate::error::UndecryptableNodeError::is_cause_of(
            &error.context("resolving the parent")
        ));
        // A failed request or any other error with the same words is not one.
        assert!(!crate::error::UndecryptableNodeError::is_cause_of(
            &anyhow::anyhow!("Degraded node has no folder secrets")
        ));
    }

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
            PotentialObject::Degraded(_) => Err(anyhow::Error::new(
                crate::error::UndecryptableNodeError("Degraded node has no folder secrets".into()),
            )),
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

    /// The node's name hash (`Hash` in the API), decoded or not.
    pub fn name_hash_digest(&self) -> &[u8] {
        match self {
            PotentialObject::Node(m) => &m.name_hash_digest,
            PotentialObject::Degraded(m) => &m.name_hash_digest,
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
        DtoToMetadataConverter::decode_listed_links(
            &self.client,
            &self.volume_id,
            response.links,
            self.parent_key.as_ref(),
        )
        .await
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
        let mut undecryptable_parents = std::collections::HashSet::new();
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
                        .await;
                        (parent_id, secrets)
                    }
                })
                .collect();

            let mut parent_keys = self.parent_keys.lock().await;
            while let Some((id, result)) = fetch_futs.next().await {
                match result {
                    Ok(secrets) => {
                        parent_keys.entry(id).or_insert(secrets.base.key);
                    }
                    // Its children are degraded below; the others go on (R1).
                    Err(error) if crate::error::UndecryptableNodeError::is_cause_of(&error) => {
                        undecryptable_parents.insert(id);
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        // Now decrypt all links in parallel (parent keys are all cached).
        let client = self.client.clone();
        let volume_id = self.volume_id.clone();
        let share_key = self.share_key.clone();

        let mut results = Vec::new();
        let (orphans, links): (Vec<_>, Vec<_>) =
            response.links.into_iter().partition(|link_details| {
                link_details
                    .link
                    .parent_id
                    .as_ref()
                    .is_some_and(|pid| undecryptable_parents.contains(pid))
            });
        for link_details in orphans {
            results.push(PotentialObject::Degraded(
                DtoToMetadataConverter::degraded_without_parent_key(&volume_id, link_details)
                    .node(),
            ));
        }

        let mut decrypt_futs: FuturesUnordered<_> = {
            let parent_keys = self.parent_keys.lock().await;
            links
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
                        DtoToMetadataConverter::convert_dto_to_node_metadata_or_degraded(
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

/// Most links per `get_details` request when nodes are fetched in bulk: the C# SDK's
/// `BatchLoaderBase` default (the JS SDK sends up to 100).
pub const FRESH_NODES_BATCH_SIZE: usize = 50;

/// Runs `load` once per consecutive batch of at most `size` ids, one batch after the
/// other, and returns the results in order. No ids, no calls.
async fn in_batches<T, F, Fut>(ids: Vec<LinkId>, size: usize, mut load: F) -> anyhow::Result<Vec<T>>
where
    F: FnMut(Vec<LinkId>) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut results = Vec::with_capacity(ids.len().div_ceil(size));
    for batch in ids.chunks(size) {
        results.push(load(batch.to_vec()).await?);
    }
    Ok(results)
}

pub struct DtoToMetadataConverter;

/// What the converter made of one link.
enum Decoded {
    Node(NodeMetadata),
    /// The node does not decrypt: what did, and the error a single-node read returns.
    Undecryptable(DegradedNodeMetadata, crate::error::UndecryptableNodeError),
}

impl Decoded {
    /// A node, or the [`crate::error::UndecryptableNodeError`] of one that does not decrypt.
    fn into_result(self) -> anyhow::Result<NodeMetadataResult> {
        match self {
            Self::Node(metadata) => Ok(PotentialObject::Node(metadata)),
            Self::Undecryptable(_, error) => Err(anyhow::Error::new(error)),
        }
    }
}

/// The parts of a node that decrypted, and an error for each that did not.
struct DecryptedParts {
    name: PotentialObject<String, ProtonDriveError>,
    errors: Vec<ProtonDriveError>,
    secrets: DegradedNodeSecrets,
    hash_key: Option<Vec<u8>>,
    content_key: Option<PgpSessionKey>,
}

impl Default for DecryptedParts {
    fn default() -> Self {
        Self {
            name: PotentialObject::Degraded(ProtonDriveError::CryptoError(
                "Name not decrypted".into(),
            )),
            errors: Vec::new(),
            secrets: DegradedNodeSecrets {
                key: None,
                passphrase_session_key: None,
                name_session_key: None,
            },
            hash_key: None,
            content_key: None,
        }
    }
}

impl DecryptedParts {
    /// The name, key and passphrase of a link, as far as they decrypted.
    fn from_link(link: crate::node::crypto::LinkDecryptionResult) -> Self {
        let mut parts = Self::default();
        match link.node_key {
            Ok(key) => parts.secrets.key = Some(key),
            // Its text says whether the passphrase or the key failed.
            Err(error) => parts.errors.push(ProtonDriveError::CryptoError(error)),
        }
        if let Ok(passphrase) = link.passphrase {
            parts.secrets.passphrase_session_key = Some(passphrase.data);
        }
        match link.name {
            Ok(name) => {
                parts.secrets.name_session_key =
                    name.session_key.as_ref().map(PgpSessionKey::from_rpgp);
                parts.name = PotentialObject::Node(name.data);
            }
            Err(Some(error)) => {
                let error =
                    ProtonDriveError::CryptoError(format!("Failed to decrypt name: {error}"));
                parts.name = PotentialObject::Degraded(error.clone());
                parts.errors.push(error);
            }
            // Nothing to decrypt it with: the key's error says why.
            Err(None) => {}
        }
        parts
    }

    /// Records a field that did not decrypt; `None` means it was not tried (no key).
    fn add_error(&mut self, field: &str, error: Option<String>) {
        if let Some(error) = error {
            self.errors.push(ProtonDriveError::CryptoError(format!(
                "Failed to decrypt {field}: {error}"
            )));
        }
    }
}

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

        Self::cache_node_metadata(client, &metadata).await?;
        Ok(metadata)
    }

    /// Fetches the given links of one volume again from the API, bypassing and then
    /// refreshing the entity cache, with one `get_details` request per
    /// [`FRESH_NODES_BATCH_SIZE`] links, as the C# SDK's batch loader does. The cache
    /// entries of all given links are evicted first, so links the API no longer
    /// returns (deleted for good) leave no stale entry; they are missing from the result.
    /// A link whose parent folder cannot be decrypted is returned degraded (see
    /// [`Self::decode_fresh_links`]); a failed request fails the call.
    pub async fn get_fresh_nodes_metadata(
        client: &ProtonDriveClient,
        volume_id: VolumeId,
        link_ids: Vec<LinkId>,
    ) -> anyhow::Result<Vec<NodeMetadataResult>> {
        let entities = client.cache().entities();
        for link_id in &link_ids {
            let _ = entities
                .remove_node(crate::node::NodeUid::new(
                    volume_id.clone(),
                    link_id.clone(),
                ))
                .await;
        }
        let api = client.api();
        let links = api.links();
        let batches = in_batches(link_ids, FRESH_NODES_BATCH_SIZE, |batch| {
            links.get_details(volume_id.clone(), batch)
        })
        .await?;

        let links = batches
            .into_iter()
            .flat_map(|response| response.links)
            .collect();
        Self::decode_fresh_links(client, volume_id, links).await
    }

    /// Decodes and caches the links of [`Self::get_fresh_nodes_metadata`], in order.
    ///
    /// A link whose parent folder key cannot be had because the parent does not decrypt
    /// (its secrets are degraded in the cache, or the parent, or a folder above it, fails
    /// to decrypt when fetched) is returned degraded with the error "Parent folder key is
    /// degraded", a link that does not decrypt by itself is returned degraded with what
    /// did decrypt, and the others are decoded: one such link must not fail the whole
    /// batch, which an event-following client asks for again and again. The two cases
    /// are told apart by type: decryption failures are [`crate::error::UndecryptableNodeError`]s, and
    /// any other error (a failed request, an API error, a cache failure) fails the call.
    async fn decode_fresh_links(
        client: &ProtonDriveClient,
        volume_id: VolumeId,
        links: Vec<crate::api::links::LinkDetailsDto>,
    ) -> anyhow::Result<Vec<NodeMetadataResult>> {
        let mut results = Vec::with_capacity(links.len());
        for link_details in links {
            let parent_key =
                match Self::resolve_parent_key(client, volume_id.clone(), &link_details).await {
                    Ok(key) => key,
                    Err(error) if crate::error::UndecryptableNodeError::is_cause_of(&error) => {
                        tracing::debug!(
                            link_id = %link_details.link.id.raw(),
                            "parent folder key is degraded; returning the node degraded"
                        );
                        results.push(PotentialObject::Degraded(
                            Self::degraded_without_parent_key(&volume_id, link_details),
                        ));
                        continue;
                    }
                    Err(error) => return Err(error),
                };
            // A link that does not decrypt by itself is degraded too, and not cached.
            let metadata = Self::convert_dto_to_node_metadata_or_degraded(
                client,
                volume_id.clone(),
                link_details,
                parent_key.as_ref(),
            )
            .await?;
            Self::cache_node_metadata(client, &metadata).await?;
            results.push(metadata);
        }
        Ok(results)
    }

    /// Decodes the children of one folder, listed by [`NodeBatchLoader`], with the
    /// folder's key, all at once; in no particular order. A child that does not decrypt
    /// is returned degraded (R1).
    async fn decode_listed_links(
        client: &ProtonDriveClient,
        volume_id: &VolumeId,
        links: Vec<crate::api::links::LinkDetailsDto>,
        parent_key: Option<&PgpPrivateKey>,
    ) -> anyhow::Result<Vec<PotentialObject<Node, DegradedNode>>> {
        let mut futs: FuturesUnordered<_> = links
            .into_iter()
            .map(|link_details| async move {
                Self::convert_dto_to_node_metadata_or_degraded(
                    client,
                    volume_id.clone(),
                    link_details,
                    parent_key,
                )
                .await
                .map(|r| r.to_node_result())
            })
            .collect();

        let mut results = Vec::new();
        while let Some(result) = futs.next().await {
            results.push(result?);
        }
        Ok(results)
    }

    /// A node whose parent folder key is degraded: nothing of it decrypts (its name,
    /// passphrase and key are encrypted to that key), so it carries what the link states
    /// in clear and the error. It is not cached: the parent may decrypt later.
    fn degraded_without_parent_key(
        volume_id: &VolumeId,
        link_details: crate::api::links::LinkDetailsDto,
    ) -> DegradedNodeMetadata {
        let error = ProtonDriveError::CryptoError("Parent folder key is degraded".into());
        Self::degraded_node_metadata(
            volume_id,
            &link_details,
            DecryptedParts {
                name: PotentialObject::Degraded(error.clone()),
                errors: vec![error],
                ..DecryptedParts::default()
            },
        )
    }

    /// A node that does not fully decrypt: what its link states in clear (uid, parent,
    /// times, owner, name hash; a file's media type and storage size) with the parts
    /// that did decrypt and an error for each that did not.
    fn degraded_node_metadata(
        volume_id: &VolumeId,
        link_details: &crate::api::links::LinkDetailsDto,
        parts: DecryptedParts,
    ) -> DegradedNodeMetadata {
        let link = &link_details.link;
        let base = DegradedNodeBase {
            uid: NodeUid::new(volume_id.clone(), link.id.clone()),
            parent_uid: link
                .parent_id
                .clone()
                .map(|id| NodeUid::new(volume_id.clone(), id)),
            name: parts.name,
            name_author: PotentialObject::Node(Author {
                email_address: link.name_signature_email_address.clone(),
            }),
            creation_time: link.creation_time,
            trash_time: link.trash_time,
            author: PotentialObject::Node(Author {
                email_address: link.signature_email_address.clone(),
            }),
            owned_by: link
                .owned_by
                .as_ref()
                .map(|o| OwnedBy {
                    email: o.email.clone(),
                    organisation: o.organization.clone(),
                })
                .unwrap_or_default(),
            errors: parts.errors,
        };
        let inner = match link.r#type {
            crate::api::links::LinkType::Folder | crate::api::links::LinkType::Album => {
                DegradedNodeAndSecrets::Folder(
                    DegradedFolderNode { base },
                    DegradedFolderSecrets {
                        base: parts.secrets,
                        hash_key: parts.hash_key,
                    },
                )
            }
            crate::api::links::LinkType::File => {
                let file = link_details
                    .file
                    .as_ref()
                    .or(link_details.photo.as_ref().map(|photo| &photo.base));
                DegradedNodeAndSecrets::File(
                    DegradedFileNode {
                        base,
                        media_type: file
                            .map(|file| file.media_type.clone())
                            .or(link.media_type.clone())
                            .unwrap_or_default(),
                        active_revision: None,
                        total_storage_quota_usage: file
                            .map_or(0, |file| file.total_size_on_storage),
                    },
                    DegradedFileSecrets {
                        base: parts.secrets,
                        content_key: parts.content_key,
                    },
                )
            }
        };
        DegradedNodeMetadata {
            inner,
            membership_share_id: link_details
                .sharing
                .as_ref()
                .map(|sharing| sharing.share_id.clone()),
            name_hash_digest: link.name_hash_digest.clone(),
        }
    }

    /// Stores a freshly decoded node and its secrets in the client's caches.
    async fn cache_node_metadata(
        client: &ProtonDriveClient,
        metadata: &NodeMetadataResult,
    ) -> anyhow::Result<()> {
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

        Ok(())
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

    /// Decodes one link. A node that does not decrypt is an
    /// [`crate::error::UndecryptableNodeError`]; readers of many nodes use
    /// [`Self::convert_dto_to_node_metadata_or_degraded`] instead.
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
        .await?
        .into_result()
    }

    /// Like [`Self::convert_dto_to_node_metadata_with_client`], but a node that does not
    /// decrypt is returned degraded, with what did decrypt (its name, its key) and an
    /// error per field that did not, as the official SDKs return it in listings: one
    /// such node must not hide the others. Any other error still fails the call.
    pub async fn convert_dto_to_node_metadata_or_degraded(
        client: &ProtonDriveClient,
        volume_id: VolumeId,
        link_details: crate::api::links::LinkDetailsDto,
        parent_key: Option<&PgpPrivateKey>,
    ) -> anyhow::Result<NodeMetadataResult> {
        let decoded = Self::convert_dto_to_node_metadata_inner(
            client.account().clone(),
            client.cache().entities().as_ref(),
            client.cache().secrets().as_ref(),
            volume_id,
            link_details,
            parent_key,
            Some(client),
        )
        .await?;
        Ok(match decoded {
            Decoded::Node(metadata) => PotentialObject::Node(metadata),
            Decoded::Undecryptable(degraded, error) => {
                tracing::debug!(
                    link_id = %degraded.node().uid().link_id.raw(),
                    %error,
                    "node does not decrypt; returning it degraded"
                );
                PotentialObject::Degraded(degraded)
            }
        })
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
        .await?
        .into_result()
    }

    async fn convert_dto_to_node_metadata_inner(
        account_client: std::sync::Arc<dyn crate::account::AccountClient>,
        _entity_cache: &dyn crate::cache::entity::DriveEntityCache,
        _secret_cache: &dyn crate::cache::secret::DriveSecretCache,
        _volume_id: crate::volume::VolumeId,
        link_details: crate::api::links::LinkDetailsDto,
        parent_key: Option<&PgpPrivateKey>,
        metric_client: Option<&ProtonDriveClient>,
    ) -> anyhow::Result<Decoded> {
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
                    .clone()
                    .map(|id| NodeUid::new(_volume_id.clone(), id));

                let crate::node::crypto::FolderDecryptionResult { link, hash_key } = decryption;
                if let (Ok(name), Ok(_hash_key), Ok(node_key), Ok(passphrase_decryption_output)) =
                    (&link.name, &hash_key, &link.node_key, &link.passphrase)
                {
                    let claimed_modification_time =
                        crate::node::folder::decrypt_folder_modification_time(
                            folder_dto.extended_attributes.as_ref(),
                            node_key,
                            &link.node_authorship_claim,
                            &uid,
                        );
                    let node_base = NodeBase {
                        uid: uid.clone(),
                        parent_uid,
                        name: name.data.clone(),
                        creation_time: link_dto.creation_time,
                        trash_time: link_dto.trash_time,
                        // A failed check is kept on the node; the node stays usable (R8).
                        name_author: link
                            .name_authorship_claim
                            .to_verified_author(name.authorship_verification_failure.as_ref()),
                        author: link.node_authorship_claim.to_verified_author(
                            _hash_key.authorship_verification_failure.as_ref().or(
                                passphrase_decryption_output
                                    .authorship_verification_failure
                                    .as_ref(),
                            ),
                        ),
                        owned_by: link_dto.owned_by.as_ref().map(|o| OwnedBy {
                            email: o.email.clone(),
                            organisation: o.organization.clone(),
                        }),
                        is_shared,
                        is_shared_by_url,
                        direct_role,
                        membership: membership.clone(),
                    };

                    let passphrase_session_key = passphrase_decryption_output.data.clone();
                    let passphrase_pgp_session_key = passphrase_decryption_output
                        .session_key
                        .as_ref()
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

                    Ok(Decoded::Node(NodeMetadata {
                        inner: NodeAndSecrets::Folder(
                            FolderNode {
                                base: node_base,
                                claimed_modification_time,
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
                    let message = match (&link.name, &hash_key, &link.node_key, &link.passphrase) {
                        (Ok(_), Ok(_), Ok(_), Err(e)) => {
                            format!("Failed to decrypt folder passphrase: {}", e)
                        }
                        _ => "Decryption failed for folder".to_string(),
                    };
                    let mut parts = DecryptedParts::from_link(link);
                    match hash_key {
                        Ok(output) => parts.hash_key = Some(output.data),
                        Err(error) => parts.add_error("hash key", error),
                    }
                    Ok(Decoded::Undecryptable(
                        Self::degraded_node_metadata(&_volume_id, &link_details, parts),
                        crate::error::UndecryptableNodeError(message),
                    ))
                }
            }
            crate::api::links::LinkType::File => {
                // Photo nodes in the Photos volume carry their file metadata in the
                // `photo` field (PhotoDto) rather than the `file` field (FileDto).
                // PhotoDto.base IS a FileDto via `#[serde(flatten)]`, so we can
                // use it directly as a fallback.
                let photo_dto_base = link_details.photo.clone().map(|p| p.base);
                let file_dto = link_details
                    .file
                    .clone()
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
                let parent_uid = link_dto
                    .parent_id
                    .clone()
                    .map(|id| NodeUid::new(_volume_id.clone(), id));

                let name_err = decryption.link.name.as_ref().err().cloned();
                let content_err = decryption.content_key.as_ref().err().cloned();
                let node_err = decryption.link.node_key.as_ref().err().cloned();

                let crate::node::crypto::FileDecryptionResult {
                    link,
                    content_key,
                    content_authorship_claim,
                } = decryption;
                if let (
                    Ok(name),
                    Ok(_content_key),
                    Ok(node_key),
                    Ok(passphrase_decryption_output),
                ) = (&link.name, &content_key, &link.node_key, &link.passphrase)
                {
                    let node_base = NodeBase {
                        uid: uid.clone(),
                        parent_uid,
                        name: name.data.clone(),
                        creation_time: link_dto.creation_time,
                        trash_time: link_dto.trash_time,
                        // A failed check is kept on the node; the node stays usable (R8).
                        name_author: link
                            .name_authorship_claim
                            .to_verified_author(name.authorship_verification_failure.as_ref()),
                        author: link.node_authorship_claim.to_verified_author(
                            passphrase_decryption_output
                                .authorship_verification_failure
                                .as_ref(),
                        ),
                        owned_by: link_dto.owned_by.as_ref().map(|o| OwnedBy {
                            email: o.email.clone(),
                            organisation: o.organization.clone(),
                        }),
                        is_shared,
                        is_shared_by_url,
                        direct_role,
                        membership,
                    };

                    let passphrase_session_key = passphrase_decryption_output.data.clone();
                    let passphrase_pgp_session_key = passphrase_decryption_output
                        .session_key
                        .as_ref()
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
                        content_key: _content_key.data.clone(),
                    };

                    Ok(Decoded::Node(NodeMetadata {
                        inner: NodeAndSecrets::File(
                            FileNode {
                                base: FileOrFileDraftNode {
                                    base: node_base,
                                    media_type: file_dto.media_type.clone(),
                                },
                                active_revision: crate::node::revision::Revision {
                                    content_author: Some(
                                        content_authorship_claim.to_verified_author(
                                            _content_key.authorship_verification_failure.as_ref(),
                                        ),
                                    ),
                                    ..crate::node::revision::Revision::from_active_revision_dto(
                                        &uid,
                                        file_dto.active_revision.as_ref(),
                                        node_key,
                                        &content_authorship_claim,
                                    )
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
                    let message = match (&link.name, &content_key, &link.node_key, &link.passphrase)
                    {
                        (Ok(_), Ok(_), Ok(_), Err(e)) => {
                            format!("Failed to decrypt file passphrase: {}", e)
                        }
                        _ => format!(
                            "Decryption failed for file parent_key={:?} name={:?} content={:?} node={:?}",
                            parent_err, name_err, content_err, node_err
                        ),
                    };
                    let mut parts = DecryptedParts::from_link(link);
                    match content_key {
                        Ok(output) => parts.content_key = Some(output.data),
                        Err(error) => parts.add_error("content key", error),
                    }
                    Ok(Decoded::Undecryptable(
                        Self::degraded_node_metadata(&_volume_id, &link_details, parts),
                        crate::error::UndecryptableNodeError(message),
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
                    .at_date(crate::server_time::check_now())
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
                .at_date(crate::server_time::check_now())
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

use crate::api::revision::RevisionConflict;
use crate::block::verify::BlockVerifier;
use crate::client::ProtonDriveClient;
use crate::error::ApiError;
use crate::links::LinkId;
use crate::node::NodeUid;
use crate::node::revision::RevisionUid;
use crate::pgp::{PgpPrivateKey, PgpSessionKey};
use crate::revision::RevisionId;
use crate::volume::VolumeId;
use async_trait::async_trait;
use proton_rpgp::{AsPublicKeyRef, Encryptor};
use proton_sdk_rs2::protobuf::Address;
use std::sync::Arc;

/// Number of stale drafts removed before draft creation gives up, as in the
/// official SDK.
const MAX_DRAFT_CREATION_ATTEMPTS: u32 = 3;

/// The server refused a new revision draft: the base revision passed as
/// `CurrentRevisionID` is no longer the active one, or another client has a
/// draft open on the file.
#[derive(Debug, thiserror::Error)]
#[error("A new version of this file is already being uploaded or the file has changed")]
pub struct RevisionDraftConflictError {
    /// Conflicting link, revision and draft reported by the server.
    pub conflict: Option<RevisionConflict>,
    #[source]
    pub source: ApiError,
}

/// The server refused a new file draft because the parent already contains
/// a node with the same name.
#[derive(Debug, thiserror::Error)]
#[error("A file or folder with this name already exists")]
pub struct NodeWithSameNameExistsError {
    /// Conflicting link, revision and draft reported by the server.
    pub conflict: Option<RevisionConflict>,
    #[source]
    pub source: ApiError,
}

#[derive(Debug)]
enum DraftConflictResolution {
    DeleteRevisionDraft(RevisionId),
    DeleteFileDraft(LinkId),
    Fail,
}

/// Returns the API error and its conflict details when `error` is a draft
/// conflict (code 2500 or HTTP 409).
fn draft_conflict(error: &anyhow::Error) -> Option<(ApiError, Option<RevisionConflict>)> {
    let api = ApiError::find(error)?;
    if !(api.is_already_exists() || api.http_status == Some(409)) {
        return None;
    }
    Some((api.clone(), api.details_as::<RevisionConflict>()))
}

/// A new revision draft conflicts with an open draft. Only a draft left
/// behind by this client is removed; anything else is a real conflict.
fn resolve_new_revision_conflict(
    conflict: Option<&RevisionConflict>,
    client_uid: &str,
) -> DraftConflictResolution {
    match conflict {
        Some(RevisionConflict {
            draft_revision_id: Some(draft),
            draft_client_uid: Some(owner),
            ..
        }) if owner == client_uid => DraftConflictResolution::DeleteRevisionDraft(draft.clone()),
        _ => DraftConflictResolution::Fail,
    }
}

/// A new file conflicts with an existing name. When the name is held by a
/// draft that never got a revision committed, it is removed if this client
/// created it or the caller allows overriding other clients' drafts.
fn resolve_new_file_conflict(
    conflict: Option<&RevisionConflict>,
    client_uid: &str,
    override_other_clients: bool,
) -> DraftConflictResolution {
    match conflict {
        Some(RevisionConflict {
            link_id: Some(link),
            revision_id: None,
            draft_revision_id: Some(_),
            draft_client_uid,
        }) if override_other_clients || draft_client_uid.as_deref() == Some(client_uid) => {
            DraftConflictResolution::DeleteFileDraft(link.clone())
        }
        _ => DraftConflictResolution::Fail,
    }
}

async fn delete_file_draft(
    client: &ProtonDriveClient,
    volume_id: VolumeId,
    link_id: LinkId,
) -> anyhow::Result<()> {
    let response = client
        .api()
        .links()
        .delete_multiple(volume_id, vec![link_id.clone()])
        .await?;
    let result = response
        .responses
        .iter()
        .find(|pair| pair.link_id == link_id)
        .ok_or_else(|| anyhow::anyhow!("Missing deletion result in response"))?;
    match result.response.to_result() {
        Err(error) if !ApiError::find(&error).is_some_and(ApiError::is_not_found) => Err(error),
        _ => Ok(()),
    }
}

#[derive(Clone)]
pub struct RevisionDraft {
    pub uid: RevisionUid,
    pub file_key: PgpPrivateKey,
    pub content_key: PgpSessionKey,
    pub signing_key: PgpPrivateKey,
    pub hash_key: Option<Vec<u8>>,
    pub membership_address: Address,
    pub block_verifier: BlockVerifier,
}

pub struct NewFileDraftProvider {
    pub client: Arc<ProtonDriveClient>,
    pub parent_folder_uid: NodeUid,
    pub name: String,
    pub media_type: String,
    pub override_existing_draft_by_other_client: bool,
}

pub struct NewRevisionDraftProvider {
    pub client: Arc<ProtonDriveClient>,
    pub node_uid: NodeUid,
    pub revision_id: RevisionId,
}

#[async_trait]
pub trait RevisionDraftProvider: Send + Sync {
    async fn get_draft(&self) -> anyhow::Result<RevisionDraft>;
}

async fn membership_address_for(
    client: &ProtonDriveClient,
    uid: &NodeUid,
) -> anyhow::Result<Address> {
    match crate::node::operations::NodeOperations::get_membership_address(client, uid).await {
        Ok(addr) => Ok(addr),
        Err(error) => {
            tracing::warn!(%error, "membership address lookup failed, using default");
            client.account().get_default_address().await
        }
    }
}

async fn signing_key_for(
    client: &ProtonDriveClient,
    address_id: &str,
) -> anyhow::Result<proton_rpgp::PrivateKey> {
    use proton_rpgp::AccessKeyInfo;
    let keys = client
        .account()
        .get_address_private_keys(&crate::account::AddressId::new(address_id.to_string()))
        .await?;
    // Drive's commit endpoint still verifies v4 signatures; skip v6/PQC primaries.
    if let Some(v4) = keys.iter().find(|k| k.version() < 6) {
        return Ok(v4.clone());
    }
    keys.into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address keys for {address_id}"))
}

#[async_trait]
impl RevisionDraftProvider for NewFileDraftProvider {
    async fn get_draft(&self) -> anyhow::Result<RevisionDraft> {
        let parent_secrets = crate::node::folder::FolderOperations::get_secrets(
            &self.client,
            self.parent_folder_uid.clone(),
        )
        .await?;

        let membership_address =
            membership_address_for(&self.client, &self.parent_folder_uid).await?;
        let signing_key = signing_key_for(&self.client, &membership_address.address_id).await?;

        // Create draft via API
        let node_key = crate::crypto::CryptoGenerator::generate_private_key()?;
        let folder_passphrase = crate::crypto::CryptoGenerator::generate_passphrase();
        let locked_folder_key =
            node_key.to_armored_private_key(Some(folder_passphrase.as_bytes()))?;

        let (encrypted_passphrase, passphrase_signature, _passphrase_session_key) =
            crate::node::crypto::NodeCrypto::encrypt_and_sign_passphrase(
                folder_passphrase.as_bytes(),
                &parent_secrets.base.key,
                &PgpPrivateKey(signing_key.clone()),
            )?;

        let (encrypted_name, name_hash_digest, _name_session_key) =
            crate::node::crypto::NodeCrypto::encrypt_and_sign_name(
                &self.name,
                &parent_secrets.hash_key,
                &parent_secrets.base.key,
                &PgpPrivateKey(signing_key.clone()),
            )?;

        let content_key = crate::crypto::CryptoGenerator::generate_session_key();

        let request = crate::api::file::FileCreationRequest {
            base: crate::api::node::NodeCreationRequest {
                name: encrypted_name,
                name_hash_digest,
                parent_link_id: self.parent_folder_uid.link_id.clone(),
                passphrase: encrypted_passphrase,
                passphrase_signature: passphrase_signature
                    .ok_or_else(|| anyhow::anyhow!("Passphrase signature missing"))?,
                key: locked_folder_key,
            },
            media_type: self.media_type.clone(),
            content_key_packet: Encryptor::default()
                .with_encryption_key(node_key.0.as_public_key())
                .encrypt_session_key(&content_key.to_rpgp_sk()?)?,
            // Official SDK signs the content key with the node key, not the address key.
            content_key_signature: node_key.sign_detached_armored(&content_key.key)?,
            signature_email_address: membership_address.email_address.clone(),
            // Lets the server tell this client's own stale drafts apart.
            client_uid: Some(self.client.uid().to_string()),
            intended_upload_size: None,
        };

        let volume_id = self.parent_folder_uid.volume_id.clone();
        let mut attempts_left = MAX_DRAFT_CREATION_ATTEMPTS;
        let response = loop {
            let error = match self
                .client
                .api()
                .files()
                .create_file(volume_id.clone(), request.clone())
                .await
            {
                Ok(response) => break response,
                Err(error) => error,
            };
            let Some((api_error, conflict)) = draft_conflict(&error) else {
                return Err(error);
            };
            match resolve_new_file_conflict(
                conflict.as_ref(),
                self.client.uid(),
                self.override_existing_draft_by_other_client,
            ) {
                DraftConflictResolution::DeleteFileDraft(link_id) if attempts_left > 0 => {
                    attempts_left -= 1;
                    tracing::info!(link_id = %link_id.raw(), "Removing stale file draft before retrying");
                    delete_file_draft(&self.client, volume_id.clone(), link_id).await?;
                }
                _ => {
                    return Err(NodeWithSameNameExistsError {
                        conflict,
                        source: api_error,
                    }
                    .into());
                }
            }
        };

        let draft_node_uid = NodeUid::new(
            self.parent_folder_uid.volume_id.clone(),
            response.identifiers.link_id,
        );
        let draft_revision_uid = RevisionUid::new(draft_node_uid, response.identifiers.revision_id);

        let block_verifier = self
            .client
            .block_verifier_factory()
            .create(
                draft_revision_uid.clone(),
                &PgpPrivateKey(node_key.0.clone()),
            )
            .await?;

        Ok(RevisionDraft {
            uid: draft_revision_uid,
            file_key: PgpPrivateKey(node_key.0),
            content_key,
            signing_key: PgpPrivateKey(signing_key),
            hash_key: Some(parent_secrets.hash_key),
            membership_address,
            block_verifier,
        })
    }
}

#[async_trait]
impl RevisionDraftProvider for NewRevisionDraftProvider {
    async fn get_draft(&self) -> anyhow::Result<RevisionDraft> {
        let node_secrets =
            crate::node::file::FileOperations::get_secrets(&self.client, self.node_uid.clone())
                .await?;
        let membership_address = membership_address_for(&self.client, &self.node_uid).await?;
        let signing_key = signing_key_for(&self.client, &membership_address.address_id).await?;

        let content_key = node_secrets.content_key.clone();

        let files = self.client.api().files();
        let mut attempts_left = MAX_DRAFT_CREATION_ATTEMPTS;
        let response = loop {
            let request = crate::api::revision::RevisionCreationRequest {
                current_revision_id: Some(self.revision_id.clone()),
                client_id: Some(self.client.uid().to_string()),
            };
            let error = match files
                .create_revision(
                    self.node_uid.volume_id.clone(),
                    self.node_uid.link_id.clone(),
                    request,
                )
                .await
            {
                Ok(response) => break response,
                Err(error) => error,
            };
            let Some((api_error, conflict)) = draft_conflict(&error) else {
                return Err(error);
            };
            match resolve_new_revision_conflict(conflict.as_ref(), self.client.uid()) {
                DraftConflictResolution::DeleteRevisionDraft(draft_id) if attempts_left > 0 => {
                    attempts_left -= 1;
                    tracing::info!(draft_revision_id = %draft_id.raw(), "Removing own stale revision draft before retrying");
                    files
                        .delete_revision(
                            self.node_uid.volume_id.clone(),
                            self.node_uid.link_id.clone(),
                            draft_id,
                        )
                        .await?
                        .to_result()?;
                }
                _ => {
                    return Err(RevisionDraftConflictError {
                        conflict,
                        source: api_error,
                    }
                    .into());
                }
            }
        };

        let draft_revision_uid =
            RevisionUid::new(self.node_uid.clone(), response.identity.revision_id);

        let block_verifier = self
            .client
            .block_verifier_factory()
            .create(draft_revision_uid.clone(), &node_secrets.base.key)
            .await?;

        Ok(RevisionDraft {
            uid: draft_revision_uid,
            file_key: node_secrets.base.key,
            content_key,
            signing_key: PgpPrivateKey(signing_key),
            hash_key: None,
            membership_address,
            block_verifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conflict(
        link: Option<&str>,
        revision: Option<&str>,
        draft: Option<&str>,
        owner: Option<&str>,
    ) -> RevisionConflict {
        RevisionConflict {
            link_id: link.map(|id| LinkId::new(id.into())),
            revision_id: revision.map(|id| RevisionId::new(id.into())),
            draft_revision_id: draft.map(|id| RevisionId::new(id.into())),
            draft_client_uid: owner.map(str::to_owned),
        }
    }

    fn api_error(status: u16, body: &str) -> anyhow::Error {
        ApiError::from_http(
            reqwest::StatusCode::from_u16(status).unwrap(),
            &reqwest::header::HeaderMap::new(),
            body,
        )
        .into()
    }

    #[test]
    fn draft_conflict_reads_details_of_already_exists_and_409_errors() {
        let error = api_error(
            409,
            r#"{"Code":2500,"Error":"Draft exists","Details":{"ConflictLinkID":"l","ConflictDraftRevisionID":"d","ConflictDraftClientUID":"me"}}"#,
        )
        .context("Failed to create revision");
        let (api, details) = draft_conflict(&error).expect("conflict");
        assert_eq!(api.http_status, Some(409));
        assert_eq!(
            details,
            Some(conflict(Some("l"), None, Some("d"), Some("me")))
        );

        let stale = api_error(409, r#"{"Code":2000,"Error":"Stale"}"#);
        assert!(draft_conflict(&stale).is_some_and(|(_, details)| details.is_none()));

        assert!(draft_conflict(&api_error(422, r#"{"Code":2001,"Error":"x"}"#)).is_none());
        assert!(draft_conflict(&anyhow::anyhow!("network down")).is_none());
    }

    #[test]
    fn own_stale_revision_draft_is_deleted_and_others_fail() {
        let own = conflict(Some("l"), Some("r"), Some("d"), Some("me"));
        assert!(matches!(
            resolve_new_revision_conflict(Some(&own), "me"),
            DraftConflictResolution::DeleteRevisionDraft(id) if id.raw() == "d"
        ));
        let other = conflict(Some("l"), Some("r"), Some("d"), Some("someone-else"));
        assert!(matches!(
            resolve_new_revision_conflict(Some(&other), "me"),
            DraftConflictResolution::Fail
        ));
        let stale_base = conflict(Some("l"), Some("r"), None, None);
        assert!(matches!(
            resolve_new_revision_conflict(Some(&stale_base), "me"),
            DraftConflictResolution::Fail
        ));
        assert!(matches!(
            resolve_new_revision_conflict(None, "me"),
            DraftConflictResolution::Fail
        ));
    }

    #[test]
    fn file_draft_without_revision_is_deleted_when_owned_or_overriding() {
        let own = conflict(Some("l"), None, Some("d"), Some("me"));
        assert!(matches!(
            resolve_new_file_conflict(Some(&own), "me", false),
            DraftConflictResolution::DeleteFileDraft(id) if id.raw() == "l"
        ));
        let other = conflict(Some("l"), None, Some("d"), Some("someone-else"));
        assert!(matches!(
            resolve_new_file_conflict(Some(&other), "me", false),
            DraftConflictResolution::Fail
        ));
        assert!(matches!(
            resolve_new_file_conflict(Some(&other), "me", true),
            DraftConflictResolution::DeleteFileDraft(_)
        ));
    }

    #[test]
    fn existing_file_with_committed_revision_is_never_deleted() {
        let committed = conflict(Some("l"), Some("r"), None, None);
        assert!(matches!(
            resolve_new_file_conflict(Some(&committed), "me", true),
            DraftConflictResolution::Fail
        ));
        let committed_with_draft = conflict(Some("l"), Some("r"), Some("d"), Some("me"));
        assert!(matches!(
            resolve_new_file_conflict(Some(&committed_with_draft), "me", true),
            DraftConflictResolution::Fail
        ));
    }

    #[test]
    fn conflict_errors_keep_the_api_error_as_source() {
        let error: anyhow::Error = NodeWithSameNameExistsError {
            conflict: None,
            source: ApiError::from_code(2500, "A file or folder with that name already exists"),
        }
        .into();
        assert!(error.to_string().contains("already exists"));
        assert!(ApiError::find(&error).is_some_and(ApiError::is_already_exists));
        assert!(
            error
                .downcast_ref::<NodeWithSameNameExistsError>()
                .is_some()
        );
    }
}

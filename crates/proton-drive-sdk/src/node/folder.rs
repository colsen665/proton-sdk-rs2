use crate::client::ProtonDriveClient;
use crate::node::crypto::NodeCrypto;
use crate::node::{
    DegradedNode, DtoToMetadataConverter, Node, NodeBase, NodeMetadataResult, NodeSecrets, NodeUid,
    OwnedBy,
};
use crate::pgp::{PgpArmoredMessage, PgpPrivateKey};
use crate::utils::PotentialObject;
use chrono::{DateTime, SubsecRound, Utc};
use std::sync::Arc;

pub struct FolderOperations;

impl FolderOperations {
    pub async fn get_folder_size(
        client: &ProtonDriveClient,
        folder_uid: NodeUid,
    ) -> anyhow::Result<FolderSizeInfo> {
        let response = client
            .api()
            .folders()
            .get_folder_size(folder_uid.volume_id, folder_uid.link_id)
            .await?;

        Ok(FolderSizeInfo {
            size: response.descendents_size,
            number_of_descendants: response.descendents_count,
        })
    }

    pub async fn create(
        client: &ProtonDriveClient,
        parent_uid: NodeUid,
        name: String,
        last_modification_time: Option<std::time::SystemTime>,
    ) -> anyhow::Result<FolderNode> {
        let membership_address = client
            .account()
            .get_address_primary_private_key(&crate::account::AddressId::new(
                client
                    .account()
                    .get_default_address()
                    .await?
                    .address_id
                    .clone(),
            ))
            .await?;

        let parent_secrets = Self::get_secrets(client, parent_uid.clone()).await?;
        let parent_key = parent_secrets.base.key;

        let folder_key = crate::crypto::CryptoGenerator::generate_private_key()?;
        let folder_passphrase = crate::crypto::CryptoGenerator::generate_passphrase();
        let locked_folder_key =
            folder_key.to_armored_private_key(Some(folder_passphrase.as_bytes()))?;

        let folder_secrets = FolderSecrets {
            base: NodeSecrets {
                key: folder_key,
                passphrase_session_key: crate::crypto::CryptoGenerator::generate_session_key(),
                passphrase_pgp_session_key: None,
                name_session_key: crate::crypto::CryptoGenerator::generate_session_key(),
                passphrase_for_anonymous_move: None,
            },
            hash_key: crate::crypto::CryptoGenerator::generate_folder_hash_key().to_vec(),
        };

        let (encrypted_passphrase, passphrase_signature, _passphrase_session_key) =
            NodeCrypto::encrypt_and_sign_passphrase(
                folder_passphrase.as_bytes(),
                &parent_key,
                &PgpPrivateKey(membership_address.clone()),
            )?;

        let (encrypted_name, name_hash_digest, _name_session_key) =
            NodeCrypto::encrypt_and_sign_name(
                &name,
                &parent_secrets.hash_key,
                &parent_key,
                &PgpPrivateKey(membership_address.clone()),
            )?;

        let encrypted_hash_key = NodeCrypto::encrypt_folder_hash_key(
            &folder_secrets.base.key,
            &folder_secrets.hash_key,
            &PgpPrivateKey(membership_address.clone()),
        )?;

        // Folder XAttr carries millisecond precision; keep the returned node consistent
        // with what a later read decodes.
        let claimed_modification_time =
            last_modification_time.map(|t| DateTime::<Utc>::from(t).trunc_subsecs(3));
        let encrypted_extended_attributes = encrypt_folder_extended_attributes(
            claimed_modification_time,
            &folder_secrets.base.key,
            &PgpPrivateKey(membership_address.clone()),
        )?;

        let request = crate::api::folder::FolderCreationRequest {
            base: crate::api::node::NodeCreationRequest {
                name: encrypted_name,
                name_hash_digest,
                parent_link_id: parent_uid.link_id.clone(),
                passphrase: encrypted_passphrase,
                passphrase_signature: passphrase_signature
                    .ok_or_else(|| anyhow::anyhow!("Passphrase signature missing"))?,
                key: locked_folder_key,
            },
            hash_key: encrypted_hash_key,
            signature_email_address: client
                .account()
                .get_default_address()
                .await?
                .email_address
                .clone(),
            extended_attributes: encrypted_extended_attributes,
        };

        let response = client
            .api()
            .folders()
            .create_folder(parent_uid.volume_id.clone(), request)
            .await?;

        let node = FolderNode {
            base: NodeBase {
                uid: NodeUid::new(
                    parent_uid.volume_id.clone(),
                    response.folder_id.value.clone(),
                ),
                parent_uid: Some(parent_uid),
                name: name.clone(),
                owned_by: Some(OwnedBy {
                    email: Some(
                        client
                            .account()
                            .get_default_address()
                            .await?
                            .email_address
                            .clone(),
                    ),
                    organisation: None,
                }),
                creation_time: Utc::now(),
                trash_time: None,
                is_shared: false,
                is_shared_by_url: false,
                direct_role: crate::node::NodeMemberRole::Admin,
                membership: None,
                ..NodeBase::default()
            },
            claimed_modification_time,
        };

        // Cache the newly created folder secrets
        client
            .cache()
            .secrets()
            .set_folder_secrets(node.base.uid.clone(), PotentialObject::Node(folder_secrets))
            .await?;

        Ok(node)
    }

    pub async fn enumerate_children(
        client: &ProtonDriveClient,
        folder_uid: NodeUid,
    ) -> anyhow::Result<Vec<PotentialObject<Node, DegradedNode>>> {
        let volume_id = folder_uid.volume_id.clone();
        let mut anchor_id = None;
        let mut must_try_more_results = true;
        let mut results = Vec::new();

        let folder_secrets = Self::get_secrets(client, folder_uid.clone()).await?;
        let mut batch_loader = crate::node::NodeBatchLoader::new(
            Arc::new(client.clone()),
            volume_id.clone(),
            Some(folder_secrets.base.key),
        );

        while must_try_more_results {
            let response = client
                .api()
                .folders()
                .get_children(
                    volume_id.clone(),
                    folder_uid.link_id.clone(),
                    anchor_id.clone(),
                )
                .await?;

            must_try_more_results = response.more_results_exist;
            if let Some(last_id) = response.link_ids.last() {
                anchor_id = Some(last_id.clone());
            }

            for child_link_id in response.link_ids {
                // Check cache first (simplified for now)
                let batch_results = batch_loader.queue_and_try_load_batch(child_link_id).await?;
                results.extend(batch_results);
            }
        }

        let remaining = batch_loader.load_remaining().await?;
        results.extend(remaining);

        Ok(results)
    }

    /// Streaming version of [`enumerate_children`]: fetches and decrypts children
    /// page-by-page, sending each item through `tx` as soon as it is ready.
    /// Intended to be called from inside a `tokio::spawn` so the caller gets
    /// items without waiting for the whole listing to complete.
    pub async fn enumerate_children_to_channel(
        client: ProtonDriveClient,
        folder_uid: NodeUid,
        tx: tokio::sync::mpsc::Sender<anyhow::Result<PotentialObject<Node, DegradedNode>>>,
    ) {
        let result: anyhow::Result<()> = async {
            let volume_id = folder_uid.volume_id.clone();
            let folder_secrets = Self::get_secrets(&client, folder_uid.clone()).await?;
            let mut batch_loader = crate::node::NodeBatchLoader::new(
                Arc::new(client.clone()),
                volume_id.clone(),
                Some(folder_secrets.base.key),
            );

            let mut anchor_id = None;
            let mut must_try_more_results = true;
            while must_try_more_results {
                let response = client
                    .api()
                    .folders()
                    .get_children(
                        volume_id.clone(),
                        folder_uid.link_id.clone(),
                        anchor_id.clone(),
                    )
                    .await?;

                must_try_more_results = response.more_results_exist;
                if let Some(last) = response.link_ids.last() {
                    anchor_id = Some(last.clone());
                }
                for child_id in response.link_ids {
                    let batch = batch_loader.queue_and_try_load_batch(child_id).await?;
                    for item in batch {
                        if tx.send(Ok(item)).await.is_err() {
                            return Ok(()); // receiver dropped — stop silently
                        }
                    }
                }
            }

            let remaining = batch_loader.load_remaining().await?;
            for item in remaining {
                if tx.send(Ok(item)).await.is_err() {
                    return Ok(());
                }
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            let _ = tx.send(Err(e)).await;
        }
    }

    pub async fn get_secrets(
        client: &ProtonDriveClient,
        folder_uid: crate::node::NodeUid,
    ) -> anyhow::Result<FolderSecrets> {
        if let Some(secrets) = client
            .cache()
            .secrets()
            .try_get_folder_secrets(folder_uid.clone())
            .await?
        {
            return secrets.result().map_err(|e| anyhow::anyhow!(e.to_string()));
        }

        let metadata_result: NodeMetadataResult = Box::pin(
            DtoToMetadataConverter::get_fresh_node_metadata(client, folder_uid.clone(), None),
        )
        .await?;

        metadata_result
            .try_get_folder_secrets_else_error()
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderSizeInfo {
    pub size: i64,
    pub number_of_descendants: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FolderNode {
    #[serde(flatten)]
    pub base: crate::node::NodeBase,
    /// Last-modification time claimed in the folder's extended attributes (XAttr);
    /// `None` if the folder has no XAttr, it is unreadable, or it carries no time.
    #[serde(default)]
    pub claimed_modification_time: Option<DateTime<Utc>>,
}

/// Builds the folder XAttr JSON (`{"Common":{"ModificationTime":"<ISO 8601>"}}`), encrypts
/// it to the folder key and signs it with `signing_key`, as the official SDKs do on folder
/// creation. Returns `None` without a modification time, like the JS SDK.
pub(crate) fn encrypt_folder_extended_attributes(
    modification_time: Option<DateTime<Utc>>,
    folder_key: &PgpPrivateKey,
    signing_key: &PgpPrivateKey,
) -> anyhow::Result<Option<PgpArmoredMessage>> {
    use proton_rpgp::AsPublicKeyRef;

    let Some(modification_time) = modification_time else {
        return Ok(None);
    };
    let xattr = crate::api::attr::ExtendedAttributes {
        common: Some(crate::api::attr::CommonExtendedAttributes {
            size: None,
            modification_time: Some(modification_time),
            block_sizes: None,
            digests: None,
        }),
        media: None,
        additional_metadata: Default::default(),
    };
    let json = serde_json::to_vec(&xattr)?;
    let result = proton_rpgp::Encryptor::default()
        .with_encryption_key(folder_key.0.as_public_key())
        .with_signing_key(&signing_key.0)
        .encrypt(&json)?;
    Ok(Some(PgpArmoredMessage(String::from_utf8(result.armor()?)?)))
}

/// Decrypts a folder XAttr with the folder key, verifies its signature against the node
/// authorship claim, and returns `Common.ModificationTime`. Returns `None` when the XAttr
/// is absent; logs a warning and returns `None` when it cannot be decrypted or parsed.
/// A failed signature check is logged and the claimed time is still returned.
pub(crate) fn decrypt_folder_modification_time(
    message: Option<&PgpArmoredMessage>,
    folder_key: &PgpPrivateKey,
    authorship_claim: &crate::node::authorship::AuthorshipClaim,
    folder_uid: &NodeUid,
) -> Option<DateTime<Utc>> {
    let message = message?;
    let parsed = NodeCrypto::decrypt_message(message, None, [folder_key], authorship_claim)
        .map_err(|e| anyhow::anyhow!("failed to decrypt folder extended attributes: {e}"))
        .and_then(|(bytes, _, verification_failure)| {
            if verification_failure.is_some() {
                tracing::warn!(
                    folder = %folder_uid,
                    author = ?authorship_claim.author.email_address,
                    "folder extended attributes signature verification failed"
                );
            }
            serde_json::from_slice::<crate::api::attr::ExtendedAttributes>(&bytes)
                .map_err(|e| anyhow::anyhow!("failed to parse folder extended attributes: {e}"))
        });
    match parsed {
        Ok(xattr) => xattr.common.and_then(|c| c.modification_time),
        Err(error) => {
            tracing::warn!(
                folder = %folder_uid,
                error = %error,
                "ignoring unreadable folder extended attributes"
            );
            None
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct DegradedFolderNode {
    pub base: crate::node::DegradedNodeBase,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FolderSecrets {
    pub base: NodeSecrets,
    pub hash_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FolderMetadata {
    pub node: FolderNode,
    pub secrets: FolderSecrets,
    pub membership_share_id: Option<crate::share::ShareId>,
    pub name_hash_digest: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DegradedFolderMetadata {
    pub node: DegradedFolderNode,
    pub secrets: DegradedFolderSecrets,
    pub membership_share_id: Option<crate::share::ShareId>,
    pub name_hash_digest: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DegradedFolderSecrets {
    pub base: crate::node::secrets::DegradedNodeSecrets,
    pub hash_key: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoGenerator;
    use crate::node::authorship::AuthorshipClaim;
    use chrono::TimeZone;
    use proton_rpgp::AsPublicKeyRef;

    fn claim_for(signer: &PgpPrivateKey) -> AuthorshipClaim {
        AuthorshipClaim {
            keys: vec![signer.0.as_public_key().clone()],
            author: crate::author::Author {
                email_address: Some("member@example.test".into()),
            },
            key_retrieval_error_message: None,
        }
    }

    #[test]
    fn folder_xattr_round_trips_modification_time() {
        let folder_key = CryptoGenerator::generate_private_key().unwrap();
        let address_key = CryptoGenerator::generate_private_key().unwrap();
        let mtime = Utc.timestamp_millis_opt(1_234_567_890_123).unwrap();

        let message = encrypt_folder_extended_attributes(Some(mtime), &folder_key, &address_key)
            .unwrap()
            .unwrap();

        // Same JSON shape as the JS and C# SDKs write on folder creation.
        let (bytes, _, verification_failure) =
            NodeCrypto::decrypt_message(&message, None, [&folder_key], &claim_for(&address_key))
                .unwrap();
        assert!(verification_failure.is_none());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            serde_json::json!({"Common": {"ModificationTime": "2009-02-13T23:31:30.123Z"}})
        );

        let decoded = decrypt_folder_modification_time(
            Some(&message),
            &folder_key,
            &claim_for(&address_key),
            &NodeUid::from_parts("volume", "folder"),
        );
        assert_eq!(decoded, Some(mtime));
    }

    /// Builds folder link details the way `FolderOperations::create` encrypts them.
    fn folder_link_details(
        parent_key: &PgpPrivateKey,
        signing_key: &PgpPrivateKey,
        modification_time: Option<DateTime<Utc>>,
    ) -> crate::api::links::LinkDetailsDto {
        let folder_key = CryptoGenerator::generate_private_key().unwrap();
        let passphrase = CryptoGenerator::generate_passphrase();
        let locked_key = folder_key
            .to_armored_private_key(Some(passphrase.as_bytes()))
            .unwrap();
        let (encrypted_passphrase, passphrase_signature, _) =
            NodeCrypto::encrypt_and_sign_passphrase(passphrase.as_bytes(), parent_key, signing_key)
                .unwrap();
        let parent_hash_key = CryptoGenerator::generate_folder_hash_key();
        let (name, name_hash, _) =
            NodeCrypto::encrypt_and_sign_name("Photos", &parent_hash_key, parent_key, signing_key)
                .unwrap();
        let hash_key = NodeCrypto::encrypt_folder_hash_key(
            &folder_key,
            &CryptoGenerator::generate_folder_hash_key(),
            signing_key,
        )
        .unwrap();
        let xattr = encrypt_folder_extended_attributes(modification_time, &folder_key, signing_key)
            .unwrap();
        serde_json::from_value(serde_json::json!({
            "Link": {
                "LinkID": "folder", "ParentLinkID": "parent", "Type": 1, "State": 1,
                "CreateTime": 1_600_000_000, "ModifyTime": 1_600_000_000,
                "Name": name.0, "NameHash": hex::encode(name_hash),
                "NodeKey": locked_key.0, "NodePassphrase": encrypted_passphrase.0,
                "NodePassphraseSignature": passphrase_signature.unwrap().0,
                "SignatureEmail": "member@example.test",
                "NameSignatureEmail": "member@example.test"
            },
            "Folder": {
                "NodeHashKey": hash_key.0,
                "XAttr": xattr.map(|m| m.0),
            }
        }))
        .unwrap()
    }

    async fn convert_folder(
        details: crate::api::links::LinkDetailsDto,
        parent_key: &PgpPrivateKey,
    ) -> FolderNode {
        let (client, _) = crate::test_support::client().await;
        let metadata = DtoToMetadataConverter::convert_dto_to_node_metadata_with_client(
            &client,
            crate::volume::VolumeId::new("volume".into()),
            details,
            Some(parent_key),
        )
        .await
        .unwrap();
        match metadata {
            PotentialObject::Node(m) => match m.node() {
                Node::Folder(folder) => folder,
                other => panic!("expected folder, got {other:?}"),
            },
            PotentialObject::Degraded(_) => panic!("folder conversion degraded"),
        }
    }

    #[tokio::test]
    async fn node_conversion_exposes_folder_modification_time() {
        let parent_key = CryptoGenerator::generate_private_key().unwrap();
        let address_key = CryptoGenerator::generate_private_key().unwrap();
        let mtime = Utc.timestamp_millis_opt(1_650_000_000_250).unwrap();

        let details = folder_link_details(&parent_key, &address_key, Some(mtime));
        let folder = convert_folder(details, &parent_key).await;
        assert_eq!(folder.base.name, "Photos");
        assert_eq!(folder.claimed_modification_time, Some(mtime));

        let details = folder_link_details(&parent_key, &address_key, None);
        let folder = convert_folder(details, &parent_key).await;
        assert_eq!(folder.claimed_modification_time, None);
    }

    #[test]
    fn folder_without_modification_time_has_no_xattr() {
        let key = CryptoGenerator::generate_private_key().unwrap();
        assert!(
            encrypt_folder_extended_attributes(None, &key, &key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn absent_or_unreadable_folder_xattr_gives_none() {
        let folder_key = CryptoGenerator::generate_private_key().unwrap();
        let other_key = CryptoGenerator::generate_private_key().unwrap();
        let uid = NodeUid::from_parts("volume", "folder");
        let claim = claim_for(&folder_key);
        assert_eq!(
            decrypt_folder_modification_time(None, &folder_key, &claim, &uid),
            None
        );
        let wrong_key = encrypt_folder_extended_attributes(
            Some(Utc.timestamp_opt(1_600_000_000, 0).unwrap()),
            &other_key,
            &other_key,
        )
        .unwrap()
        .unwrap();
        for message in [wrong_key, PgpArmoredMessage("invalid".into())] {
            assert_eq!(
                decrypt_folder_modification_time(Some(&message), &folder_key, &claim, &uid),
                None
            );
        }
    }
}

use crate::api::share::ShareTargetType;
use crate::client::ProtonDriveClient;
use crate::error::ProtonDriveError;
use crate::node::NodeUid;
use crate::node::secrets::ShareAndKey;
use crate::pgp::{PgpArmoredMessage, PgpArmoredPrivateKey, PgpArmoredSignature, PgpPrivateKey};
use crate::share::{Share, ShareId};
use crate::volume::VolumeId;

pub struct ShareOperations;

impl ShareOperations {
    pub async fn get_share(
        client: &ProtonDriveClient,
        share_id: ShareId,
    ) -> anyhow::Result<ShareAndKey> {
        if let Some(share) = client
            .cache()
            .entities()
            .try_get_share(share_id.clone())
            .await?
        {
            if let Some(key) = client
                .cache()
                .secrets()
                .try_get_share_key(share_id.clone())
                .await?
            {
                return Ok(ShareAndKey { share, key });
            }
        }

        let response = client.api().shares().get_share(share_id.clone()).await?;

        // Match C# logic: decrypt share key, with the share from this one response
        let (share, key) = ShareCrypto::decrypt_share_with_creation_time(
            client,
            ShareCrypto::share_of(&response),
            &response.key,
            &response.passphrase,
            &response.passphrase_signature,
            response
                .invitee_share_passphrase_session_key_signature
                .as_ref(),
            &response.creator_email_address,
            response.creation_time,
        )
        .await?;

        client.cache().entities().set_share(share.clone()).await?;
        client
            .cache()
            .secrets()
            .set_share_key(share.id.clone(), key.clone())
            .await?;

        Ok(ShareAndKey { share, key })
    }
}

pub struct ShareCrypto;

impl ShareCrypto {
    /// Decrypts a share's key from its parts. The share's root folder and
    /// type are not among them, so this fetches the share once for those;
    /// a caller that holds the share's response should use
    /// [`ShareOperations::get_share`], which needs no second request.
    pub async fn decrypt_share(
        client: &ProtonDriveClient,
        share_id: ShareId,
        encrypted_key: &PgpArmoredPrivateKey,
        encrypted_passphrase: &PgpArmoredMessage,
        passphrase_signature: &PgpArmoredSignature,
        invitee_signature: Option<&PgpArmoredSignature>,
        creator_email: &str,
        address_id: &crate::account::AddressId,
    ) -> anyhow::Result<(Share, PgpPrivateKey)> {
        let response = client.api().shares().get_share(share_id.clone()).await?;
        let share = Share {
            id: share_id,
            membership_address_id: address_id.clone(),
            ..Self::share_of(&response)
        };
        Self::decrypt_share_with_creation_time(
            client,
            share,
            encrypted_key,
            encrypted_passphrase,
            passphrase_signature,
            invitee_signature,
            creator_email,
            None,
        )
        .await
    }

    /// The share that a `GET shares/{id}` response describes.
    pub(crate) fn share_of(response: &crate::api::share::ShareResponse) -> Share {
        Share {
            id: response.id.clone(),
            root_folder_id: NodeUid::new(response.volume_id.clone(), response.root_link_id.clone()),
            membership_address_id: response.address_id.clone(),
            share_type: response.r#type,
        }
    }

    /// Decrypts the key of `share`, whose metadata the caller already has
    /// (as C#'s `ShareCrypto.DecryptShareAsync`): no request for the share.
    pub(crate) async fn decrypt_share_with_creation_time(
        client: &ProtonDriveClient,
        share: Share,
        encrypted_key: &PgpArmoredPrivateKey,
        encrypted_passphrase: &PgpArmoredMessage,
        passphrase_signature: &PgpArmoredSignature,
        invitee_signature: Option<&PgpArmoredSignature>,
        creator_email: &str,
        creation_time: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<(Share, PgpPrivateKey)> {
        let address_keys = client
            .account()
            .get_address_private_keys(&share.membership_address_id)
            .await?;
        let user_keys = client.account().get_user_keys().await?;

        let mut all_keys = Vec::new();
        for k in address_keys {
            all_keys.push(PgpPrivateKey(k));
        }
        for k in user_keys {
            all_keys.push(PgpPrivateKey(k));
        }

        let authorship_claim = crate::node::authorship::AuthorshipClaim::create(
            client.account().clone(),
            Some(creator_email),
        )
        .await;

        let metric_item = crate::telemetry::MetricItem {
            uid: share.id.raw().clone(),
            creation_time,
            third_party: None,
            sdk: None,
        };
        let decrypted = crate::node::crypto::NodeCrypto::decrypt_message(
            encrypted_passphrase,
            invitee_signature.or(Some(passphrase_signature)),
            &all_keys,
            &authorship_claim,
        );
        match &decrypted {
            Err(error) => {
                client
                    .integrity_reporter()
                    .report_unchecked(client, &metric_item, "shareKey", Some(error), false, None)
                    .await
            }
            Ok((_, _, Some(_))) => {
                client
                    .integrity_reporter()
                    .report_unchecked(client, &metric_item, "shareKey", None, true, None)
                    .await
            }
            _ => {}
        }
        match decrypted {
            Ok((passphrase, _, _)) => {
                // Unlock the share private key using the decrypted passphrase
                let share_key = crate::node::crypto::NodeCrypto::unlock_key_with_passphrase(
                    encrypted_key,
                    &passphrase,
                );
                let share_key = match share_key {
                    Ok(key) => key,
                    Err(error) => {
                        client
                            .integrity_reporter()
                            .report_unchecked(
                                client,
                                &metric_item,
                                "shareKey",
                                Some(&error.to_string()),
                                false,
                                None,
                            )
                            .await;
                        anyhow::bail!("Failed to unlock share key: {:?}", error);
                    }
                };

                return Ok((share, share_key));
            }
            Err(e) => {
                anyhow::bail!("Failed to decrypt share passphrase: {}", e)
            }
        }
    }
}

pub struct SharingOperations;

impl SharingOperations {
    pub async fn enumerate_shared_node_uids(
        client: &ProtonDriveClient,
        volume_id: VolumeId,
    ) -> anyhow::Result<Vec<NodeUid>> {
        let mut uids = Vec::new();
        let mut anchor_id = None;
        loop {
            let response = client
                .api()
                .shares()
                .get_shared_by_me(volume_id.clone(), anchor_id)
                .await?;
            for link in &response.links {
                uids.push(NodeUid::new(volume_id.clone(), link.link_id.clone()));
            }
            if !response.more || response.anchor_id.is_none() {
                break;
            }
            anchor_id = response.anchor_id;
        }
        Ok(uids)
    }

    pub async fn enumerate_shared_with_me_node_uids(
        client: &ProtonDriveClient,
        share_target_types: &[ShareTargetType],
    ) -> anyhow::Result<Vec<NodeUid>> {
        let mut uids = Vec::new();
        let mut anchor_id = None;
        loop {
            let response = client.api().shares().get_shared_with_me(anchor_id).await?;
            for link in &response.links {
                if share_target_types.contains(&link.share_target_type) {
                    uids.push(NodeUid::new(link.volume_id.clone(), link.link_id.clone()));
                }
            }
            if !response.more || response.anchor_id.is_none() {
                break;
            }
            anchor_id = response.anchor_id;
        }
        Ok(uids)
    }

    pub async fn leave_shared_node(
        client: &ProtonDriveClient,
        node_uid: NodeUid,
    ) -> anyhow::Result<()> {
        let response = client
            .api()
            .links()
            .get_details(node_uid.volume_id.clone(), vec![node_uid.link_id.clone()])
            .await?;

        let membership = response
            .links
            .into_iter()
            .find(|link| link.link.id == node_uid.link_id)
            .and_then(|link| link.membership)
            .ok_or_else(|| {
                ProtonDriveError::Validation(
                    "You can leave only an item that is shared with you".into(),
                )
            })?;

        client
            .api()
            .shares()
            .remove_member(membership.share_id, membership.membership_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{AccountClient, AddressId};
    use crate::api::DefaultDriveApiClientsFactory;
    use crate::cache::client::DefaultDriveClientCache;
    use crate::cache::entity::DefaultDriveEntityCache;
    use crate::cache::secret::DefaultDriveSecretCache;
    use crate::crypto::CryptoGenerator;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use proton_rpgp::PublicKey;
    use proton_sdk_rs2::cache::InMemoryCacheRepository;
    use proton_sdk_rs2::client::AlwaysDisabledFeatureFlagProvider;
    use proton_sdk_rs2::protobuf::Address;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The share member: its address key decrypts the share passphrase.
    struct Member(PgpPrivateKey);

    #[async_trait]
    impl AccountClient for Member {
        async fn get_address(&self, _: &AddressId) -> anyhow::Result<Address> {
            unreachable!()
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
            assert_eq!(id.raw(), "address");
            Ok(vec![self.0.0.clone()])
        }

        async fn get_address_public_keys(&self, _: &str) -> anyhow::Result<Vec<PublicKey>> {
            Ok(vec![PublicKey::from(&self.0.0)])
        }

        async fn get_user_keys(&self) -> anyhow::Result<Vec<proton_rpgp::PrivateKey>> {
            Ok(Vec::new())
        }

        async fn get_user_storage_info(&self) -> anyhow::Result<(i64, i64)> {
            unreachable!()
        }
    }

    /// A `GET shares/{id}` answer for a standard share whose passphrase is
    /// encrypted to and signed by `member`.
    fn share_response(member: &Member) -> String {
        let passphrase = CryptoGenerator::generate_passphrase();
        let key = CryptoGenerator::generate_private_key()
            .unwrap()
            .to_armored_private_key(Some(passphrase.as_bytes()))
            .unwrap();
        let (message, signature, _) = crate::node::crypto::NodeCrypto::encrypt_and_sign_passphrase(
            passphrase.as_bytes(),
            &member.0,
            &member.0,
        )
        .unwrap();
        serde_json::json!({
            "Code": 1000,
            "ShareID": "share",
            "VolumeID": "volume",
            "Type": 2,
            "State": 1,
            "Creator": "owner@example.test",
            "Locked": false,
            "CreateTime": 1_700_000_000,
            "LinkID": "root",
            "LinkType": 1,
            "Key": key.0,
            "Passphrase": message.0,
            "PassphraseSignature": signature.unwrap().0,
            "AddressID": "address",
        })
        .to_string()
    }

    /// Answers every request with `body` and records its request line.
    async fn serve(
        listener: tokio::net::TcpListener,
        body: String,
        requests: Arc<Mutex<Vec<String>>>,
    ) {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let line = String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            requests.lock().push(line);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_share_is_fetched_once() {
        let member = Member(CryptoGenerator::generate_private_key().unwrap());
        let body = share_response(&member);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = reqwest::Url::parse(&format!("http://{}/drive/", listener.local_addr().unwrap()))
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server = tokio::spawn(serve(listener, body, requests.clone()));
        let http = reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build();
        let cache = Arc::new(DefaultDriveClientCache::new(
            Arc::new(DefaultDriveEntityCache::new(Arc::new(
                InMemoryCacheRepository::new(),
            ))),
            Arc::new(DefaultDriveSecretCache::new(Arc::new(
                InMemoryCacheRepository::new(),
            ))),
        ));
        let client = ProtonDriveClient::from_http_clients(
            http.clone(),
            http,
            url.clone(),
            url.clone(),
            Arc::new(member),
            cache,
            Arc::new(AlwaysDisabledFeatureFlagProvider),
            Arc::new(crate::test_support::RecordingTelemetry::default()),
            Arc::new(DefaultDriveApiClientsFactory),
            "test".into(),
            None,
            url.to_string(),
        )
        .unwrap();

        let first = ShareOperations::get_share(&client, ShareId::new("share".into()))
            .await
            .unwrap();
        assert_eq!(*requests.lock(), ["GET /drive/shares/share HTTP/1.1"]);
        assert_eq!(first.share.id.raw(), "share");
        assert_eq!(
            first.share.root_folder_id,
            NodeUid::from_parts("volume", "root")
        );
        assert_eq!(first.share.membership_address_id.raw(), "address");
        assert_eq!(
            first.share.share_type,
            crate::api::share::ShareType::Standard
        );

        // Cached: no further request.
        let again = ShareOperations::get_share(&client, ShareId::new("share".into()))
            .await
            .unwrap();
        assert_eq!(again.share.root_folder_id, first.share.root_folder_id);
        assert_eq!(requests.lock().len(), 1);
        server.abort();
    }
}

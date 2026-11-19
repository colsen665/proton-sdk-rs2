//! In-memory client components for tests that must not contact a live account.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use proton_sdk_rs2::cache::InMemoryCacheRepository;
use proton_sdk_rs2::client::{AlwaysDisabledFeatureFlagProvider, FeatureFlagProvider, Telemetry};
use proton_sdk_rs2::protobuf::Address;

use crate::account::{AccountClient, AddressId};
use crate::api::DefaultDriveApiClientsFactory;
use crate::cache::entity::{DefaultDriveEntityCache, DriveEntityCache};
use crate::cache::secret::DefaultDriveSecretCache;
use crate::client::ProtonDriveClient;
use crate::share::{Share, ShareId};

#[derive(Default)]
pub(crate) struct RecordingTelemetry(pub Mutex<Vec<(String, serde_json::Value)>>);

#[async_trait]
impl Telemetry for RecordingTelemetry {
    async fn record_metric(&self, name: String, payload: Option<Vec<u8>>) {
        // Most metrics are JSON; `uploadError` carries the error text.
        let payload = payload.map_or(serde_json::Value::Null, |payload| {
            serde_json::from_slice(&payload).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&payload).into_owned())
            })
        });
        self.0.lock().push((name, payload));
    }
}

struct TestAccount;

#[async_trait]
impl AccountClient for TestAccount {
    async fn get_address(&self, id: &AddressId) -> anyhow::Result<Address> {
        assert_eq!(id.raw(), "my-files-member");
        Ok(Address {
            address_id: id.raw().into(),
            email_address: "member@example.test".into(),
            ..Default::default()
        })
    }

    async fn get_default_address(&self) -> anyhow::Result<Address> {
        panic!("use the My Files member, not the default address")
    }

    async fn get_address_primary_private_key(
        &self,
        _: &AddressId,
    ) -> anyhow::Result<proton_rpgp::PrivateKey> {
        panic!("unexpected key lookup")
    }

    async fn get_address_private_keys(
        &self,
        _: &AddressId,
    ) -> anyhow::Result<Vec<proton_rpgp::PrivateKey>> {
        panic!("unexpected key lookup")
    }

    async fn get_address_public_keys(
        &self,
        _: &str,
    ) -> anyhow::Result<Vec<proton_rpgp::PublicKey>> {
        Ok(Vec::new())
    }

    async fn get_user_keys(&self) -> anyhow::Result<Vec<proton_rpgp::PrivateKey>> {
        panic!("unexpected user key lookup")
    }

    async fn get_user_storage_info(&self) -> anyhow::Result<(i64, i64)> {
        panic!("unexpected quota lookup")
    }
}

/// Answers every feature flag with the same value.
pub(crate) struct FixedFeatureFlags(pub bool);

#[async_trait]
impl FeatureFlagProvider for FixedFeatureFlags {
    async fn is_enabled(&self, _flag_name: String) -> anyhow::Result<bool> {
        Ok(self.0)
    }
}

/// A client whose Drive API is at `api_url` (a local test server), with the
/// given feature flags.
pub(crate) fn client_at(
    api_url: reqwest::Url,
    feature_flags: Arc<dyn FeatureFlagProvider>,
) -> ProtonDriveClient {
    let http = reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build();
    let api = crate::api::DriveApiClientsFactory::create(
        &DefaultDriveApiClientsFactory,
        http.clone(),
        http.clone(),
        api_url.clone(),
        api_url.clone(),
        None,
    );
    let cache = Arc::new(crate::cache::client::DefaultDriveClientCache::new(
        Arc::new(DefaultDriveEntityCache::new(Arc::new(
            InMemoryCacheRepository::new(),
        ))),
        Arc::new(DefaultDriveSecretCache::new(Arc::new(
            InMemoryCacheRepository::new(),
        ))),
    ));
    ProtonDriveClient::from_components(
        Arc::new(TestAccount),
        api,
        cache,
        Arc::new(crate::block::verify::DefaultBlockVerifierFactory::new(
            http, api_url, None,
        )),
        feature_flags,
        Arc::new(RecordingTelemetry::default()),
        "test-client".into(),
        None,
    )
}

pub(crate) async fn client() -> (ProtonDriveClient, Arc<RecordingTelemetry>) {
    let entities = Arc::new(DefaultDriveEntityCache::new(Arc::new(
        InMemoryCacheRepository::new(),
    )));
    let share_id = ShareId::new("my-files-share".into());
    entities
        .set_my_files_share_id(share_id.clone())
        .await
        .unwrap();
    entities
        .set_share(Share {
            id: share_id,
            root_folder_id: crate::node::NodeUid::from_parts("volume", "root"),
            membership_address_id: AddressId::new("my-files-member".into()),
            share_type: crate::api::share::ShareType::Main,
        })
        .await
        .unwrap();
    let telemetry = Arc::new(RecordingTelemetry::default());
    let client = ProtonDriveClient::from_http_client_factory_with_drive_api_clients_factory(
        Arc::new(TestAccount),
        entities,
        Arc::new(DefaultDriveSecretCache::new(Arc::new(
            InMemoryCacheRepository::new(),
        ))),
        Arc::new(AlwaysDisabledFeatureFlagProvider),
        telemetry.clone(),
        Arc::new(DefaultDriveApiClientsFactory),
        None,
    )
    .unwrap();
    (client, telemetry)
}

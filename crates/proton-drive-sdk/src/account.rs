use async_trait::async_trait;
use proton_rpgp::{PrivateKey, PublicKey};
use proton_sdk_rs2::account::ProtonAccountClient;
use proton_sdk_rs2::protobuf::Address;
use proton_sdk_rs2::session::ProtonAPISession;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct AddressId(String);

impl Default for AddressId {
    fn default() -> Self {
        Self(String::new())
    }
}

impl AddressId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn raw(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct AddressKeyId(String);

impl Default for AddressKeyId {
    fn default() -> Self {
        Self(String::new())
    }
}

impl AddressKeyId {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn raw(&self) -> &str {
        &self.0
    }
}

#[async_trait]
pub trait AccountClient: Send + Sync {
    async fn get_address(&self, address_id: &AddressId) -> anyhow::Result<Address>;
    async fn get_default_address(&self) -> anyhow::Result<Address>;
    async fn get_address_primary_private_key(
        &self,
        address_id: &AddressId,
    ) -> anyhow::Result<PrivateKey>;
    async fn get_address_private_keys(
        &self,
        address_id: &AddressId,
    ) -> anyhow::Result<Vec<PrivateKey>>;
    async fn get_address_public_keys(&self, email_address: &str) -> anyhow::Result<Vec<PublicKey>>;
    async fn get_user_keys(&self) -> anyhow::Result<Vec<PrivateKey>>;
    async fn get_user_storage_info(&self) -> anyhow::Result<(i64, i64)>;
}

pub struct AccountClientAdapter {
    client: ProtonAccountClient,
}

impl AccountClientAdapter {
    pub fn new(session: &ProtonAPISession) -> Self {
        Self {
            client: ProtonAccountClient::new(session),
        }
    }
}

#[async_trait]
impl AccountClient for AccountClientAdapter {
    async fn get_address(&self, address_id: &AddressId) -> anyhow::Result<Address> {
        self.client.get_address(address_id.raw()).await
    }

    async fn get_default_address(&self) -> anyhow::Result<Address> {
        self.client.get_current_user_default_address().await
    }

    async fn get_address_primary_private_key(
        &self,
        address_id: &AddressId,
    ) -> anyhow::Result<PrivateKey> {
        self.client
            .get_address_primary_private_key(address_id.raw())
            .await
    }

    async fn get_address_private_keys(
        &self,
        address_id: &AddressId,
    ) -> anyhow::Result<Vec<PrivateKey>> {
        self.client.get_address_private_keys(address_id.raw()).await
    }

    async fn get_address_public_keys(&self, email_address: &str) -> anyhow::Result<Vec<PublicKey>> {
        self.client.get_address_public_keys(email_address).await
    }

    async fn get_user_keys(&self) -> anyhow::Result<Vec<PrivateKey>> {
        self.client.get_user_keys().await
    }

    async fn get_user_storage_info(&self) -> anyhow::Result<(i64, i64)> {
        self.client.get_user_storage_info().await
    }
}

/// The key that signs uploads, given the address's primary key and all its unlocked keys:
/// the primary, as the official SDKs sign (C# `NewFileDraftProvider`,
/// `NewRevisionDraftProvider`: `GetAddressPrimaryPrivateKeyAsync`). While the primary is a
/// v6 key, the address's first v4 key instead: Drive's commit endpoint still verifies v4
/// signatures (the upstream guard, kept until v6 primary keys are handled).
pub(crate) fn upload_signing_key(primary: PrivateKey, keys: &[PrivateKey]) -> PrivateKey {
    use proton_rpgp::AccessKeyInfo;
    if primary.version() < 6 {
        return primary;
    }
    keys.iter()
        .find(|key| key.version() < 6)
        .cloned()
        .unwrap_or(primary)
}

#[cfg(test)]
mod tests {
    use super::upload_signing_key;
    use proton_rpgp::AccessKeyInfo;

    #[test]
    fn uploads_are_signed_with_the_primary_key() {
        let key = || {
            crate::crypto::CryptoGenerator::generate_private_key()
                .unwrap()
                .0
        };
        let (older, primary) = (key(), key());
        // The address's first key is not its primary.
        let keys = vec![older, primary.clone()];
        assert_eq!(
            upload_signing_key(primary.clone(), &keys).key_id(),
            primary.key_id()
        );
    }
}

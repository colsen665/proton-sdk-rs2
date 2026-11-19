use crate::api::cache::{AccountClientCache, DefaultAccountClientCache};
use crate::api::client::{AccountApiClients, DefaultAccountApiClients};
use crate::protobuf::{Address, AddressKey};
use crate::session::ProtonAPISession;
use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, Decryptor, ExternalDetachedSignature, PrivateKey, PublicKey,
};
use std::sync::Arc;

pub struct ProtonAccountClient {
    /// API client collection providing access to addresses, keys, and users endpoints.
    pub api: Arc<dyn AccountApiClients>,
    /// Layered cache (entities + secrets + public keys) backed by the session's cache repositories.
    pub cache: Arc<dyn AccountClientCache>,
}

impl ProtonAccountClient {
    /// Constructs a `ProtonAccountClient` wired to the given authenticated session's HTTP client and caches.
    pub fn new(session: &ProtonAPISession) -> Self {
        Self {
            api: Arc::new(DefaultAccountApiClients::new_with_token_credential(
                session.http_client.clone(),
                session.token_credential.clone(),
            )),
            cache: Arc::new(DefaultAccountClientCache::new(
                session.client_config.entity_cache_repository.clone(),
                session.client_config.secret_cache_repository.clone(),
                session.session_secret_cache.clone(),
            )),
        }
    }

    /// Returns the address matching `address_id`, fetching and caching it from the API if needed.
    pub async fn get_address(&self, address_id: &str) -> anyhow::Result<Address> {
        if let Some(address) = self.cache.entities().try_get_address(address_id).await? {
            if self
                .cache
                .secrets()
                .try_get_address_keys(address_id)
                .await?
                .is_some()
            {
                return Ok(address);
            }
        }

        let response = self.api.addresses().get_address(address_id).await?;

        let user_keys = self.get_user_keys().await?;

        let address = self
            .convert_from_address_dto(response.address, &user_keys)
            .await?;
        self.cache.entities().set_address(&address).await?;
        Ok(address)
    }

    /// Returns all addresses for the current user, fetching and caching them if not yet loaded.
    pub async fn get_current_user_addresses(&self) -> anyhow::Result<Vec<Address>> {
        if let Some(addresses) = self
            .cache
            .entities()
            .try_get_current_user_addresses()
            .await?
        {
            return Ok(addresses);
        }

        let response = self.api.addresses().get_addresses().await?;

        let user_keys = self.get_user_keys().await?;

        let mut addresses = Vec::new();
        for dto in response.addresses {
            match self.convert_from_address_dto(dto, &user_keys).await {
                Ok(address) => addresses.push(address),
                Err(error) => {
                    log::warn!("Failed to load address: {error}");
                }
            }
        }

        self.cache
            .entities()
            .set_current_user_addresses(&addresses)
            .await?;

        Ok(addresses)
    }

    /// Returns the address with the lowest `order` value, which is the user's primary address.
    pub async fn get_current_user_default_address(&self) -> anyhow::Result<Address> {
        let mut addresses = self.get_current_user_addresses().await?;
        if addresses.is_empty() {
            anyhow::bail!("User has no address")
        }
        addresses.sort_by_key(|a| a.order);
        Ok(addresses.remove(0))
    }

    /// Returns all decrypted private keys for the given address, caching them after the first fetch.
    pub async fn get_address_private_keys(
        &self,
        address_id: &str,
    ) -> anyhow::Result<Vec<PrivateKey>> {
        if let Some(keys) = self
            .cache
            .secrets()
            .try_get_address_keys(address_id)
            .await?
        {
            log::debug!("Located keys");
            return Ok(keys);
        }

        log::debug!("Address id: {:?}", address_id);
        let _ = self.get_address(address_id).await?;

        if let Some(keys) = self
            .cache
            .secrets()
            .try_get_address_keys(address_id)
            .await?
        {
            return Ok(keys);
        }

        anyhow::bail!("Could not get address keys for address {address_id}")
    }

    /// Returns the address's primary key as identified by its `primary_key_index` field:
    /// its position among the address's unlocked keys. Fails when the primary key did not
    /// unlock, rather than returning another key.
    pub async fn get_address_primary_private_key(
        &self,
        address_id: &str,
    ) -> anyhow::Result<PrivateKey> {
        let address = self.get_address(address_id).await?;
        let keys = self.get_address_private_keys(address_id).await?;
        let index = usize::try_from(address.primary_key_index).map_err(|_| {
            anyhow::anyhow!("The primary key of address {address_id} could not be unlocked")
        })?;
        keys.get(index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Address primary key index out of bounds"))
    }

    /// Returns the private key at the given position within the address's key list.
    pub async fn get_address_private_key(
        &self,
        address_id: &str,
        index: usize,
    ) -> anyhow::Result<PrivateKey> {
        let keys = self.get_address_private_keys(address_id).await?;
        keys.get(index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Address key index out of bounds"))
    }

    /// Fetches and caches the active public keys for the given email address from the Keys API.
    pub async fn get_address_public_keys(
        &self,
        email_address: &str,
    ) -> anyhow::Result<Vec<PublicKey>> {
        if let Some(cached) = self.cache.public_keys().try_get_public_keys(email_address) {
            return Ok(cached);
        }

        let response = self
            .api
            .keys()
            .get_active_public_keys(email_address.to_string())
            .await?;

        let mut keys = Vec::new();
        for key in response.address_public_keys {
            if let Some(armored) = key.public_key {
                if let Ok(public_key) = PublicKey::import(armored.as_bytes(), DataEncoding::Auto) {
                    keys.push(public_key);
                }
            }
        }

        self.cache
            .public_keys()
            .set_public_keys(email_address, keys.clone());

        Ok(keys)
    }

    /// Returns all unlocked user-level private keys, fetching and caching them from the Users API if needed.
    pub async fn get_user_keys(&self) -> anyhow::Result<Vec<PrivateKey>> {
        if let Some(keys) = self.cache.secrets().try_get_user_keys().await? {
            return Ok(keys);
        }

        let response = self.api.users().get_user().await?;

        let mut unlocked = Vec::new();
        let mut active_key_found = false;

        for key in response
            .user
            .ok_or(anyhow::anyhow!("Unable to get keys from user"))?
            .keys
        {
            if !key.is_active {
                continue;
            }

            active_key_found = true;

            if let Ok(unlocked_user_key) =
                PrivateKey::import_unlocked(key.private_key.as_bytes(), DataEncoding::Auto)
            {
                unlocked.push(unlocked_user_key);
                continue;
            }

            let Some(passphrase) = self
                .cache
                .session_secrets()
                .try_get_account_key_passphrase(&key.id)
                .await?
            else {
                log::warn!("Unable to locate passphrase for user key {:?}", key.id);
                continue;
            };

            log::debug!("Passphrase: {:?}", String::from_utf8(passphrase.to_vec()));

            let unlocked_user_key =
                PrivateKey::import(key.private_key.as_bytes(), &passphrase, DataEncoding::Auto)?;
            unlocked.push(unlocked_user_key);
        }

        if unlocked.is_empty() {
            anyhow::bail!(
                "{}",
                if active_key_found {
                    format!("At least one active user key exists, but none could be unlocked")
                } else {
                    "No active user key found".to_string()
                }
            )
        }

        self.cache.secrets().set_user_keys(&unlocked).await?;

        Ok(unlocked)
    }

    async fn convert_from_address_dto(
        &self,
        dto: crate::addresses::AddressDto,
        user_keys: &[PrivateKey],
    ) -> anyhow::Result<Address> {
        let mut entries = Vec::new();
        for key_dto in dto.keys.iter().filter(|key_dto| key_dto.is_active) {
            let unlocked = self.unlock_address_key(key_dto, user_keys).await?;
            entries.push((key_dto, unlocked));
        }
        let (keys, unlocked, primary) = address_keys(&dto.id, entries);
        let primary_key_index = match primary {
            Some(index) => i32::try_from(index).unwrap_or(i32::MAX),
            None => {
                log::warn!(
                    "The primary key of address {} is not among its unlocked keys",
                    dto.id
                );
                NO_PRIMARY_KEY
            }
        };

        if !unlocked.is_empty() {
            self.cache
                .secrets()
                .set_address_keys(&dto.id, &unlocked)
                .await?;
        }

        Ok(Address {
            address_id: dto.id,
            order: dto.order,
            email_address: dto.email,
            status: dto.status,
            keys,
            primary_key_index,
        })
    }

    /// Unlocks an address key with its token (signed by a user key) or the passphrase
    /// stored for it. A key that does not unlock, a token that does not decrypt or whose
    /// signature fails included, is left out with a warning; the address's other keys
    /// stay usable, as in the official account client.
    async fn unlock_address_key(
        &self,
        key_dto: &crate::addresses::AddressKeyDto,
        user_keys: &[PrivateKey],
    ) -> anyhow::Result<Option<PrivateKey>> {
        let passphrase = if let (Some(token), Some(signature)) =
            (key_dto.token.as_ref(), key_dto.signature.as_ref())
        {
            match Self::get_address_key_token_passphrase(token, signature, user_keys) {
                Ok(passphrase) => passphrase,
                Err(error) => {
                    log::warn!("Cannot unlock address key {}: {error}", key_dto.id);
                    return Ok(None);
                }
            }
        } else {
            let passphrase = self
                .cache
                .session_secrets()
                .try_get_account_key_passphrase(&key_dto.id)
                .await?;
            let Some(passphrase) = passphrase else {
                log::warn!("No passphrase found for address key {}", key_dto.id);
                return Ok(None);
            };
            passphrase
        };

        match PrivateKey::import(
            key_dto.private_key.as_bytes(),
            passphrase.as_slice(),
            DataEncoding::Auto,
        ) {
            Ok(key) => Ok(Some(key)),
            Err(error) => {
                log::warn!("Failed to import address key {}: {error}", key_dto.id);
                Ok(None)
            }
        }
    }

    fn get_address_key_token_passphrase(
        token: &str,
        signature: &str,
        user_keys: &[PrivateKey],
    ) -> anyhow::Result<Vec<u8>> {
        if user_keys.is_empty() {
            anyhow::bail!("No user keys available for address key token decryption")
        }

        let decrypted = Decryptor::default()
            .with_decryption_keys(user_keys.iter())
            .with_verification_keys(user_keys.iter().map(|key| key.as_public_key()))
            .with_external_detached_signature(ExternalDetachedSignature::new_unencrypted(
                signature.as_bytes(),
                DataEncoding::Auto,
            ))
            .decrypt(token.as_bytes(), DataEncoding::Auto)?;

        if !decrypted.verification_succeeded() {
            anyhow::bail!("Invalid account address key passphrase signature")
        }

        Ok(decrypted.data)
    }

    pub async fn get_user_storage_info(&self) -> anyhow::Result<(i64, i64)> {
        let response = self.api.users().get_user().await?;
        let user = response
            .user
            .ok_or(anyhow::anyhow!("Unable to get user info"))?;
        Ok((user.used_space, user.max_space))
    }
}

/// `primary_key_index` of an address whose primary key did not unlock: no key is taken
/// for it, rather than another key in its place.
const NO_PRIMARY_KEY: i32 = -1;

/// Address key flag: the key is not compromised, so it may verify signatures
/// (`AddressKeyCapabilities.IsAllowedForSignatureVerification` in the official account
/// client).
const KEY_FLAG_NOT_COMPROMISED: i32 = 1;
/// Address key flag: the key is not obsolete, so it may be encrypted to
/// (`AddressKeyCapabilities.IsAllowedForEncryption`).
const KEY_FLAG_NOT_OBSOLETE: i32 = 2;

/// The address's usable keys from its active key entries and their unlocked keys (`None`
/// for one that did not unlock), as the official account client keeps them
/// (`AddressOperations.ConvertFromDtoAsync`): only the keys that unlocked, the
/// [`AddressKey`]s and private keys in the same order, and the index of the first primary
/// among them. A key that does not unlock therefore never shifts the primary, and a
/// primary that does not unlock is no primary.
fn address_keys(
    address_id: &str,
    entries: Vec<(&crate::addresses::AddressKeyDto, Option<PrivateKey>)>,
) -> (Vec<AddressKey>, Vec<PrivateKey>, Option<usize>) {
    let mut keys = Vec::new();
    let mut unlocked = Vec::new();
    let mut primary = None;
    for (key_dto, key) in entries {
        let Some(key) = key else {
            continue;
        };
        if key_dto.is_primary && primary.is_none() {
            primary = Some(unlocked.len());
        }
        keys.push(AddressKey {
            address_id: address_id.to_string(),
            address_key_id: key_dto.id.clone(),
            is_active: key_dto.is_active,
            is_allowed_for_encryption: (key_dto.flags & KEY_FLAG_NOT_OBSOLETE) != 0,
            is_allowed_for_verification: (key_dto.flags & KEY_FLAG_NOT_COMPROMISED) != 0,
        });
        unlocked.push(key);
    }
    (keys, unlocked, primary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addresses::AddressKeyDto;
    use proton_rpgp::AccessKeyInfo;

    fn key_dto(id: &str, primary: bool, flags: i32) -> AddressKeyDto {
        serde_json::from_value(serde_json::json!({
            "ID": id,
            "PrivateKey": "",
            "Primary": primary,
            "Active": true,
            "Flags": flags,
        }))
        .unwrap()
    }

    fn private_key() -> PrivateKey {
        proton_rpgp::KeyGenerator::default()
            .with_user_id("test", "test@example.test")
            .generate()
            .unwrap()
    }

    #[test]
    fn the_primary_is_found_among_the_unlocked_keys() {
        let (primary, newer) = (private_key(), private_key());
        let primary_id = primary.key_id();
        let dtos = [
            key_dto("old", false, 3),
            key_dto("primary", true, 3),
            key_dto("newer", false, 3),
        ];
        // The first key does not unlock: it must not shift the primary.
        let entries = vec![
            (&dtos[0], None),
            (&dtos[1], Some(primary)),
            (&dtos[2], Some(newer)),
        ];
        let (keys, unlocked, index) = address_keys("address", entries);
        let index = index.unwrap();
        assert_eq!(unlocked[index].key_id(), primary_id);
        assert_eq!(keys[index].address_key_id, "primary");
        assert_eq!(keys.len(), unlocked.len());
    }

    #[test]
    fn a_primary_that_does_not_unlock_is_no_primary() {
        let dtos = [key_dto("primary", true, 3), key_dto("other", false, 3)];
        let entries = vec![(&dtos[0], None), (&dtos[1], Some(private_key()))];
        let (keys, unlocked, index) = address_keys("address", entries);
        assert_eq!(index, None);
        assert_eq!(keys.len(), 1);
        assert_eq!(unlocked.len(), 1);
    }

    #[test]
    fn key_flags_tell_verification_and_encryption_apart() {
        let dtos = [
            key_dto("compromised", true, KEY_FLAG_NOT_OBSOLETE),
            key_dto("obsolete", false, KEY_FLAG_NOT_COMPROMISED),
        ];
        let entries = vec![
            (&dtos[0], Some(private_key())),
            (&dtos[1], Some(private_key())),
        ];
        let (keys, _, _) = address_keys("address", entries);
        assert!(keys[0].is_allowed_for_encryption && !keys[0].is_allowed_for_verification);
        assert!(!keys[1].is_allowed_for_encryption && keys[1].is_allowed_for_verification);
    }
}

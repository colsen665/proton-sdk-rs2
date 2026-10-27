use crate::{EventId, PasswordMode, SessionId, UserId, api::ApiResponse};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Deserializer, de::Error as _};

fn deserialize_boolish<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Bool(v) => Ok(v),
        serde_json::Value::Number(n) => Ok(n.as_i64().unwrap_or(0) != 0),
        serde_json::Value::String(s) => {
            let lower = s.to_ascii_lowercase();
            if lower == "true" || lower == "yes" {
                return Ok(true);
            }
            if lower == "false" || lower == "no" {
                return Ok(false);
            }
            if let Ok(parsed) = lower.parse::<i64>() {
                return Ok(parsed != 0);
            }
            Err(D::Error::custom("cannot parse boolean-like string"))
        }
        serde_json::Value::Null => Ok(false),
        _ => Err(D::Error::custom(
            "expected bool/int/string for boolean field",
        )),
    }
}

fn deserialize_option_boolish<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Bool(v)) => Ok(Some(v)),
        Some(serde_json::Value::Number(n)) => Ok(Some(n.as_i64().unwrap_or(0) != 0)),
        Some(serde_json::Value::String(s)) => {
            let lower = s.to_ascii_lowercase();
            if lower == "true" || lower == "yes" {
                return Ok(Some(true));
            }
            if lower == "false" || lower == "no" {
                return Ok(Some(false));
            }
            if let Ok(parsed) = lower.parse::<i64>() {
                return Ok(Some(parsed != 0));
            }
            Err(D::Error::custom(
                "cannot parse optional boolean-like string",
            ))
        }
        Some(_) => Err(D::Error::custom(
            "expected bool/int/string for optional boolean field",
        )),
    }
}

fn deserialize_binary_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(s) => general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(|_| D::Error::custom("invalid base64 in KeySalt")),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let b = item
                    .as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| {
                        D::Error::custom("KeySalt byte array must contain 0..255 integers")
                    })?;
                out.push(b);
            }
            Ok(out)
        }
        serde_json::Value::Null => Ok(vec![]),
        _ => Err(D::Error::custom(
            "KeySalt must be base64 string or byte array",
        )),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SesisonInitiationResponse {
    /// SRP protocol version negotiated with the server.
    #[serde(rename = "Version", alias = "version")]
    pub version: i32,
    /// Signed SRP modulus returned by the server.
    #[serde(rename = "Modulus", alias = "modulus")]
    pub modulus: String,
    /// Server's SRP ephemeral value (base64-encoded).
    #[serde(rename = "ServerEphemeral", alias = "server_ephemeral")]
    pub server_ephemeral: String,
    /// Per-account password salt (base64-encoded).
    #[serde(rename = "Salt", alias = "salt")]
    pub salt: String,
    /// Opaque SRP session identifier to be echoed back in the auth request.
    #[serde(rename = "SRPSession", alias = "srp_session_id")]
    pub srp_session_id: String,
    #[serde(flatten)]
    pub response: ApiResponse,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationResponse {
    /// The session UID assigned by the server (`UID` field).
    #[serde(rename = "UID", alias = "session_id")]
    pub session_id: SessionId,
    /// The authenticated user's ID.
    #[serde(rename = "UserID", alias = "user_id")]
    pub user_id: UserId,
    /// Latest core event ID at the time of login; use as the starting cursor for event polling.
    #[serde(rename = "EventID", alias = "event_id")]
    pub event_id: Option<EventId>,
    /// Short-lived access token; `None` when a second factor is still required.
    #[serde(rename = "AccessToken", alias = "access_token", default)]
    pub access_token: Option<String>,
    /// Long-lived refresh token used to obtain new access tokens.
    #[serde(rename = "RefreshToken", alias = "refresh_token", default)]
    pub refresh_token: Option<String>,
    /// List of OAuth-style scopes granted to this session.
    #[serde(rename = "Scopes", alias = "scopes", default)]
    pub scopes: Vec<String>,
    /// Indicates whether the account uses one or two passwords.
    #[serde(rename = "PasswordMode", alias = "password_mode", default)]
    pub password_mode: Option<PasswordMode>,
    /// Present when a second authentication factor must be provided before the session is fully active.
    #[serde(rename = "2FA", alias = "two_factor", default)]
    pub second_factor_parameters: Option<SecondFactorParameters>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionForkInitResponse {
    #[serde(rename = "Selector", alias = "selector")]
    pub selector: String,
    #[serde(rename = "UserCode", alias = "user_code")]
    pub user_code: String,
    #[serde(flatten)]
    pub response: ApiResponse,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionForkStatusResponse {
    #[serde(rename = "Payload", alias = "payload")]
    pub payload: String,
    #[serde(rename = "UID", alias = "session_id")]
    pub session_id: SessionId,
    #[serde(rename = "AccessToken", alias = "access_token")]
    pub access_token: String,
    #[serde(rename = "RefreshToken", alias = "refresh_token", default)]
    pub refresh_token: String,
    #[serde(rename = "UserID", alias = "user_id")]
    pub user_id: UserId,
    #[serde(rename = "Scopes", alias = "scopes", default)]
    pub scopes: Vec<String>,
    #[serde(rename = "PasswordMode", alias = "password_mode", default)]
    pub password_mode: Option<PasswordMode>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecondFactorParameters {
    #[serde(
        rename = "Enabled",
        alias = "enabled",
        default,
        deserialize_with = "deserialize_boolish"
    )]
    /// `true` when at least one second factor method (TOTP or U2F) is enabled for the account.
    pub is_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefreshSessionResponse {
    /// New short-lived access token replacing the expired one.
    #[serde(rename = "AccessToken", alias = "access_token")]
    pub access_token: String,
    /// Rotated long-lived refresh token; replace the stored value with this after each refresh.
    #[serde(rename = "RefreshToken", alias = "refresh_token")]
    pub refresh_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopesResponse {
    /// Scopes currently granted to the session.
    #[serde(rename = "Scopes", alias = "scopes", default)]
    pub scopes: Vec<String>,
    #[serde(
        rename = "TwoFactor",
        alias = "two_factor",
        default,
        deserialize_with = "deserialize_option_boolish"
    )]
    /// `Some(true)` when a second factor code is still required to fully activate the session.
    pub is_waiting_for_second_factor_code: Option<bool>,
    #[serde(flatten)]
    pub response: ApiResponse,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModulusResponse {
    #[serde(rename = "Modulus", alias = "modulus")]
    pub modulus: String,
    #[serde(flatten)]
    pub response: ApiResponse,
}

/// Answer of `GET core/v4/keys/all` (`get_core-{_version}-keys-all` in the
/// API schema of the official JS SDK, `coreTypes.ts`).
#[derive(Debug, Clone, Deserialize)]
pub struct AddressPublicKeyListResponse {
    /// The internal address's keys, backed by its signed key list.
    #[serde(rename = "Address", alias = "address", default)]
    pub address: Option<AddressPublicKeys>,
    /// The catch-all address's keys, if the address is caught by one.
    #[serde(rename = "CatchAll", alias = "catch_all", default)]
    pub catch_all: Option<AddressPublicKeys>,
    /// Keys without trusted metadata (legacy, WKD): not for signature verification.
    #[serde(rename = "Unverified", alias = "unverified", default)]
    pub unverified: Option<AddressPublicKeys>,
    #[serde(flatten)]
    pub response: ApiResponse,
}

/// One address's key list in [`AddressPublicKeyListResponse`].
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AddressPublicKeys {
    #[serde(rename = "Keys", alias = "keys", default)]
    pub keys: Vec<AddressPublicKey>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddressPublicKey {
    /// Email address associated with this key.
    #[serde(rename = "Email", alias = "email", default)]
    pub email: Option<String>,
    /// Bitfield of key usage: 1 = not compromised (may verify), 2 = not
    /// obsolete (may encrypt).
    #[serde(rename = "Flags", alias = "flags", default)]
    pub flags: Option<i32>,
    /// Armored PGP public key.
    #[serde(rename = "PublicKey", alias = "public_key", default)]
    pub public_key: Option<String>,
    /// Origin of the key: `0` = ProtonMail, `3` = external/WKD.
    #[serde(rename = "Source", alias = "source", default)]
    pub source: Option<i32>,
}

impl AddressPublicKey {
    /// Key flag: the key is not compromised, so its signatures count.
    pub const FLAG_NOT_COMPROMISED: i32 = 1;

    /// Whether signatures by this key may be trusted.
    pub fn may_verify(&self) -> bool {
        self.flags
            .is_none_or(|flags| flags & Self::FLAG_NOT_COMPROMISED != 0)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeySaltListResponse {
    #[serde(rename = "KeySalts", alias = "key_salts", default)]
    pub key_salts: Vec<KeySalt>,
    #[serde(flatten)]
    pub response: ApiResponse,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeySalt {
    #[serde(rename = "ID", alias = "key_id")]
    pub key_id: String,
    #[serde(
        rename = "KeySalt",
        alias = "key_salt",
        deserialize_with = "deserialize_binary_bytes"
    )]
    pub value: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of `GET core/v4/keys/all` in the official API schema.
    #[test]
    fn all_keys_answer_decodes_the_address_keys() {
        let json = r#"{
            "Code": 1000,
            "Address": {
                "Keys": [
                    {"PublicKey": "key-1", "Primary": 1, "Flags": 3, "Source": 0},
                    {"PublicKey": "key-2", "Primary": 0, "Flags": 2, "Source": 0}
                ],
                "SignedKeyList": {"Data": "[]", "Signature": "sig"}
            },
            "CatchAll": null,
            "Unverified": {"Keys": [{"PublicKey": "legacy", "Flags": 3, "Source": 1}]},
            "Warnings": [],
            "ProtonMX": true,
            "IsProton": 0
        }"#;

        let response: AddressPublicKeyListResponse = serde_json::from_str(json).unwrap();

        let keys = response.address.unwrap().keys;
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].public_key.as_deref(), Some("key-1"));
        assert!(keys[0].may_verify());
        assert!(!keys[1].may_verify(), "compromised");
        assert!(response.catch_all.is_none());
        assert_eq!(response.unverified.unwrap().keys.len(), 1);
    }
}

pub mod attr;
pub mod block;
pub mod devices;
pub mod events;
pub mod file;
pub mod folder;
pub mod links;
pub mod node;
pub mod revision;
pub mod share;
pub mod storage;
pub mod trash;
pub mod volumes;

use crate::error::ApiError;
use proton_sdk_rs2::auth::TokenCredential;
use reqwest_middleware::ClientWithMiddleware;
use serde::Deserialize;
use std::sync::Arc;

pub trait DriveApiClientsFactory: Send + Sync {
    fn create(
        &self,
        default_api_http_client: ClientWithMiddleware,
        storage_api_http_client: ClientWithMiddleware,
        default_api_base_url: Url,
        storage_api_base_url: Url,
        token_credential: Option<TokenCredential>,
    ) -> Arc<dyn DriveApiClients>;
}

pub struct DefaultDriveApiClientsFactory;

impl DriveApiClientsFactory for DefaultDriveApiClientsFactory {
    fn create(
        &self,
        default_api_http_client: ClientWithMiddleware,
        storage_api_http_client: ClientWithMiddleware,
        default_api_base_url: Url,
        storage_api_base_url: Url,
        token_credential: Option<TokenCredential>,
    ) -> Arc<dyn DriveApiClients> {
        if let Some(token_credential) = token_credential {
            Arc::new(DefaultDriveApiClients::new_with_token_credential(
                default_api_http_client,
                storage_api_http_client,
                default_api_base_url,
                storage_api_base_url,
                token_credential,
            ))
        } else {
            Arc::new(DefaultDriveApiClients::new(
                default_api_http_client,
                storage_api_http_client,
                default_api_base_url,
                storage_api_base_url,
            ))
        }
    }
}
use crate::api::devices::{DefaultDevicesApiClient, DevicesApiClient};
use crate::api::events::{DefaultEventsApiClient, EventsApiClient};
use crate::api::file::{DefaultFilesApiClient, FilesApiClient};
use crate::api::folder::{DefaultFoldersApiClient, FoldersApiClient};
use crate::api::links::{DefaultLinksApiClient, LinksApiClient};
use crate::api::share::{DefaultSharesApiClient, SharesApiClient};
use crate::api::storage::{DefaultStorageApiClient, StorageApiClient};
use crate::api::trash::{DefaultTrashApiClient, TrashApiClient};
use crate::api::volumes::{DefaultVolumesApiClient, VolumesApiClient};

use reqwest::Url;

pub trait DriveApiClients: Send + Sync {
    fn volumes(&self) -> Arc<dyn VolumesApiClient>;
    fn shares(&self) -> Arc<dyn SharesApiClient>;
    fn links(&self) -> Arc<dyn LinksApiClient>;
    fn folders(&self) -> Arc<dyn FoldersApiClient>;
    fn files(&self) -> Arc<dyn FilesApiClient>;
    fn storage(&self) -> Arc<dyn StorageApiClient>;
    fn trash(&self) -> Arc<dyn TrashApiClient>;
    fn events(&self) -> Arc<dyn EventsApiClient>;
    fn devices(&self) -> Arc<dyn DevicesApiClient>;
}

pub struct DefaultDriveApiClients {
    default_api_http_client: ClientWithMiddleware,
    storage_api_http_client: ClientWithMiddleware,
    default_api_base_url: Url,
    storage_api_base_url: Url,
    token_credential: Option<TokenCredential>,
}
impl DefaultDriveApiClients {
    pub fn new(
        default_api_http_client: ClientWithMiddleware,
        storage_api_http_client: ClientWithMiddleware,
        default_api_base_url: Url,
        storage_api_base_url: Url,
    ) -> Self {
        Self {
            default_api_http_client,
            storage_api_http_client,
            default_api_base_url,
            storage_api_base_url,
            token_credential: None,
        }
    }

    pub fn new_with_token_credential(
        default_api_http_client: ClientWithMiddleware,
        storage_api_http_client: ClientWithMiddleware,
        default_api_base_url: Url,
        storage_api_base_url: Url,
        token_credential: TokenCredential,
    ) -> Self {
        Self {
            default_api_http_client,
            storage_api_http_client,
            default_api_base_url,
            storage_api_base_url,
            token_credential: Some(token_credential),
        }
    }
}

impl DriveApiClients for DefaultDriveApiClients {
    fn volumes(&self) -> Arc<dyn VolumesApiClient> {
        Arc::new(DefaultVolumesApiClient::new(
            self.default_api_http_client.clone(),
            self.default_api_base_url.clone(),
            self.token_credential.clone(),
        ))
    }

    fn shares(&self) -> Arc<dyn SharesApiClient> {
        Arc::new(DefaultSharesApiClient::new(
            self.default_api_http_client.clone(),
            self.default_api_base_url.clone(),
            self.token_credential.clone(),
        ))
    }

    fn links(&self) -> Arc<dyn LinksApiClient> {
        Arc::new(DefaultLinksApiClient::new(
            self.default_api_http_client.clone(),
            self.default_api_base_url.clone(),
            self.token_credential.clone(),
        ))
    }

    fn folders(&self) -> Arc<dyn FoldersApiClient> {
        Arc::new(DefaultFoldersApiClient::new(
            self.default_api_http_client.clone(),
            self.default_api_base_url.clone(),
            self.token_credential.clone(),
        ))
    }

    fn files(&self) -> Arc<dyn FilesApiClient> {
        Arc::new(DefaultFilesApiClient::new(
            self.default_api_http_client.clone(),
            self.default_api_base_url.clone(),
            self.token_credential.clone(),
        ))
    }

    fn storage(&self) -> Arc<dyn StorageApiClient> {
        Arc::new(DefaultStorageApiClient::new(
            self.default_api_http_client.clone(),
            self.storage_api_http_client.clone(),
            self.default_api_base_url.clone(),
            self.storage_api_base_url.clone(),
            self.token_credential.clone(),
        ))
    }

    fn trash(&self) -> Arc<dyn TrashApiClient> {
        Arc::new(DefaultTrashApiClient::new(
            self.default_api_http_client.clone(),
            self.default_api_base_url.clone(),
            self.token_credential.clone(),
        ))
    }

    fn events(&self) -> Arc<dyn EventsApiClient> {
        Arc::new(DefaultEventsApiClient::new(
            self.default_api_http_client.clone(),
            self.default_api_base_url.clone(),
            self.token_credential.clone(),
        ))
    }

    fn devices(&self) -> Arc<dyn DevicesApiClient> {
        Arc::new(DefaultDevicesApiClient::new(
            self.default_api_http_client.clone(),
            self.default_api_base_url.clone(),
            self.token_credential.clone(),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct ResponseCode(pub u32);

impl ResponseCode {
    pub const SUCCESS: ResponseCode = ResponseCode(1000);

    pub fn is_success(self) -> bool {
        self == Self::SUCCESS
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiResponse {
    #[serde(rename = "Code")]
    pub code: ResponseCode,

    #[serde(rename = "Error")]
    pub error_message: Option<String>,
}

impl ApiResponse {
    pub fn is_success(&self) -> bool {
        self.code.is_success()
    }

    /// Converts a non-success response into a typed [`ApiError`].
    pub fn to_result(&self) -> anyhow::Result<()> {
        if self.is_success() {
            Ok(())
        } else {
            Err(
                ApiError::from_code(self.code.0, self.error_message.clone().unwrap_or_default())
                    .into(),
            )
        }
    }

    pub async fn from_response(response: reqwest::Response) -> anyhow::Result<Self> {
        let status = response.status();
        let headers = response.headers().clone();
        let text = response.text().await?;
        match serde_json::from_str::<Self>(&text) {
            Ok(res) => Ok(res),
            Err(_) if !status.is_success() => {
                Err(ApiError::from_http(status, &headers, &text).into())
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to decode response body: {}. Body: {}",
                e,
                text
            )),
        }
    }
}

/// Parses a Drive API response body as `T`.
///
/// A non-2xx status becomes an [`ApiError`] carrying the HTTP status, the
/// Proton `Code`/`Error` from the body (when present) and `Retry-After`.
pub(crate) async fn parse_json_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> anyhow::Result<T> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();
    parse_json_body(status, &headers, &body)
}

fn parse_json_body<T: serde::de::DeserializeOwned>(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    body: &str,
) -> anyhow::Result<T> {
    if !status.is_success() {
        return Err(ApiError::from_http(status, headers, body).into());
    }
    serde_json::from_str::<T>(body).map_err(|e| {
        // A 2xx body that does not match `T` is usually a Proton error
        // object; report it as such rather than as a parse failure.
        match ApiError::from_body(body) {
            Some(api) if api.code != Some(ResponseCode::SUCCESS.0) => api.into(),
            _ => anyhow::anyhow!(
                "JSON parse error: {}. Body: {}",
                e,
                &body[..floor_char_boundary(body, 512)]
            ),
        }
    })
}

/// Parses a body that may carry a Proton `Code`, failing with [`ApiError`]
/// when `Code` is present and not 1000.
pub(crate) fn parse_coded_json_body<T: serde::de::DeserializeOwned>(
    body: &str,
) -> anyhow::Result<T> {
    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| anyhow::anyhow!("Failed to decode response body: {}. Body: {}", e, body))?;
    if let Some(code) = value.get("Code").and_then(|c| c.as_u64()) {
        if code != u64::from(ResponseCode::SUCCESS.0) {
            let error = ApiError::from_body(body)
                .unwrap_or_else(|| ApiError::from_code(code as u32, "Unknown error"));
            return Err(error.into());
        }
    }
    serde_json::from_value(value)
        .map_err(|e| anyhow::anyhow!("Failed to parse JSON: {}. Body: {}", e, body))
}

fn floor_char_boundary(text: &str, max: usize) -> usize {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

#[derive(Debug, Clone, Deserialize)]
pub struct AggregateApiResponse<T> {
    #[serde(flatten)]
    pub base: ApiResponse,

    #[serde(rename = "Responses")]
    pub responses: Vec<T>,
}

impl<T> AggregateApiResponse<T> {
    pub fn is_success(&self) -> bool {
        self.base.is_success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_code_1000_is_success() {
        assert!(ResponseCode::SUCCESS.is_success());
        assert!(!ResponseCode(0).is_success());
        assert!(!ResponseCode(1001).is_success());
    }

    #[test]
    fn successful_api_response_converts_to_ok() {
        let response = ApiResponse {
            code: ResponseCode::SUCCESS,
            error_message: None,
        };
        assert!(response.is_success());
        assert!(response.to_result().is_ok());
    }

    #[test]
    fn failed_api_response_preserves_code_and_message() {
        let response = ApiResponse {
            code: ResponseCode(2500),
            error_message: Some("Not found".into()),
        };
        let error = response.to_result().unwrap_err().to_string();
        assert!(error.contains("2500"));
        assert!(error.contains("Not found"));
    }

    #[test]
    fn failed_api_response_is_a_typed_api_error() {
        let response = ApiResponse {
            code: ResponseCode(2501),
            error_message: Some("Link does not exist".into()),
        };
        let error = response.to_result().unwrap_err();
        let api = ApiError::find(&error).expect("typed error");
        assert!(api.is_not_found());
        assert_eq!(api.http_status, None);
    }

    #[derive(Debug, Deserialize)]
    struct Payload {
        #[serde(rename = "Value")]
        value: u32,
    }

    #[test]
    fn json_body_with_error_status_becomes_api_error() {
        let error = parse_json_body::<Payload>(
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            &reqwest::header::HeaderMap::new(),
            r#"{"Code":200002,"Error":"Storage quota exceeded"}"#,
        )
        .unwrap_err();
        let api = ApiError::find(&error).expect("typed error");
        assert_eq!(api.http_status, Some(422));
        assert!(api.is_quota_exceeded());
        assert_eq!(
            error.to_string(),
            "API error 200002: Storage quota exceeded"
        );
    }

    #[test]
    fn json_body_with_success_status_but_error_code_becomes_api_error() {
        let error = parse_json_body::<Payload>(
            reqwest::StatusCode::OK,
            &reqwest::header::HeaderMap::new(),
            r#"{"Code":2500,"Error":"Already exists"}"#,
        )
        .unwrap_err();
        assert!(ApiError::find(&error).unwrap().is_already_exists());
    }

    #[test]
    fn json_body_with_success_status_parses_payload() {
        let payload = parse_json_body::<Payload>(
            reqwest::StatusCode::OK,
            &reqwest::header::HeaderMap::new(),
            r#"{"Code":1000,"Value":7}"#,
        )
        .unwrap();
        assert_eq!(payload.value, 7);
    }

    #[test]
    fn malformed_success_body_stays_a_parse_error() {
        let error = parse_json_body::<Payload>(
            reqwest::StatusCode::OK,
            &reqwest::header::HeaderMap::new(),
            "not json",
        )
        .unwrap_err();
        assert!(ApiError::find(&error).is_none());
        assert!(error.to_string().starts_with("JSON parse error"));
    }

    #[test]
    fn coded_body_rejects_non_success_codes() {
        let error =
            parse_coded_json_body::<serde_json::Value>(r#"{"Code":2011,"Error":"No access"}"#)
                .unwrap_err();
        assert!(ApiError::find(&error).unwrap().is_permission_denied());
        let ok: serde_json::Value = parse_coded_json_body(r#"{"Code":1000,"X":1}"#).unwrap();
        assert_eq!(ok["X"], 1);
    }

    #[test]
    fn deserializes_typescript_api_error_shape() {
        let response: ApiResponse =
            serde_json::from_str(r#"{"Code":2500,"Error":"Not found"}"#).unwrap();
        assert_eq!(response.code, ResponseCode(2500));
        assert_eq!(response.error_message.as_deref(), Some("Not found"));
    }
}

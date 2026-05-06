//! Compatibility DTOs for Bitwarden Web Vault / Connector WebAuthn payloads.
//!
//! The bundled web-vault and its connectors send field names that differ from
//! the standard WebAuthn / `passkey-server` naming:
//!
//! | Web Vault sends          | passkey-server expects   |
//! |--------------------------|--------------------------|
//! | `clientDataJson`         | `clientDataJSON`         |
//! | `AttestationObject`      | `attestationObject`      |
//!
//! These wrapper types accept both variants via `#[serde(alias)]`, normalize
//! WebAuthn binary fields to unpadded base64url, then convert into the
//! standard `passkey_server::types` structs.

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::Deserialize;

use crate::error::AppError;

fn normalize_base64url(value: &str) -> Option<String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| STANDARD.decode(value))
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .ok()
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
}

fn deserialize_base64url_compat<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    normalize_base64url(&value).ok_or_else(|| serde::de::Error::custom("invalid base64url data"))
}

fn deserialize_optional_base64url_compat<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| {
            normalize_base64url(&value)
                .ok_or_else(|| serde::de::Error::custom("invalid base64url data"))
        })
        .transpose()
}

/// Compatibility wrapper for `RegistrationResponse` (registration completion).
///
/// Mirrors `passkey_server::types::RegistrationResponse` but accepts the
/// field-name variants emitted by the Bitwarden web-vault.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationResponseCompat {
    #[serde(deserialize_with = "deserialize_base64url_compat")]
    pub id: String,
    #[serde(deserialize_with = "deserialize_base64url_compat")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AttestationResponseCompat,
    pub client_extension_results: Option<serde_json::Value>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponseCompat {
    #[serde(
        rename = "clientDataJSON",
        alias = "clientDataJson",
        alias = "ClientDataJSON",
        deserialize_with = "deserialize_base64url_compat"
    )]
    pub client_data_json: String,
    #[serde(
        rename = "attestationObject",
        alias = "AttestationObject",
        alias = "attestation_object",
        deserialize_with = "deserialize_base64url_compat"
    )]
    pub attestation_object: String,
}

impl RegistrationResponseCompat {
    /// Parse a `deviceResponse` JSON value into a `RegistrationResponse`,
    /// optionally overriding the name (for display-name / AAGUID extraction).
    pub fn parse(
        value: serde_json::Value,
        name: Option<String>,
    ) -> Result<passkey_server::types::RegistrationResponse, AppError> {
        let mut compat: Self = serde_json::from_value(value).map_err(|e| {
            log::error!("Failed to parse WebAuthn registration response: {e}");
            AppError::BadRequest("Invalid deviceResponse".into())
        })?;
        if name.is_some() {
            compat.name = name;
        }
        Ok(compat.into())
    }
}

impl From<RegistrationResponseCompat> for passkey_server::types::RegistrationResponse {
    fn from(c: RegistrationResponseCompat) -> Self {
        Self {
            id: c.id,
            raw_id: c.raw_id,
            type_: c.type_,
            response: passkey_server::types::AttestationResponse {
                client_data_json: c.response.client_data_json,
                attestation_object: c.response.attestation_object,
            },
            client_extension_results: c.client_extension_results,
            name: c.name,
        }
    }
}

/// Compatibility wrapper for `LoginResponse` (assertion / 2FA login).
///
/// Mirrors `passkey_server::types::LoginResponse` but accepts `clientDataJson`
/// in addition to the canonical `clientDataJSON`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponseCompat {
    #[serde(deserialize_with = "deserialize_base64url_compat")]
    pub id: String,
    #[serde(deserialize_with = "deserialize_base64url_compat")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AssertionResponseCompat,
    pub client_extension_results: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionResponseCompat {
    #[serde(
        rename = "clientDataJSON",
        alias = "clientDataJson",
        alias = "ClientDataJSON",
        deserialize_with = "deserialize_base64url_compat"
    )]
    pub client_data_json: String,
    #[serde(deserialize_with = "deserialize_base64url_compat")]
    pub authenticator_data: String,
    #[serde(deserialize_with = "deserialize_base64url_compat")]
    pub signature: String,
    #[serde(default, deserialize_with = "deserialize_optional_base64url_compat")]
    pub user_handle: Option<String>,
}

impl LoginResponseCompat {
    /// Parse a `deviceResponse` JSON value, returning `(credential_id, LoginResponse)`.
    pub fn parse(
        value: serde_json::Value,
    ) -> Result<(String, passkey_server::types::LoginResponse), AppError> {
        let compat: Self = serde_json::from_value(value).map_err(|e| {
            log::error!("Failed to parse WebAuthn assertion response: {e}");
            AppError::BadRequest("Invalid deviceResponse".into())
        })?;
        let credential_id = compat.id.clone();
        Ok((credential_id, compat.into()))
    }

    /// Parse a `deviceResponse` JSON string, returning `(credential_id, LoginResponse)`.
    pub fn parse_str(s: &str) -> Result<(String, passkey_server::types::LoginResponse), AppError> {
        let compat: Self = serde_json::from_str(s).map_err(|e| {
            log::error!("Failed to parse WebAuthn assertion response: {e}");
            AppError::BadRequest("Invalid WebAuthn response".into())
        })?;
        let credential_id = compat.id.clone();
        Ok((credential_id, compat.into()))
    }
}

impl From<LoginResponseCompat> for passkey_server::types::LoginResponse {
    fn from(c: LoginResponseCompat) -> Self {
        Self {
            id: c.id,
            raw_id: c.raw_id,
            type_: c.type_,
            response: passkey_server::types::AssertionResponse {
                client_data_json: c.response.client_data_json,
                authenticator_data: c.response.authenticator_data,
                signature: c.response.signature,
                user_handle: c.response.user_handle,
            },
            client_extension_results: c.client_extension_results,
        }
    }
}

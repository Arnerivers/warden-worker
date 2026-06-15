use passkey_server::types::{
    CredentialDescriptor, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
};
use passkey_server::{
    finish_login, finish_registration, start_login, start_registration, PasskeyConfig,
};
use serde_json::{json, Value};

use super::store::{D1PasskeyStore, WebauthnCredentialRow};
use crate::error::AppError;

// ── Registration ─────────────────────────────────────────────────────────────

/// Generate registration options with usage-appropriate authenticator selection.
pub async fn start_ceremony_registration(
    store: &D1PasskeyStore<'_>,
    user_id: &str,
    username: &str,
    display_name: &str,
    config: &PasskeyConfig,
    now_ms: i64,
) -> Result<PublicKeyCredentialCreationOptions, AppError> {
    let mut opts = start_registration(store, user_id, username, display_name, config, now_ms)
        .await
        .map_err(|e| {
            log::error!(
                "WebAuthn registration start failed ({:?}): {e}",
                store.usage(),
            );
            AppError::BadRequest("WebAuthn registration start failed".into())
        })?;

    opts.authenticator_selection = Some(store.usage().authenticator_selection());
    Ok(opts)
}

/// Complete a WebAuthn credential registration (shared for both modes).
pub async fn finish_ceremony_registration(
    store: &D1PasskeyStore<'_>,
    user_id: &str,
    config: &PasskeyConfig,
    response: passkey_server::types::RegistrationResponse,
    now_ms: i64,
) -> Result<(), AppError> {
    let aligned_config =
        super::verify_origin_and_align_config(config, &response.response.client_data_json);
    finish_registration(store, user_id, &aligned_config, response, now_ms)
        .await
        .map_err(|e| {
            log::error!("WebAuthn registration verification failed: {e}");
            AppError::BadRequest("WebAuthn registration failed".into())
        })
}

// ── Assertion (Login — discoverable) ─────────────────────────────────────────

/// Generate discoverable-credential assertion options for passkey login.
/// Produces empty `allowCredentials` so the browser selects a resident key.
pub async fn start_login_assertion(
    store: &D1PasskeyStore<'_>,
    config: &PasskeyConfig,
    now_ms: i64,
) -> Result<PublicKeyCredentialRequestOptions, AppError> {
    let mut opts = start_login(store, config, now_ms).await.map_err(|e| {
        log::error!("Login passkey assertion start failed: {e}");
        AppError::BadRequest("WebAuthn assertion start failed".into())
    })?;

    opts.user_verification = Some("required".into());
    Ok(opts)
}

// ── Assertion (2FA — credential-list based) ──────────────────────────────────

/// Generate 2FA assertion options with explicit `allowCredentials` list.
pub async fn start_2fa_assertion(
    store: &D1PasskeyStore<'_>,
    config: &PasskeyConfig,
    user_creds: &[WebauthnCredentialRow],
    now_ms: i64,
) -> Result<PublicKeyCredentialRequestOptions, AppError> {
    let mut opts = start_login(store, config, now_ms).await.map_err(|e| {
        log::error!("WebAuthn 2FA assertion start failed: {e}");
        AppError::BadRequest("WebAuthn assertion start failed".into())
    })?;

    opts.allow_credentials = Some(
        user_creds
            .iter()
            .map(|c| {
                let transports: Option<Vec<String>> = serde_json::from_str(&c.transports)
                    .ok()
                    .filter(|v: &Vec<String>| !v.is_empty());
                CredentialDescriptor {
                    type_: "public-key".into(),
                    id: c.credential_id.clone(),
                    transports,
                }
            })
            .collect(),
    );
    opts.user_verification = Some("discouraged".into());

    Ok(opts)
}

// ── Shared assertion verification ────────────────────────────────────────────

/// Verify a WebAuthn assertion and return the authenticated user_id.
///
/// When `expected_user_id` is `Some`, the returned user must match;
/// pass `None` for discoverable-credential login where the user is unknown.
pub async fn finish_assertion(
    store: &D1PasskeyStore<'_>,
    config: &PasskeyConfig,
    response: passkey_server::types::LoginResponse,
    expected_user_id: Option<&str>,
    now_ms: i64,
) -> Result<String, AppError> {
    let aligned_config =
        super::verify_origin_and_align_config(config, &response.response.client_data_json);
    let returned_user_id = finish_login(store, &aligned_config, response, now_ms)
        .await
        .map_err(|e| {
            log::error!("WebAuthn assertion verification failed: {e}");
            AppError::BadRequest("WebAuthn verification failed".into())
        })?;

    if let Some(expected) = expected_user_id {
        if returned_user_id != expected {
            log::warn!(
                "WebAuthn credential user mismatch: expected {expected}, got {returned_user_id}"
            );
            return Err(AppError::BadRequest("WebAuthn verification failed".into()));
        }
    }
    Ok(returned_user_id)
}

// ── JSON helpers (camelCase for Bitwarden clients) ──────────────────────────

pub trait ToBitwardenJson {
    fn to_bitwarden_json(&self) -> Value;
}

impl ToBitwardenJson for PublicKeyCredentialCreationOptions {
    fn to_bitwarden_json(&self) -> Value {
        let mut obj = json!({
            "challenge": self.challenge,
            "excludeCredentials": Value::Array(
                self.exclude_credentials
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(ToBitwardenJson::to_bitwarden_json)
                    .collect(),
            ),
            "rp": {
                "id": self.rp.id,
                "name": self.rp.name,
            },
            "user": {
                "id": self.user.id,
                "name": self.user.name,
                "displayName": self.user.display_name,
            },
            "pubKeyCredParams": self.pub_key_cred_params.iter().map(|p| json!({
                "type": p.type_,
                "alg": p.alg,
            })).collect::<Vec<_>>(),
        });
        if let Some(timeout) = self.timeout {
            obj["timeout"] = json!(timeout);
        }
        if let Some(ref sel) = self.authenticator_selection {
            let mut s = json!({});
            if let Some(ref aa) = sel.authenticator_attachment {
                s["authenticatorAttachment"] = json!(aa);
            }
            if let Some(rrk) = sel.require_resident_key {
                s["requireResidentKey"] = json!(rrk);
            }
            if let Some(ref rk) = sel.resident_key {
                s["residentKey"] = json!(rk);
            }
            if let Some(ref uv) = sel.user_verification {
                s["userVerification"] = json!(uv);
            }
            obj["authenticatorSelection"] = s;
        }
        if let Some(ref att) = self.attestation {
            obj["attestation"] = json!(att);
        }
        obj
    }
}

impl ToBitwardenJson for PublicKeyCredentialRequestOptions {
    fn to_bitwarden_json(&self) -> Value {
        let mut obj = json!({
            "challenge": self.challenge,
            "rpId": self.rp_id,
        });
        if let Some(timeout) = self.timeout {
            obj["timeout"] = json!(timeout);
        }
        if let Some(ref creds) = self.allow_credentials {
            obj["allowCredentials"] = Value::Array(
                creds
                    .iter()
                    .map(ToBitwardenJson::to_bitwarden_json)
                    .collect(),
            );
        }
        if let Some(ref uv) = self.user_verification {
            obj["userVerification"] = json!(uv);
        }
        obj
    }
}

impl ToBitwardenJson for CredentialDescriptor {
    fn to_bitwarden_json(&self) -> Value {
        let mut obj = json!({
            "type": self.type_,
            "id": self.id,
        });
        if let Some(ref transports) = self.transports {
            obj["transports"] = json!(transports);
        }
        obj
    }
}

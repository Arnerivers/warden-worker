use passkey_server::types::{
    AuthenticatorSelection, CredentialDescriptor, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
};
use passkey_server::{
    finish_login, finish_registration, start_login, start_registration, PasskeyConfig,
};
use serde_json::{json, Value};

use super::store::{D1PasskeyStore, WebauthnCredentialRow};
use crate::error::AppError;

// ── 2FA Registration ────────────────────────────────────────────────────────

/// Generate registration options for a 2FA WebAuthn credential.
///
/// Calls `start_registration` then overrides `authenticator_selection` to
/// discourage user verification (security-key behaviour).
pub async fn start_2fa_registration(
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
            log::error!("WebAuthn registration start failed: {e}");
            AppError::BadRequest("WebAuthn registration start failed".into())
        })?;

    opts.authenticator_selection = Some(AuthenticatorSelection {
        authenticator_attachment: None,
        require_resident_key: Some(false),
        resident_key: None,
        user_verification: Some("discouraged".into()),
    });

    Ok(opts)
}

/// Complete a 2FA WebAuthn credential registration.
pub async fn finish_2fa_registration(
    store: &D1PasskeyStore<'_>,
    user_id: &str,
    config: &PasskeyConfig,
    response: passkey_server::types::RegistrationResponse,
    now_ms: i64,
) -> Result<(), AppError> {
    finish_registration(store, user_id, config, response, now_ms)
        .await
        .map_err(|e| {
            log::error!("WebAuthn registration verification failed: {e}");
            AppError::BadRequest("WebAuthn registration failed".into())
        })
}

// ── 2FA Assertion ───────────────────────────────────────────────────────────

/// Generate assertion options for 2FA WebAuthn challenge.
///
/// Uses `start_login` (which saves state as `login:{challenge}`), then
/// overrides `allow_credentials` with the user's 2FA credential list and
/// sets `user_verification` to `"discouraged"`.
pub async fn start_2fa_assertion(
    store: &D1PasskeyStore<'_>,
    config: &PasskeyConfig,
    user_creds: &[WebauthnCredentialRow],
    now_ms: i64,
) -> Result<PublicKeyCredentialRequestOptions, AppError> {
    let mut opts = start_login(store, config, now_ms).await.map_err(|e| {
        log::error!("WebAuthn assertion start failed: {e}");
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

/// Verify a 2FA WebAuthn assertion and return the authenticated user_id.
///
/// The server-side state (`LoginState`) only stores the challenge, not the
/// allowed credential set.  Currently, we allow all the credentials
/// that belong to the user.
pub async fn finish_2fa_assertion(
    store: &D1PasskeyStore<'_>,
    config: &PasskeyConfig,
    response: passkey_server::types::LoginResponse,
    expected_user_id: &str,
    now_ms: i64,
) -> Result<(), AppError> {
    let returned_user_id = finish_login(store, config, response, now_ms)
        .await
        .map_err(|e| {
            log::error!("WebAuthn assertion verification failed: {e}");
            AppError::BadRequest("WebAuthn verification failed".into())
        })?;

    if returned_user_id != expected_user_id {
        log::warn!("WebAuthn credential user mismatch: expected {expected_user_id}, got {returned_user_id}");
        return Err(AppError::BadRequest("WebAuthn verification failed".into()));
    }
    Ok(())
}

// ── JSON helpers (camelCase for Bitwarden clients) ──────────────────────────

pub trait ToBitwardenJson {
    fn to_bitwarden_json(&self) -> Value;
}

/// Serialize `PublicKeyCredentialCreationOptions` as camelCase JSON
/// for the Bitwarden client.
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

/// Serialize `PublicKeyCredentialRequestOptions` as camelCase JSON
/// for the Bitwarden client's `TwoFactorProviders2["7"]`.
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

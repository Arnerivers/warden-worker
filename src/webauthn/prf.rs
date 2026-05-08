use serde::{Deserialize, Serialize};
use worker::wasm_bindgen::JsValue;

use super::store::d1_i64;
use crate::db::Db;
use crate::error::AppError;
use crate::models::user::WebAuthnRotateKeyData;

/// PRF status mirroring upstream `WebAuthnPrfStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfStatus {
    Enabled = 0,
    Supported = 1,
    Unsupported = 2,
}

/// Joined credential + PRF for a user's login credentials with PRF enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCredentialWithPrf {
    pub id: String,
    pub credential_id: String,
    pub name: String,
    pub transports: String,
    pub supports_prf: bool,
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

impl LoginCredentialWithPrf {
    pub fn prf_status(&self) -> PrfStatus {
        if !self.supports_prf {
            return PrfStatus::Unsupported;
        }
        if self.encrypted_user_key.is_some()
            && self.encrypted_public_key.is_some()
            && self.encrypted_private_key.is_some()
        {
            PrfStatus::Enabled
        } else {
            PrfStatus::Supported
        }
    }

    /// Build a `WebAuthnPrfDecryptionOption` JSON object.
    ///
    /// Returns `Some` only when PRF is `Enabled`.
    pub fn to_prf_option(&self) -> Option<serde_json::Value> {
        if self.prf_status() != PrfStatus::Enabled {
            return None;
        }
        let transports: Vec<String> = serde_json::from_str(&self.transports).unwrap_or_default();
        Some(serde_json::json!({
            "encryptedPrivateKey": self.encrypted_private_key,
            "encryptedUserKey": self.encrypted_user_key,
            "credentialId": self.credential_id,
            "transports": transports
        }))
    }

    /// Serialize to the `GET /api/webauthn` response format
    /// (upstream `WebAuthnCredentialResponseModel`).
    pub fn to_response_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "prfStatus": self.prf_status() as i32,
            "encryptedUserKey": self.encrypted_user_key,
            "encryptedPublicKey": self.encrypted_public_key,
            "object": "webAuthnCredential"
        })
    }
}

// ── PRF credential operations ───────────────────────────────────────────────

/// Create a PRF record when registering a login credential.
pub async fn create_prf_credential(
    db: &Db,
    credential_row_id: &str,
    supports_prf: bool,
    encrypted_user_key: Option<&str>,
    encrypted_public_key: Option<&str>,
    encrypted_private_key: Option<&str>,
    now_ms: i64,
) -> Result<(), AppError> {
    db.prepare(
        "INSERT INTO webauthn_prf_credentials \
         (credential_row_id, supports_prf, encrypted_user_key, encrypted_public_key, encrypted_private_key, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&[
        credential_row_id.into(),
        supports_prf.into(),
        encrypted_user_key
            .map(Into::into)
            .unwrap_or(JsValue::NULL),
        encrypted_public_key
            .map(Into::into)
            .unwrap_or(JsValue::NULL),
        encrypted_private_key
            .map(Into::into)
            .unwrap_or(JsValue::NULL),
        d1_i64(now_ms),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

/// Update PRF key material for a credential (after PRF assertion).
pub async fn update_prf_keys(
    db: &Db,
    credential_row_id: &str,
    encrypted_user_key: &str,
    encrypted_public_key: &str,
    encrypted_private_key: &str,
    now_ms: i64,
) -> Result<(), AppError> {
    db.prepare(
        "UPDATE webauthn_prf_credentials \
         SET supports_prf = 1, encrypted_user_key = ?1, encrypted_public_key = ?2, \
             encrypted_private_key = ?3, updated_at = ?4 \
         WHERE credential_row_id = ?5",
    )
    .bind(&[
        encrypted_user_key.into(),
        encrypted_public_key.into(),
        encrypted_private_key.into(),
        d1_i64(now_ms),
        credential_row_id.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

/// Update PRF keys during account key rotation (only user_key + public_key)
/// in a single D1 batch.
pub async fn rotate_prf_keys(
    db: &Db,
    updates: &[WebAuthnRotateKeyData],
    now_ms: i64,
) -> Result<(), AppError> {
    let stmt = updates
        .iter()
        .map(|data| {
            db.prepare(
                "UPDATE webauthn_prf_credentials \
                 SET encrypted_user_key = ?1, encrypted_public_key = ?2, updated_at = ?3 \
                 WHERE credential_row_id = ?4",
            )
            .bind(&[
                data.encrypted_user_key.as_str().into(),
                data.encrypted_public_key.as_str().into(),
                d1_i64(now_ms),
                data.id.as_str().into(),
            ])
            .map_err(|_| AppError::Database)
        })
        .collect::<Result<Vec<_>, _>>()?;
    db.batch(stmt).await.map_err(|_| AppError::Database)?;
    Ok(())
}

// ── Login credential + PRF queries ──────────────────────────────────────────

/// List all login credentials with their PRF status (joined query).
pub async fn list_login_credentials_with_prf(
    db: &Db,
    user_id: &str,
) -> Result<Vec<LoginCredentialWithPrf>, AppError> {
    db.prepare(
        "SELECT c.id, c.credential_id, c.name, c.transports, \
         COALESCE(p.supports_prf, 0) AS supports_prf, \
         p.encrypted_user_key, p.encrypted_public_key, p.encrypted_private_key \
         FROM webauthn_credentials c \
         LEFT JOIN webauthn_prf_credentials p ON c.id = p.credential_row_id \
         WHERE c.user_id = ?1 AND c.usage = 'login' \
         ORDER BY c.created_at ASC",
    )
    .bind(&[user_id.into()])?
    .all()
    .await
    .map_err(|_| AppError::Database)?
    .results::<LoginCredentialWithPrf>()
    .map_err(|_| AppError::Database)
}

/// Get the internal row_id for a login credential by its credential_id.
pub async fn get_login_row_id_by_credential_id(
    db: &Db,
    credential_id: &str,
) -> Result<Option<String>, AppError> {
    #[derive(Deserialize)]
    struct IdRow {
        id: String,
    }
    let row: Option<IdRow> = db
        .prepare(
            "SELECT id FROM webauthn_credentials \
             WHERE credential_id = ?1 AND usage = 'login'",
        )
        .bind(&[credential_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|v| serde_json::from_value(v).map_err(|_| AppError::Database))
        .transpose()?;
    Ok(row.map(|r| r.id))
}

/// Look up a single login credential's PRF decryption option by its credential_id.
/// Returns `Some(json)` only when the credential exists and PRF is fully enabled.
pub async fn get_prf_option_by_credential_id(
    db: &Db,
    credential_id: &str,
) -> Result<Option<serde_json::Value>, AppError> {
    let row: Option<LoginCredentialWithPrf> = db
        .prepare(
            "SELECT c.id, c.credential_id, c.name, c.transports, \
             COALESCE(p.supports_prf, 0) AS supports_prf, \
             p.encrypted_user_key, p.encrypted_public_key, p.encrypted_private_key \
             FROM webauthn_credentials c \
             LEFT JOIN webauthn_prf_credentials p ON c.id = p.credential_row_id \
             WHERE c.credential_id = ?1 AND c.usage = 'login'",
        )
        .bind(&[credential_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|v| serde_json::from_value(v).map_err(|_| AppError::Database))
        .transpose()?;
    Ok(row.and_then(|c| c.to_prf_option()))
}

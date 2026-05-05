use crate::db::Db;
use crate::models::user::WebAuthnRotateKeyData;
use async_trait::async_trait;
use passkey_server::error::Result as PkResult;
use passkey_server::store::PasskeyStore;
use passkey_server::types::{PasskeyState, StoredPasskey};
use serde::{Deserialize, Serialize};
use worker::wasm_bindgen::JsValue;

use crate::error::AppError;

const CREDENTIAL_COLUMNS: &str = "id, user_id, usage, provider_id, name, credential_id, \
    public_key, counter, aaguid, transports, backup_eligible, backup_state, created_at, last_used_at";

/// Credential usage kind, stored as `"twofactor"` or `"login"` in D1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialUsage {
    TwoFactor,
    #[allow(dead_code)]
    Login,
}

impl CredentialUsage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TwoFactor => "twofactor",
            Self::Login => "login",
        }
    }
}

/// D1-backed implementation of `PasskeyStore`.
///
/// `usage` controls which kind of credential gets created ("twofactor" or "login").
pub struct D1PasskeyStore<'a> {
    db: &'a Db,
    usage: CredentialUsage,
    /// Saved as `provider_id` in [WebauthnCredentialRow].
    requested_twofactor_provider_id: Option<i32>,
    /// When set, `create_passkey` uses this as the stored display name instead
    /// of the library-provided name (which has AAGUID appended).  The AAGUID is
    /// derived from the difference and written to the `aaguid` column.
    original_name: Option<String>,
}

impl<'a> D1PasskeyStore<'a> {
    pub fn new(db: &'a Db, usage: CredentialUsage) -> Self {
        Self {
            db,
            usage,
            requested_twofactor_provider_id: None,
            original_name: None,
        }
    }

    pub fn with_requested_twofactor_provider_id(mut self, provider_id: i32) -> Self {
        self.requested_twofactor_provider_id = Some(provider_id);
        self
    }

    pub fn with_original_name(mut self, name: String) -> Self {
        self.original_name = Some(name);
        self
    }
}

/// D1 row representation of a WebAuthn credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredentialRow {
    pub id: String,
    pub user_id: String,
    pub usage: String,
    // Serialize as id of webauthn key in response json
    pub provider_id: Option<i32>,
    pub name: String,
    pub credential_id: String,
    pub public_key: String,
    pub counter: i64,
    pub aaguid: Option<String>,
    pub transports: String,
    pub backup_eligible: i64,
    pub backup_state: i64,
    pub created_at: i64,
    pub last_used_at: i64,
}

impl From<WebauthnCredentialRow> for StoredPasskey {
    fn from(r: WebauthnCredentialRow) -> Self {
        Self {
            user_id: r.user_id,
            cred_id: r.credential_id,
            public_key: r.public_key,
            name: r.name,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
            counter: r.counter,
        }
    }
}

/// List WebAuthn credentials for a user and usage.
#[allow(dead_code)]
pub async fn list_credentials_by_usage(
    db: &Db,
    user_id: &str,
    usage: &str,
) -> Result<Vec<WebauthnCredentialRow>, AppError> {
    db.prepare(format!(
        "SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials \
         WHERE user_id = ?1 AND usage = ?2 ORDER BY created_at ASC",
    ))
    .bind(&[user_id.into(), usage.into()])?
    .all()
    .await
    .map_err(|_| AppError::Database)?
    .results::<WebauthnCredentialRow>()
    .map_err(|_| AppError::Database)
}

/// List all 2FA WebAuthn credentials for a user, ordered by provider_id.
pub async fn list_twofactor_credentials(
    db: &Db,
    user_id: &str,
) -> Result<Vec<WebauthnCredentialRow>, AppError> {
    db.prepare(format!(
        "SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials \
         WHERE user_id = ?1 AND usage = 'twofactor' ORDER BY provider_id ASC",
    ))
    .bind(&[user_id.into()])?
    .all()
    .await
    .map_err(|_| AppError::Database)?
    .results::<WebauthnCredentialRow>()
    .map_err(|_| AppError::Database)
}

/// Whether a 2FA WebAuthn provider id already exists for the user.
pub async fn twofactor_provider_id_exists(
    db: &Db,
    user_id: &str,
    provider_id: i32,
) -> Result<bool, AppError> {
    let row: Option<serde_json::Value> = db
        .prepare(
            "SELECT 1 AS present FROM webauthn_credentials \
             WHERE user_id = ?1 AND usage = 'twofactor' AND provider_id = ?2 LIMIT 1",
        )
        .bind(&[user_id.into(), provider_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    Ok(row.is_some())
}

/// Delete a 2FA WebAuthn credential by stable provider id.
pub async fn delete_twofactor_credential_by_provider_id(
    db: &Db,
    user_id: &str,
    provider_id: i32,
) -> Result<bool, AppError> {
    let result = db
        .prepare(
            "DELETE FROM webauthn_credentials \
             WHERE user_id = ?1 AND usage = 'twofactor' AND provider_id = ?2",
        )
        .bind(&[user_id.into(), provider_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let changed = result
        .meta()
        .map(|m| m.and_then(|m| m.changed_db).unwrap_or(false))
        .unwrap_or(false);
    Ok(changed)
}

// ── PasskeyStore trait implementation ───────────────────────────────────────

fn pk_err(msg: impl Into<String>) -> passkey_server::error::PasskeyError {
    passkey_server::error::PasskeyError::InternalError(msg.into())
}

fn d1_i64(value: i64) -> JsValue {
    // `i64.into()` becomes a JS BigInt in wasm, but D1 only accepts JS numbers.
    JsValue::from_f64(value as f64)
}

#[async_trait(?Send)]
impl<'a> PasskeyStore for D1PasskeyStore<'a> {
    async fn create_passkey(
        &self,
        user_id: String,
        cred_id: &str,
        public_key: &str,
        name: &str,
        counter: i64,
        created_at: i64,
    ) -> PkResult<()> {
        let row_id = uuid::Uuid::new_v4().to_string();
        let provider_id = if self.usage == CredentialUsage::TwoFactor {
            Some(
                self.requested_twofactor_provider_id
                    .ok_or_else(|| pk_err("missing twofactor provider id"))?,
            )
        } else {
            None
        };

        // passkey-server's finish_registration formats name as "{name}-{aaguid}".
        // When original_name is set, use it for the display name and extract the
        // AAGUID from the suffix that the library appended.
        let (display_name, aaguid) = if let Some(ref orig) = self.original_name {
            let prefix = format!("{}-", orig);
            let aaguid = if let Some(suffix) = name.strip_prefix(&prefix) {
                uuid::Uuid::parse_str(suffix).ok().map(|u| u.to_string())
            } else {
                None
            };
            (orig.as_str(), aaguid)
        } else {
            (name, None)
        };

        self.db
            .prepare(format!(
                "INSERT INTO webauthn_credentials ({CREDENTIAL_COLUMNS}) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"
            ))
            .bind(&[
                row_id.into(),
                user_id.into(),
                self.usage.as_str().into(),
                provider_id.map(Into::into).unwrap_or(JsValue::NULL),
                display_name.to_string().into(),
                cred_id.to_string().into(),
                public_key.to_string().into(),
                d1_i64(counter),
                aaguid.map(Into::into).unwrap_or(JsValue::NULL),
                "[]".to_string().into(), // transports
                d1_i64(0),               // backup_eligible
                d1_i64(0),               // backup_state
                d1_i64(created_at),
                d1_i64(created_at), // last_used_at = created_at initially
            ])
            .map_err(|e| pk_err(format!("bind error: {e}")))?
            .run()
            .await
            .map_err(|e| pk_err(format!("create_passkey: {e}")))?;
        Ok(())
    }

    async fn get_passkey(&self, cred_id: &str) -> PkResult<Option<StoredPasskey>> {
        let row: Option<WebauthnCredentialRow> = self
            .db
            .prepare(format!(
                "SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials \
                 WHERE credential_id = ?1 AND usage = ?2",
            ))
            .bind(&[cred_id.into(), self.usage.as_str().into()])
            .map_err(|e| pk_err(format!("bind error: {e}")))?
            .first(None)
            .await
            .map_err(|e| pk_err(format!("get_passkey: {e}")))?
            .map(|v| serde_json::from_value(v).map_err(|e| pk_err(format!("deser: {e}"))))
            .transpose()?;

        Ok(row.map(StoredPasskey::from))
    }

    async fn list_passkeys(&self, user_id: String) -> PkResult<Vec<StoredPasskey>> {
        let rows: Vec<WebauthnCredentialRow> = self
            .db
            .prepare(format!(
                "SELECT {CREDENTIAL_COLUMNS} FROM webauthn_credentials \
                 WHERE user_id = ?1 AND usage = ?2 ORDER BY created_at ASC",
            ))
            .bind(&[user_id.into(), self.usage.as_str().into()])
            .map_err(|e| pk_err(format!("bind error: {e}")))?
            .all()
            .await
            .map_err(|e| pk_err(format!("list_passkeys: {e}")))?
            .results()
            .map_err(|e| pk_err(format!("deser: {e}")))?;

        Ok(rows.into_iter().map(StoredPasskey::from).collect())
    }

    async fn delete_passkey(&self, user_id: String, cred_id: &str) -> PkResult<()> {
        self.db
            .prepare("DELETE FROM webauthn_credentials WHERE credential_id = ?1 AND user_id = ?2")
            .bind(&[cred_id.into(), user_id.into()])
            .map_err(|e| pk_err(format!("bind error: {e}")))?
            .run()
            .await
            .map_err(|e| pk_err(format!("delete_passkey: {e}")))?;
        Ok(())
    }

    async fn update_passkey_counter(
        &self,
        cred_id: &str,
        new_counter: i64,
        last_used_at: i64,
    ) -> PkResult<()> {
        self.db
            .prepare(
                "UPDATE webauthn_credentials SET counter = ?1, last_used_at = ?2 WHERE credential_id = ?3",
            )
            .bind(&[d1_i64(new_counter), d1_i64(last_used_at), cred_id.into()])
            .map_err(|e| pk_err(format!("bind error: {e}")))?
            .run()
            .await
            .map_err(|e| pk_err(format!("update_counter: {e}")))?;
        Ok(())
    }

    async fn update_passkey_name(&self, cred_id: &str, new_name: &str) -> PkResult<()> {
        self.db
            .prepare("UPDATE webauthn_credentials SET name = ?1 WHERE credential_id = ?2")
            .bind(&[new_name.into(), cred_id.into()])
            .map_err(|e| pk_err(format!("bind error: {e}")))?
            .run()
            .await
            .map_err(|e| pk_err(format!("update_name: {e}")))?;
        Ok(())
    }

    async fn save_state(&self, id: &str, state_json: &str, expires_at: i64) -> PkResult<()> {
        let now_ms = crate::webauthn::now_ms();
        let insert = self
            .db
            .prepare(
                "INSERT OR REPLACE INTO webauthn_states (id, state_json, expires_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&[
                id.into(),
                state_json.into(),
                d1_i64(expires_at),
                d1_i64(now_ms),
            ])
            .map_err(|e| pk_err(format!("bind error: {e}")))?;
        // Also purge expired states on save
        let purge = self
            .db
            .prepare("DELETE FROM webauthn_states WHERE expires_at <= ?1")
            .bind(&[d1_i64(now_ms)])
            .map_err(|e| pk_err(format!("bind error: {e}")))?;
        self.db
            .batch(vec![insert, purge])
            .await
            .map_err(|e| pk_err(format!("save_state batch: {e}")))?;
        Ok(())
    }

    async fn get_state(&self, id: &str) -> PkResult<Option<PasskeyState>> {
        let now_ms = crate::webauthn::now_ms();
        let row: Option<serde_json::Value> = self
            .db
            .prepare(
                "SELECT id, state_json, expires_at FROM webauthn_states \
                 WHERE id = ?1 AND expires_at > ?2",
            )
            .bind(&[id.into(), d1_i64(now_ms)])
            .map_err(|e| pk_err(format!("bind error: {e}")))?
            .first(None)
            .await
            .map_err(|e| pk_err(format!("get_state: {e}")))?;

        row.map(|v| serde_json::from_value(v).map_err(|e| pk_err(format!("deser: {e}"))))
            .transpose()
    }

    async fn delete_state(&self, id: &str) -> PkResult<()> {
        self.db
            .prepare("DELETE FROM webauthn_states WHERE id = ?1")
            .bind(&[id.into()])
            .map_err(|e| pk_err(format!("bind error: {e}")))?
            .run()
            .await
            .map_err(|e| pk_err(format!("delete_state: {e}")))?;
        Ok(())
    }
}

// ── Login credential queries ────────────────────────────────────────────────

/// Delete a login credential by its internal row id.
pub async fn delete_login_credential(
    db: &Db,
    user_id: &str,
    row_id: &str,
) -> Result<bool, AppError> {
    let result = db
        .prepare(
            "DELETE FROM webauthn_credentials \
             WHERE id = ?1 AND user_id = ?2 AND usage = 'login'",
        )
        .bind(&[row_id.into(), user_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    let changed = result
        .meta()
        .map(|m| m.and_then(|m| m.changed_db).unwrap_or(false))
        .unwrap_or(false);
    Ok(changed)
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
        d1_i64(supports_prf as i64),
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

/// Joined credential + PRF for a user's login credentials with PRF enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCredentialWithPrf {
    pub id: String,
    pub credential_id: String,
    pub name: String,
    pub transports: String,
    pub supports_prf: i64,
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

/// PRF status mirroring upstream `WebAuthnPrfStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfStatus {
    Enabled,
    Supported,
    Unsupported,
}

impl PrfStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "Enabled",
            Self::Supported => "Supported",
            Self::Unsupported => "Unsupported",
        }
    }
}

impl LoginCredentialWithPrf {
    /// Determine the PRF status for this credential.
    pub fn prf_status(&self) -> PrfStatus {
        if self.supports_prf == 0 {
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
            "EncryptedPrivateKey": self.encrypted_private_key,
            "EncryptedUserKey": self.encrypted_user_key,
            "CredentialId": self.credential_id,
            "Transports": transports
        }))
    }

    /// Serialize to the `GET /api/webauthn` response format
    /// (upstream `WebAuthnCredentialResponseModel`).
    pub fn to_response_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "prfStatus": self.prf_status().as_str(),
            "encryptedUserKey": self.encrypted_user_key,
            "encryptedPublicKey": self.encrypted_public_key,
            "object": "webAuthnCredential"
        })
    }
}

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

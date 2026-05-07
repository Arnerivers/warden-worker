use crate::db::Db;
use async_trait::async_trait;
use passkey_server::error::Result as PkResult;
use passkey_server::store::PasskeyStore;
use passkey_server::types::{AuthenticatorSelection, PasskeyState, StoredPasskey};
use serde::{Deserialize, Serialize};
use worker::wasm_bindgen::JsValue;

use crate::error::AppError;

const CREDENTIAL_COLUMNS: &str = "id, user_id, usage, provider_id, name, credential_id, \
    public_key, counter, aaguid, transports, backup_eligible, backup_state, created_at, last_used_at";

/// Credential usage kind, stored as `"twofactor"` or `"login"` in D1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialUsage {
    TwoFactor,
    Login,
}

impl CredentialUsage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TwoFactor => "twofactor",
            Self::Login => "login",
        }
    }

    pub fn authenticator_selection(self) -> AuthenticatorSelection {
        match self {
            Self::Login => AuthenticatorSelection {
                authenticator_attachment: None,
                require_resident_key: Some(true),
                resident_key: Some("required".into()),
                user_verification: Some("required".into()),
            },
            Self::TwoFactor => AuthenticatorSelection {
                authenticator_attachment: None,
                require_resident_key: Some(false),
                resident_key: None,
                user_verification: Some("discouraged".into()),
            },
        }
    }
}

/// Per-request store mode. Each variant carries exactly the data its business
/// scenario requires — invalid combinations are unrepresentable.
#[derive(Debug)]
pub enum StoreMode {
    /// Assertion (start/finish) or registration-start for login passkeys.
    Login,
    /// Assertion (start/finish) or registration-start for 2FA WebAuthn.
    TwoFactor,
    /// Registration-finish for a login passkey.
    LoginRegistration {
        row_id: String,
        original_name: String,
    },
    /// Registration-finish for a 2FA WebAuthn credential.
    TwoFactorRegistration {
        provider_id: i32,
        original_name: String,
    },
}

impl StoreMode {
    pub fn usage(&self) -> CredentialUsage {
        match self {
            Self::Login | Self::LoginRegistration { .. } => CredentialUsage::Login,
            Self::TwoFactor | Self::TwoFactorRegistration { .. } => CredentialUsage::TwoFactor,
        }
    }
}

/// D1-backed implementation of `PasskeyStore`.
///
/// Constructed via scene-specific constructors that enforce valid data
/// combinations at the type level.
pub struct D1PasskeyStore<'a> {
    db: &'a Db,
    mode: StoreMode,
}

impl<'a> D1PasskeyStore<'a> {
    /// Store for login assertion or registration-start (read + state ops only).
    pub fn for_login(db: &'a Db) -> Self {
        Self {
            db,
            mode: StoreMode::Login,
        }
    }

    /// Store for 2FA assertion or registration-start (read + state ops only).
    pub fn for_twofactor(db: &'a Db) -> Self {
        Self {
            db,
            mode: StoreMode::TwoFactor,
        }
    }

    /// Store for completing a login passkey registration.
    pub fn for_login_registration(db: &'a Db, row_id: String, original_name: String) -> Self {
        Self {
            db,
            mode: StoreMode::LoginRegistration {
                row_id,
                original_name,
            },
        }
    }

    /// Store for completing a 2FA WebAuthn credential registration.
    pub fn for_twofactor_registration(db: &'a Db, provider_id: i32, original_name: String) -> Self {
        Self {
            db,
            mode: StoreMode::TwoFactorRegistration {
                provider_id,
                original_name,
            },
        }
    }

    pub(crate) fn usage(&self) -> CredentialUsage {
        self.mode.usage()
    }

    /// Prefix a state id with the usage namespace to prevent cross-usage
    /// collisions (e.g. simultaneous login + 2FA registrations for the same user).
    fn scoped_state_id(&self, id: &str) -> String {
        format!("{}:{}", self.mode.usage().as_str(), id)
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

pub(crate) fn d1_i64(value: i64) -> JsValue {
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
        let (row_id, provider_id, original_name) = match &self.mode {
            StoreMode::LoginRegistration {
                row_id,
                original_name,
            } => (row_id.clone(), None, original_name.as_str()),
            StoreMode::TwoFactorRegistration {
                provider_id,
                original_name,
            } => (
                uuid::Uuid::new_v4().to_string(),
                Some(*provider_id),
                original_name.as_str(),
            ),
            _ => return Err(pk_err("create_passkey requires a registration-mode store")),
        };

        // passkey-server's finish_registration formats name as "{name}-{aaguid}".
        // Use original_name for the display name and extract the AAGUID from the
        // suffix that the library appended.
        let prefix = format!("{}-", original_name);
        let aaguid = name
            .strip_prefix(&prefix)
            .and_then(|suffix| uuid::Uuid::parse_str(suffix).ok())
            .map(|u| u.to_string());
        let display_name = original_name;

        self.db
            .prepare(format!(
                "INSERT INTO webauthn_credentials ({CREDENTIAL_COLUMNS}) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"
            ))
            .bind(&[
                row_id.into(),
                user_id.into(),
                self.mode.usage().as_str().into(),
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
            .bind(&[cred_id.into(), self.mode.usage().as_str().into()])
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
            .bind(&[user_id.into(), self.mode.usage().as_str().into()])
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
        let scoped_id = self.scoped_state_id(id);
        let now_ms = crate::webauthn::now_ms();
        let insert = self
            .db
            .prepare(
                "INSERT OR REPLACE INTO webauthn_states (id, state_json, expires_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&[
                scoped_id.as_str().into(),
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
        let scoped_id = self.scoped_state_id(id);
        let now_ms = crate::webauthn::now_ms();
        let row: Option<serde_json::Value> = self
            .db
            .prepare(
                "SELECT id, state_json, expires_at FROM webauthn_states \
                 WHERE id = ?1 AND expires_at > ?2",
            )
            .bind(&[scoped_id.as_str().into(), d1_i64(now_ms)])
            .map_err(|e| pk_err(format!("bind error: {e}")))?
            .first(None)
            .await
            .map_err(|e| pk_err(format!("get_state: {e}")))?;

        row.map(|v| serde_json::from_value(v).map_err(|e| pk_err(format!("deser: {e}"))))
            .transpose()
    }

    async fn delete_state(&self, id: &str) -> PkResult<()> {
        let scoped_id = self.scoped_state_id(id);
        self.db
            .prepare("DELETE FROM webauthn_states WHERE id = ?1")
            .bind(&[scoped_id.as_str().into()])
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

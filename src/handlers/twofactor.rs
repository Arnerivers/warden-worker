use axum::{extract::State, Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::d1_query;
use crate::webauthn::ceremony::ToBitwardenJson;
use crate::{
    auth::AuthUser,
    crypto::{base32_decode, ct_eq, generate_recovery_code, generate_totp_secret, validate_totp},
    db,
    error::AppError,
    handlers::allow_totp_drift,
    models::twofactor::{
        DisableAuthenticatorData, DisableTwoFactorData, EnableAuthenticatorData, TwoFactor,
        TwoFactorType,
    },
    models::user::{PasswordOrOtpData, User},
    util::NumberOrString,
    webauthn, BaseUrl,
};

/// List all 2FA providers for a user.
///
/// Batches two queries in a single D1 batch:
///   1. `twofactor` table (TOTP, Remember, etc.)
///   2. whether any `webauthn_credentials` exist for `usage = 'twofactor'`
///
/// When WebAuthn credentials exist, we synthesize a `TwoFactorType::Webauthn`
/// provider entry (atype = 7). The actual key list is returned by
/// `get_webauthn_twofactor`.
pub(crate) async fn list_user_twofactors(
    db: &crate::db::Db,
    user_id: &str,
) -> Result<Vec<TwoFactor>, AppError> {
    let stmt_tf = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000")
        .bind(&[user_id.to_string().into()])?;
    let stmt_wa = db
        .prepare(
            "SELECT 1 AS present FROM webauthn_credentials \
             WHERE user_id = ?1 AND usage = 'twofactor' LIMIT 1",
        )
        .bind(&[user_id.to_string().into()])?;

    let results = db
        .batch(vec![stmt_tf, stmt_wa])
        .await
        .map_err(|_| AppError::Database)?;

    let mut twofactors: Vec<TwoFactor> = results[0]
        .results::<TwoFactor>()
        .map_err(|_| AppError::Database)?;

    let has_webauthn = !results[1]
        .results::<serde_json::Value>()
        .map_err(|_| AppError::Database)?
        .is_empty();

    if has_webauthn {
        twofactors.push(TwoFactor {
            uuid: format!("webauthn-2fa-{user_id}"),
            user_uuid: user_id.to_string(),
            atype: TwoFactorType::Webauthn as i32,
            enabled: true,
            data: String::new(),
            last_used: 0,
        });
    }

    Ok(twofactors)
}

/// Whether the user has any real 2FA provider enabled (TOTP or WebAuthn).
pub(crate) fn is_twofactor_enabled(twofactors: &[TwoFactor]) -> bool {
    twofactors.iter().any(|tf| {
        tf.enabled
            && (tf.atype == TwoFactorType::Authenticator as i32
                || tf.atype == TwoFactorType::Webauthn as i32)
    })
}

/// Build a deduplicated, sorted list of active 2FA provider IDs from the
/// combined twofactor list (used for `TwoFactorProviders` in the error response).
pub(crate) fn active_provider_ids(twofactors: &[TwoFactor]) -> Vec<i32> {
    let mut ids: Vec<i32> = twofactors
        .iter()
        .filter(|tf| {
            tf.enabled
                && (tf.atype == TwoFactorType::Authenticator as i32
                    || tf.atype == TwoFactorType::Webauthn as i32)
        })
        .map(|tf| tf.atype)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// GET /api/two-factor - Get all enabled 2FA providers for current user
#[worker::send]
pub async fn get_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let twofactors = list_user_twofactors(&db, &user_id).await?;
    let providers: Vec<Value> = twofactors.iter().map(|tf| tf.to_json_provider()).collect();

    Ok(Json(json!({
        "data": providers,
        "object": "list",
        "continuationToken": null,
    })))
}

/// POST /api/two-factor/get-authenticator - Get or generate TOTP secret
#[worker::send]
pub async fn get_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&data).await?;

    // Check if TOTP is already configured
    let existing: Option<Value> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let (enabled, key) = match existing {
        Some(tf_value) => {
            let tf: TwoFactor = serde_json::from_value(tf_value).map_err(|_| AppError::Internal)?;
            (true, tf.data)
        }
        None => (false, generate_totp_secret()?),
    };

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// POST /api/two-factor/authenticator - Activate TOTP
#[worker::send]
pub async fn activate_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    })
    .await?;

    let key = data.key.to_uppercase();

    // Validate key format (Base32, 20 bytes = 32 characters without padding)
    let decoded_key = base32_decode(&key)?;
    if decoded_key.len() != 20 {
        return Err(AppError::BadRequest("Invalid key length".to_string()));
    }

    // Check if TOTP is already configured - reuse existing record for replay protection
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    // Get last_used from existing record to prevent replay during reconfiguration
    let previous_last_used = existing.as_ref().map(|tf| tf.last_used).unwrap_or(0);

    // Validate TOTP code and capture time step for replay protection
    let allow_drift = allow_totp_drift(&env);
    let last_used_step = validate_totp(&data.token, &key, previous_last_used, allow_drift).await?;

    // Delete existing TOTP to avoid stale bypass
    d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &user_id,
        TwoFactorType::Authenticator as i32
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Create new TOTP entry
    let mut twofactor = TwoFactor::new(user_id.clone(), TwoFactorType::Authenticator, key.clone());
    twofactor.last_used = last_used_step;

    d1_query!(
        &db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &twofactor.uuid,
        &twofactor.user_uuid,
        twofactor.atype,
        twofactor.enabled as i32,
        &twofactor.data,
        twofactor.last_used
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Generate recovery code if not exists
    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// PUT /api/two-factor/authenticator - Same as POST
#[worker::send]
pub async fn activate_authenticator_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    activate_authenticator(state, auth_user, json).await
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[worker::send]
pub async fn disable_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    })
    .await?;

    let type_ = data.r#type;

    if type_ == TwoFactorType::Webauthn as i32 {
        // WebAuthn credentials live in webauthn_credentials, not twofactor.
        db.prepare("DELETE FROM webauthn_credentials WHERE user_id = ?1 AND usage = 'twofactor'")
            .bind(&[user_id.clone().into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
    } else {
        d1_query!(
            &db,
            "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
            &user_id,
            type_
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    log::info!("User {} disabled 2FA type {}", user_id, type_);

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": type_,
        "object": "twoFactorProvider"
    })))
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[worker::send]
pub async fn disable_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    if data.r#type != TwoFactorType::Authenticator as i32 {
        return Err(AppError::BadRequest("Invalid two factor type".to_string()));
    }

    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    })
    .await?;

    // Fetch existing TOTP and verify key matches before deleting
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[user_id.clone().into(), data.r#type.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    let Some(tf) = existing else {
        return Err(AppError::BadRequest("TOTP not configured".to_string()));
    };

    // Compare keys case-insensitively (key is stored uppercased during activation)
    if !ct_eq(&tf.data, &data.key.to_uppercase()) {
        return Err(AppError::BadRequest(
            "TOTP key does not match recorded value".to_string(),
        ));
    }

    d1_query!(&db, "DELETE FROM twofactor WHERE uuid = ?1", &tf.uuid)
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    log::info!(
        "User {} disabled authenticator (2FA type {})",
        user_id,
        data.r#type
    );

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": data.r#type,
        "object": "twoFactorProvider"
    })))
}

/// PUT /api/two-factor/disable - Same as POST
#[worker::send]
pub async fn disable_twofactor_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    disable_twofactor(state, auth_user, json).await
}

/// POST /api/two-factor/get-recover - Get recovery code
#[worker::send]
pub async fn get_recover(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&data).await?;

    Ok(Json(serde_json::json!({
        "code": user.totp_recover,
        "object": "twoFactorRecover"
    })))
}

async fn generate_recovery_code_for_user(
    db: &crate::db::Db,
    user_id: &str,
) -> Result<(), AppError> {
    // Check if recovery code already exists
    let user_value: Value = db
        .prepare("SELECT totp_recover FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let totp_recover: Option<String> = user_value
        .get("totp_recover")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if totp_recover.is_none() {
        let recovery_code = generate_recovery_code()?;
        d1_query!(
            db,
            "UPDATE users SET totp_recover = ?1 WHERE id = ?2",
            &recovery_code,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}


/// Clear recovery code when no real 2FA providers remain (checks TOTP + WebAuthn).
async fn clear_recovery_if_no_twofactor(db: &crate::db::Db, user_id: &str) -> Result<(), AppError> {
    let remaining = list_user_twofactors(db, user_id).await?;

    if !is_twofactor_enabled(&remaining) {
        d1_query!(
            db,
            "UPDATE users SET totp_recover = NULL WHERE id = ?1",
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}

// ── WebAuthn 2FA management endpoints ───────────────────────────────────────
//
// Vaultwarden compatibility quirk:
// - `POST /api/two-factor/get-webauthn` returns `"object": "twoFactorWebAuthn"`
// - `POST/PUT/DELETE /api/two-factor/webauthn` returns `"object": "twoFactorU2f"`

/// POST /api/two-factor/get-webauthn - List 2FA WebAuthn credentials
#[worker::send]
pub async fn get_webauthn_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&data).await?;

    let creds = webauthn::store::list_twofactor_credentials(&db, &user_id).await?;
    let keys = webauthn_keys_json(&creds)?;

    Ok(Json(json!({
        "enabled": !creds.is_empty(),
        "keys": keys,
        "object": "twoFactorWebAuthn"
    })))
}

/// POST /api/two-factor/get-webauthn-challenge - Generate registration challenge
#[worker::send]
pub async fn get_webauthn_challenge(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    AuthUser(user_id, email): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&data).await?;

    let config = webauthn::build_passkey_config(&base_url);
    let store =
        webauthn::store::D1PasskeyStore::new(&db, webauthn::store::CredentialUsage::TwoFactor);
    let now_ms = webauthn::now_ms();

    let display_name = user.name.as_deref().unwrap_or(&email);
    let opts = webauthn::ceremony::start_ceremony_registration(
        &store,
        &user_id,
        &email,
        display_name,
        &config,
        now_ms,
    )
    .await?;

    let mut challenge_value = opts.to_bitwarden_json();
    challenge_value["status"] = serde_json::Value::String("ok".into());
    challenge_value["errorMessage"] = serde_json::Value::String(String::new());
    Ok(Json(challenge_value))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnRegisterData {
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    pub id: NumberOrString,
    pub device_response: Value,
    pub name: String,
}

/// POST or PUT /api/two-factor/webauthn - Complete 2FA WebAuthn registration
#[worker::send]
pub async fn activate_webauthn(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<WebauthnRegisterData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let WebauthnRegisterData {
        master_password_hash,
        otp,
        id,
        device_response,
        name,
    } = data;

    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&PasswordOrOtpData {
        master_password_hash,
        otp,
    })
    .await?;

    let provider_id = id.try_i32()?;
    if webauthn::store::twofactor_provider_id_exists(&db, &user_id, provider_id).await? {
        return Err(AppError::BadRequest(
            "WebAuthn credential id already exists".to_string(),
        ));
    }

    let config = webauthn::build_passkey_config(&base_url);
    let store =
        webauthn::store::D1PasskeyStore::new(&db, webauthn::store::CredentialUsage::TwoFactor)
            .with_requested_twofactor_provider_id(provider_id)
            .with_original_name(name.clone());
    let now_ms = webauthn::now_ms();

    let reg_response =
        webauthn::compat::RegistrationResponseCompat::parse(device_response, Some(name))?;

    webauthn::ceremony::finish_ceremony_registration(
        &store,
        &user_id,
        &config,
        reg_response,
        now_ms,
    )
    .await?;

    // Generate recovery code if not present
    generate_recovery_code_for_user(&db, &user_id).await?;

    let creds = webauthn::store::list_twofactor_credentials(&db, &user_id).await?;
    let keys = webauthn_keys_json(&creds)?;

    Ok(Json(json!({
        "enabled": true,
        "keys": keys,
        "object": "twoFactorU2f"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebauthnDeleteData {
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
    pub id: NumberOrString,
}

/// DELETE /api/two-factor/webauthn - Delete a 2FA WebAuthn credential
#[worker::send]
pub async fn delete_webauthn(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<WebauthnDeleteData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&PasswordOrOtpData {
        master_password_hash: data.master_password_hash,
        otp: data.otp,
    })
    .await?;

    let provider_id = data.id.try_i32()?;
    let deleted =
        webauthn::store::delete_twofactor_credential_by_provider_id(&db, &user_id, provider_id)
            .await?;
    if !deleted {
        return Err(AppError::BadRequest("Invalid credential id".into()));
    }

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    let creds = webauthn::store::list_twofactor_credentials(&db, &user_id).await?;
    let keys = webauthn_keys_json(&creds)?;

    Ok(Json(json!({
        "enabled": !creds.is_empty(),
        "keys": keys,
        "object": "twoFactorU2f"
    })))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build the `keys` array for WebAuthn 2FA response (Vaultwarden-compatible integer IDs).
fn webauthn_keys_json(
    creds: &[webauthn::store::WebauthnCredentialRow],
) -> Result<Vec<Value>, AppError> {
    creds
        .iter()
        .map(|c| {
            let provider_id = c.provider_id.ok_or(AppError::Internal)?;
            Ok(json!({
                "id": provider_id,
                "name": c.name,
                "migrated": false,
            }))
        })
        .collect()
}

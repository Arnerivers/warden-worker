use axum::{extract::Path, extract::State, Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::webauthn::twofactor::ToBitwardenJson;
use crate::{
    auth::AuthUser,
    db,
    error::AppError,
    models::user::{PasswordOrOtpData, User},
    webauthn, BaseUrl,
};

/// GET /api/webauthn — List the current user's login passkey credentials with PRF status.
#[worker::send]
pub async fn get_webauthn_credentials(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let creds = webauthn::store::list_login_credentials_with_prf(&db, &user_id).await?;
    let data: Vec<Value> = creds.iter().map(|c| c.to_response_json()).collect();

    Ok(Json(json!({
        "object": "list",
        "data": data,
        "continuationToken": null
    })))
}

/// POST /api/webauthn/attestation-options — Generate registration challenge
#[worker::send]
pub async fn post_attestation_options(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    AuthUser(user_id, email): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&data).await?;

    let config = webauthn::build_passkey_config(&base_url);
    let store = webauthn::store::D1PasskeyStore::new(&db, webauthn::store::CredentialUsage::Login);
    let now_ms = webauthn::now_ms();
    let display_name = user.name.as_deref().unwrap_or(&email);

    let opts = webauthn::login::start_login_registration(
        &store,
        &user_id,
        &email,
        display_name,
        &config,
        now_ms,
    )
    .await?;

    let options_json = opts.to_bitwarden_json();

    Ok(Json(json!({
        "options": options_json,
        "token": null,
        "object": "webAuthnCredentialCreateOptions"
    })))
}

// ── POST /api/webauthn — Create login credential ────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateLoginCredentialRequest {
    pub device_response: Value,
    pub name: String,
    #[allow(dead_code)]
    pub token: Option<String>,
    pub supports_prf: Option<bool>,
    pub encrypted_user_key: Option<String>,
    pub encrypted_public_key: Option<String>,
    pub encrypted_private_key: Option<String>,
}

/// Complete registration of a login passkey and persist
/// the associated PRF key material (if `supportsPrf` is true).
#[worker::send]
pub async fn post_webauthn_credential(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<CreateLoginCredentialRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let config = webauthn::build_passkey_config(&base_url);
    let store = webauthn::store::D1PasskeyStore::new(&db, webauthn::store::CredentialUsage::Login)
        .with_original_name(data.name.clone());
    let now_ms = webauthn::now_ms();

    let mut compat_response: webauthn::compat::RegistrationResponseCompat =
        serde_json::from_value(data.device_response).map_err(|e| {
            log::error!("Failed to parse WebAuthn deviceResponse: {e}");
            AppError::BadRequest("Invalid deviceResponse".to_string())
        })?;
    compat_response.name = Some(data.name.clone());
    let credential_id = compat_response.id.clone();
    let reg_response: passkey_server::types::RegistrationResponse = compat_response.into();

    webauthn::login::finish_login_registration(&store, &user_id, &config, reg_response, now_ms)
        .await?;

    // Look up the newly-created credential by its globally-unique credential_id
    let row_id = webauthn::store::get_login_row_id_by_credential_id(&db, &credential_id)
        .await?
        .ok_or(AppError::Internal)?;

    let supports_prf = data.supports_prf.unwrap_or(false);
    webauthn::store::create_prf_credential(
        &db,
        &row_id,
        supports_prf,
        data.encrypted_user_key.as_deref(),
        data.encrypted_public_key.as_deref(),
        data.encrypted_private_key.as_deref(),
        now_ms,
    )
    .await?;

    let all_creds = webauthn::store::list_login_credentials_with_prf(&db, &user_id).await?;
    let resp_data: Vec<Value> = all_creds.iter().map(|c| c.to_response_json()).collect();

    Ok(Json(json!({
        "object": "list",
        "data": resp_data,
        "continuationToken": null
    })))
}

/// POST /api/webauthn/assertion-options — Generate an assertion challenge for
/// updating PRF key material on an existing login passkey.
#[worker::send]
pub async fn post_assertion_options(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&data).await?;

    let config = webauthn::build_passkey_config(&base_url);
    let store = webauthn::store::D1PasskeyStore::new(&db, webauthn::store::CredentialUsage::Login);
    let now_ms = webauthn::now_ms();

    let opts = webauthn::login::start_login_assertion(&store, &config, now_ms).await?;
    let options_json = opts.to_bitwarden_json();

    Ok(Json(json!({
        "options": options_json,
        "token": null,
        "object": "webAuthnLoginAssertionOptions"
    })))
}

// ── PUT /api/webauthn — Update PRF keys ─────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePrfKeysRequest {
    pub device_response: Value,
    #[allow(dead_code)]
    pub token: Option<String>,
    pub encrypted_user_key: String,
    pub encrypted_public_key: String,
    pub encrypted_private_key: String,
}

/// After a successful assertion with PRF extension results,
/// store the encrypted user key / public key / private key for this credential.
#[worker::send]
pub async fn put_webauthn_credential(
    State(env): State<Arc<Env>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<UpdatePrfKeysRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let config = webauthn::build_passkey_config(&base_url);
    let store = webauthn::store::D1PasskeyStore::new(&db, webauthn::store::CredentialUsage::Login);
    let now_ms = webauthn::now_ms();

    let compat_response: webauthn::compat::LoginResponseCompat =
        serde_json::from_value(data.device_response).map_err(|e| {
            log::error!("Failed to parse WebAuthn deviceResponse: {e}");
            AppError::BadRequest("Invalid deviceResponse".to_string())
        })?;
    let credential_id = compat_response.id.clone();
    let login_response: passkey_server::types::LoginResponse = compat_response.into();

    let returned_user_id =
        webauthn::login::finish_login_assertion(&store, &config, login_response, now_ms).await?;

    if returned_user_id != user_id {
        return Err(AppError::BadRequest("WebAuthn credential mismatch".into()));
    }

    let row_id = webauthn::store::get_login_row_id_by_credential_id(&db, &credential_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Credential not found".into()))?;

    webauthn::store::update_prf_keys(
        &db,
        &row_id,
        &data.encrypted_user_key,
        &data.encrypted_public_key,
        &data.encrypted_private_key,
        now_ms,
    )
    .await?;

    let all_creds = webauthn::store::list_login_credentials_with_prf(&db, &user_id).await?;
    let resp_data: Vec<Value> = all_creds.iter().map(|c| c.to_response_json()).collect();

    Ok(Json(json!({
        "object": "list",
        "data": resp_data,
        "continuationToken": null
    })))
}

/// POST /api/webauthn/{id}/delete — Delete a login passkey credential
/// (and its associated PRF record via CASCADE).
#[worker::send]
pub async fn delete_webauthn_credential(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = User::find_by_id(&db, &user_id).await?;
    user.verify_password_or_otp(&data).await?;

    let deleted = webauthn::store::delete_login_credential(&db, &user_id, &id).await?;
    if !deleted {
        return Err(AppError::NotFound("Credential not found".into()));
    }

    Ok(Json(json!({})))
}

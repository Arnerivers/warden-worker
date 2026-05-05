use passkey_server::types::{
    AuthenticatorSelection, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
};
use passkey_server::{
    finish_login, finish_registration, start_login, start_registration, PasskeyConfig,
};

use super::store::D1PasskeyStore;
use crate::error::AppError;

// ── Login Passkey Registration ──────────────────────────────────────────────

/// Generate registration options for a login passkey (discoverable credential).
///
/// Overrides `authenticator_selection` to require resident key and user
/// verification — needed for passwordless / discoverable login.
pub async fn start_login_registration(
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
            log::error!("Login passkey registration start failed: {e}");
            AppError::BadRequest("WebAuthn registration start failed".into())
        })?;

    opts.authenticator_selection = Some(AuthenticatorSelection {
        authenticator_attachment: None,
        require_resident_key: Some(true),
        resident_key: Some("required".into()),
        user_verification: Some("required".into()),
    });

    Ok(opts)
}

/// Complete a login passkey registration.
pub async fn finish_login_registration(
    store: &D1PasskeyStore<'_>,
    user_id: &str,
    config: &PasskeyConfig,
    response: passkey_server::types::RegistrationResponse,
    now_ms: i64,
) -> Result<(), AppError> {
    finish_registration(store, user_id, config, response, now_ms)
        .await
        .map_err(|e| {
            log::error!("Login passkey registration verification failed: {e}");
            AppError::BadRequest("WebAuthn registration failed".into())
        })
}

// ── Login Passkey Assertion (discoverable) ──────────────────────────────────

/// Generate assertion options for anonymous passkey login.
///
/// Uses `start_login` which produces discoverable-credential options
/// (empty `allowCredentials`, saves state as `login:{challenge}`).
/// Overrides `user_verification` to `"required"`.
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

/// Verify a login passkey assertion and return the authenticated user_id.
pub async fn finish_login_assertion(
    store: &D1PasskeyStore<'_>,
    config: &PasskeyConfig,
    response: passkey_server::types::LoginResponse,
    now_ms: i64,
) -> Result<String, AppError> {
    finish_login(store, config, response, now_ms)
        .await
        .map_err(|e| {
            log::error!("Login passkey assertion verification failed: {e}");
            AppError::BadRequest("WebAuthn login failed".into())
        })
}

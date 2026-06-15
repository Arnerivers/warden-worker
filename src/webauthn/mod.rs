pub mod ceremony;
pub mod compat;
pub mod prf;
pub mod store;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use passkey_server::PasskeyConfig;
use serde::Deserialize;
use url::Url;

/// Build a `PasskeyConfig` from the application's `BaseUrl`.
///
/// `base_url` is the same value carried by `Extension<BaseUrl>` (e.g.
/// `"https://vault.example.com"`).
///
/// - `rp_id`  = hostname portion of `base_url` (without port), fallback `"localhost"`
/// - `origin` = `base_url` as-is
/// - `rp_name` = `"Warden"`
pub fn build_passkey_config(base_url: &str) -> PasskeyConfig {
    let rp_id = Url::parse(base_url)
        .ok()
        .as_ref()
        .and_then(|parsed| parsed.host_str())
        .map(|str| str.to_string())
        .unwrap_or_else(|| "localhost".into());

    PasskeyConfig {
        rp_id,
        rp_name: "Warden".into(),
        origin: base_url.to_string(),
        state_ttl: 300,
    }
}

pub fn now_ms() -> i64 {
    js_sys::Date::now() as i64
}

#[derive(Deserialize)]
struct ClientData {
    origin: String,
}

fn is_allowed_origin(base_url: &str, origin: &str) -> bool {
    let origin = origin.trim_end_matches('/');

    if origin == base_url {
        return true;
    }

    const ALLOWED_EXTENSIONS: &[&str] = &[
        "chrome-extension://nngceckbapebfimnlniiiahkandclblb",
        "chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh",
        "chrome-extension://ccnckbpmaceehanjmeomladnmlffdjgn",
    ];

    if ALLOWED_EXTENSIONS.contains(&origin) {
        return true;
    }

    if origin.starts_with("moz-extension://") {
        return true;
    }

    false
}

/// Parse the origin from base64url-encoded `client_data_json`.
/// If it matches one of the allowed origins, clone `config` and update its `origin` field
/// to bypass the library's strict origin validation check.
/// Returns the updated config, or the original config if parsing fails or origin is not allowed.
pub fn verify_origin_and_align_config(
    config: &PasskeyConfig,
    client_data_json_b64: &str,
) -> PasskeyConfig {
    let mut adjusted = config.clone();
    let base_url = &config.origin;

    let decoded_bytes = match URL_SAFE_NO_PAD.decode(client_data_json_b64) {
        Ok(bytes) => bytes,
        Err(_) => return adjusted,
    };

    let client_data: ClientData = match serde_json::from_slice(&decoded_bytes) {
        Ok(data) => data,
        Err(_) => return adjusted,
    };

    if is_allowed_origin(base_url, &client_data.origin) {
        adjusted.origin = client_data.origin;
    }

    adjusted
}

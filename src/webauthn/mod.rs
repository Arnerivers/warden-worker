pub mod compat;
pub mod store;
pub mod twofactor;

use passkey_server::PasskeyConfig;
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

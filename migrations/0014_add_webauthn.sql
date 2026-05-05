-- WebAuthn credentials (shared by 2FA and login passkeys)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    usage TEXT NOT NULL,          -- 'twofactor' | 'login'
    provider_id INTEGER,          -- stable 2FA key id exposed via the Bitwarden API
    name TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL,
    aaguid TEXT,
    transports TEXT NOT NULL DEFAULT '[]',
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,  -- ms timestamp
    last_used_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_usage
    ON webauthn_credentials(user_id, usage);

CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_user_usage_provider_id
    ON webauthn_credentials(user_id, usage, provider_id)
    WHERE provider_id IS NOT NULL;

-- PRF key material (only for usage='login' credentials)
CREATE TABLE IF NOT EXISTS webauthn_prf_credentials (
    credential_row_id TEXT PRIMARY KEY NOT NULL,
    supports_prf INTEGER NOT NULL,
    encrypted_user_key TEXT,
    encrypted_public_key TEXT,
    encrypted_private_key TEXT,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (credential_row_id) REFERENCES webauthn_credentials(id) ON DELETE CASCADE
);

-- Ephemeral WebAuthn challenge states
CREATE TABLE IF NOT EXISTS webauthn_states (
    id TEXT PRIMARY KEY NOT NULL,
    state_json TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webauthn_states_expires
    ON webauthn_states(expires_at);

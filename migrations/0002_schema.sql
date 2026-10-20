-- Silo core schema. The server stores only opaque, encrypted vault payloads
-- and salted Argon2id hashes of the client-derived auth key; it never stores
-- raw passphrases, raw auth keys, vault keys, or session tokens.

CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    auth_key_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE vaults (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    version BIGINT NOT NULL DEFAULT 0,
    ciphertext TEXT,
    nonce TEXT,
    CONSTRAINT vault_payload_valid CHECK (
        (version = 0 AND ciphertext IS NULL AND nonce IS NULL)
        OR (version > 0 AND ciphertext IS NOT NULL AND nonce IS NOT NULL)
    )
);

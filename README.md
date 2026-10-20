# silo-backend

Rust backend for Silo: axum 0.8 + tokio, PostgreSQL via sqlx (runtime
tokio-rustls, embedded migrations on startup), Argon2id auth-key hashing,
cookie sessions, opaque whole-vault CAS, and user-scoped websocket
invalidations.

The server is deliberately key- and plaintext-blind. It stores only the
base64-encoded encrypted vault snapshot, the client's 16-byte KDF salt, and an
Argon2id hash of the client-derived 32-byte auth key. Session tokens are random
and stored only as SHA-256 hashes.

## Routes

| Method | Path                | Success | Purpose |
| ------ | ------------------- | ------- | ------- |
| GET    | `/api/health`       | 200     | DB readiness (`{"status":"ok"}`) |
| POST   | `/api/auth/register`| 201     | `{email,auth_key,salt}` → user + session cookie |
| GET    | `/api/auth/salt`    | 200     | `?email=...` → `{salt}` (401 when unknown) |
| POST   | `/api/auth/login`   | 200     | `{email,auth_key}` → user + session cookie |
| GET    | `/api/auth/me`      | 200     | `{id,email,salt}` for the session |
| POST   | `/api/auth/logout`  | 204     | Deletes session and clears cookie (500 if delete fails) |
| GET    | `/api/vault`        | 200     | `{version,ciphertext,nonce}` (empty = `version:0`, nulls) |
| PUT    | `/api/vault`        | 200     | `{expected_version,ciphertext,nonce}` → `{version}`; 409 on CAS conflict |
| GET    | `/api/events`       | 101     | Authenticated websocket; sends `{"type":"vault_changed","version":N}` |

All errors use `{"error":"..."}`. Vault payloads are opaque to the server; no
plaintext metadata fields are accepted or stored.

## Local setup

Requirements: Rust stable and PostgreSQL 16 (either locally or via Docker).

### With Docker Compose

```sh
cp .env.example .env    # optional; compose has safe defaults
docker compose up --build
```

The app listens on `http://127.0.0.1:3000` and the database on
`localhost:5432` (host ports are configurable via `APP_PORT`/`POSTGRES_PORT`).
Both published dev ports bind only to `127.0.0.1`, never all host interfaces.
Migrations are applied automatically when the app starts. `curl -fsS
http://127.0.0.1:3000/api/health` should return `{"status":"ok"}`.

### With local Postgres

```sh
cp .env.example .env
export DATABASE_URL=postgres://silo:silo@localhost:5432/silo
export BIND_ADDR=0.0.0.0:3000
cargo run
```

### Integration tests against a temporary Postgres

The DB tests fail (rather than skip) when `DATABASE_URL` is unset, because the
security-critical behavior is only meaningful against a real database. To run
them locally without touching a shared port:

```sh
POSTGRES_PORT=55432 docker compose -p silo-backend-unit up -d db
DATABASE_URL=postgres://silo:silo@127.0.0.1:55432/silo cargo test
POSTGRES_PORT=55432 docker compose -p silo-backend-unit down -v
```

## Configuration

| Variable            | Default                     | Meaning |
| ------------------- | --------------------------- | ------- |
| `DATABASE_URL`      | (required)                  | PostgreSQL connection string |
| `BIND_ADDR`         | `0.0.0.0:3000`              | Socket the server binds |
| `ALLOWED_ORIGIN`    | `http://127.0.0.1:5173`     | Exact browser `Origin` accepted for writes and websocket |
| `COOKIE_SECURE`     | `false`                     | Set to `true` behind HTTPS; controls the `Secure` cookie flag |
| `SESSION_TTL_HOURS` | `168`                       | Session lifetime in hours, clamped to `1..=168` |

`DATABASE_URL` may embed credentials and is never logged. The Vite dev server
proxies `/api` (including websocket upgrades), so the browser is same-origin
and no permissive CORS layer is enabled.

## Security model

- **No recovery/reset.** The raw passphrase and vault key never leave the
  browser. There is no account recovery or reset flow in the MVP; losing the
  passphrase means losing the vault. This is intentional and documented.
- **Auth key at rest.** The client sends a PBKDF2-derived 32-byte auth key.
  The server verifies byte length (32) and Argon2id-hashes it with a fresh
  salt; the raw auth key is never stored.
- **Sessions.** Session tokens are 32 random bytes, sent only as an
  `HttpOnly; SameSite=Strict; Path=/api` cookie (plus `Secure` in production),
  and stored only as SHA-256 hashes. Logout deletes the session row and only
  clears the cookie after that delete succeeds; a failed delete returns 500 so
  a captured token is not falsely reported as revoked. Expired rows are cleaned
  at startup and opportunistically on login.
- **No caching of API responses.** Every `/api` response carries
  `Cache-Control: no-store` and `Vary: Cookie` so browser and intermediary
  caches do not retain email/salt metadata or opaque vault bytes after logout.
- **Origin / CSRF.** State-changing requests with an `Origin` header must match
  `ALLOWED_ORIGIN`. Websocket upgrades always require the allowed `Origin`.
  There is no wildcard CORS with credentials.
- **Vault CAS.** `PUT /api/vault` is a single atomic `UPDATE ... WHERE user_id =
  $1 AND version = $2`. A stale `expected_version` returns 409 and never
  overwrites the newer snapshot. The returned version is the incremented
  committed value.
- **Invalidations.** After a successful CAS write, only websockets belonging to
  the same user receive `vault_changed`. The message contains a version number,
  never plaintext or ciphertext. Each socket has a bounded outbound queue; a
  slow or stalled subscriber is dropped and reconnects rather than allowing
  unbounded server memory growth.
- **Failure handling.** Base64/nonce/salt/auth-key lengths are validated before
  any DB write. Decoded ciphertext is capped at 8 MiB; the HTTP body limit is
  16 MiB to accommodate padded base64 and the JSON envelope.

## Metadata and deployment limitations

- **Account enumeration and email verification.** `GET /api/auth/salt` returns
  200 for an existing account and 401 otherwise, and `POST /api/auth/register`
  returns a distinct 409 for an already-registered email. Both reveal whether
  an email is registered. The MVP has **no email ownership verification**, so
  registration is also an identifier-squatting surface. Deployments **must**
  place an external rate limiter (reverse proxy/WAF) in front of auth/salt
  endpoints and, outside the MVP, should add ownership verification. Login
  responses are deliberately generic, and the unknown-account path performs a
  dummy Argon2 hash to reduce timing side-channel leakage.
- **Single-instance broadcasts.** Vault invalidations are delivered through an
  in-process hub. Running more than one backend replica requires an external
  fan-out (for example Redis pub/sub); without it a write on replica A will
  not reach a websocket connected to replica B.
- **Whole-vault snapshots.** There is no multi-master realtime character
  merging. Every save is a full encrypted vault snapshot guarded by CAS;
  clients present an explicit conflict choice rather than auto-merging.
- **No audit claim.** This MVP does not provide tamper-evident or write-once
  audit logging for vault history.
- **Dev compose credentials are development-only.** `docker-compose.yml`
  publishes its ports on `127.0.0.1` and uses the default `silo/silo`
  credentials strictly for local development. Production must provision its own
  secrets externally (for example a secrets manager or operator-managed
  environment); do not reuse these defaults outside localhost.

## Threat model (E2E)

- The backend (and anyone with database access) sees account email addresses,
  KDF salts, Argon2id auth-key hashes, session hashes, per-user vault versions,
  and opaque ciphertext/nonce pairs. It cannot recover plaintext notes,
  folders, editor state, the auth key, or the vault key.
- The browser performs PBKDF2/HKDF and AES-GCM locally. A compromised backend
  can attempt to serve malicious JavaScript on future visits; HTTPS and
  trusting the served frontend remain assumptions of the browser-side E2E
  model.
- TLS must terminate at the edge in production (`COOKIE_SECURE=true`), or
  session cookies and opaque ciphertext would traverse plaintext HTTP.
- The backend rejects malformed base64/lengths and cross-origin writes, but it
  cannot detect a client that encrypts the wrong bytes; authenticity failures
  are detected by the client and must fail closed there.

## Development gates

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test            # requires DATABASE_URL; see integration-test section
```

CI (`.github/workflows/ci.yml`) runs all three on pushes to `main` and pull
requests, with a PostgreSQL 16 service, an explicit readiness wait, and
`DATABASE_URL` preconfigured. DB integration tests are not silently skipped.

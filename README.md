# silo-backend

Rust backend for Silo: axum 0.8 + tokio, PostgreSQL via sqlx (runtime
tokio-rustls, embedded migrations on startup), tracing.

Currently the bootstrap skeleton only: `GET /api/health` (DB readiness
placeholder). Auth, vault and websocket routes arrive with feature work.

## Local setup

Requires Rust (stable) and a running PostgreSQL instance.

```sh
cp .env.example .env   # fill in values; no secrets are committed
export DATABASE_URL=postgres://silo:silo@localhost:5432/silo
export BIND_ADDR=0.0.0.0:3000

cargo run
```

Migrations in `migrations/` are applied automatically on startup.

Verify:

```sh
curl -s http://127.0.0.1:3000/api/health
# {"status":"ok"}
```

## Configuration

| Variable       | Default         | Meaning                          |
| -------------- | --------------- | -------------------------------- |
| `DATABASE_URL` | (required)      | PostgreSQL connection string     |
| `BIND_ADDR`    | `0.0.0.0:3000`  | Socket the server binds          |

## Development gates

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI (`.github/workflows/ci.yml`) runs all three on pushes to `main` and pull
requests, with a PostgreSQL 16 service and `DATABASE_URL` preconfigured.

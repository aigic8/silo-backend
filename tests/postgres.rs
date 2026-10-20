//! Real-Postgres integration tests for the Silo backend.
//!
//! These tests intentionally refuse to run without `DATABASE_URL`; they are
//! not silently skipped. CI supplies a PostgreSQL service, and locally they
//! can be pointed at the temporary Postgres described in the README.
//!
//! A single top-level test drives the scenarios sequentially so the shared
//! database is reset between scenarios without racing other test binaries.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use silo_backend::{build_router, run_migrations, AppConfig, AppState, EventHub, ServerEvent};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "http://127.0.0.1:5173";
const EVIL_ORIGIN: &str = "http://evil.example";

fn test_config() -> AppConfig {
    AppConfig {
        allowed_origin: ORIGIN.to_string(),
        cookie_secure: false,
        session_ttl_hours: 1,
    }
}

async fn connect_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set for the Postgres integration tests");
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("failed to connect to Postgres")
}

async fn reset_db(pool: &PgPool) {
    sqlx::query("TRUNCATE TABLE sessions, vaults, users RESTART IDENTITY CASCADE")
        .execute(pool)
        .await
        .expect("failed to reset test database");
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn json_request(
    method: Method,
    uri: &str,
    body: Value,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, format!("silo_session={cookie}"));
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    builder.body(Body::from(body.to_string())).expect("request")
}

fn get_request(uri: &str, cookie: Option<&str>, origin: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, format!("silo_session={cookie}"));
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    builder.body(Body::empty()).expect("request")
}

fn cookie_from(response: &Response) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            let (name, cookie_value) = value.split(';').next()?.split_once('=')?;
            (name == "silo_session" && !cookie_value.is_empty()).then(|| cookie_value.to_string())
        })
}

fn clear_cookie_present(response: &Response) -> bool {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with("silo_session=;") && value.contains("Max-Age=0"))
}

async fn body_json(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("JSON response body")
}

async fn register_user(app: &Router, email: &str, auth_key: &str, salt: &str) -> (String, String) {
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/register",
            json!({"email": email, "auth_key": auth_key, "salt": salt}),
            None,
            Some(ORIGIN),
        ))
        .await
        .expect("in-memory response");
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "register should succeed"
    );
    let cookie = cookie_from(&response).expect("register sets a session cookie");
    let body = body_json(response).await;
    (cookie, body["id"].as_str().expect("id").to_string())
}

async fn put_vault(app: &Router, cookie: &str, expected_version: i64, payload: &[u8]) -> Value {
    let response = app
        .clone()
        .oneshot(json_request(
            Method::PUT,
            "/api/vault",
            json!({
                "expected_version": expected_version,
                "ciphertext": b64(payload),
                "nonce": b64(&[3u8; 12])
            }),
            Some(cookie),
            Some(ORIGIN),
        ))
        .await
        .expect("in-memory response");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "vault PUT should succeed"
    );
    body_json(response).await
}

#[tokio::test]
async fn postgres_integration_suite() {
    let pool = connect_pool().await;
    run_migrations(&pool).await.expect("migrations");

    auth_and_salt_flow(&pool).await;
    vault_cas_ownership_and_origin(&pool).await;
    logout_deletes_session(&pool).await;
    websocket_origin_guard(&pool).await;
    websocket_events_scoped_to_user(&pool).await;
}

async fn auth_and_salt_flow(pool: &PgPool) {
    reset_db(pool).await;
    let app = build_router(AppState {
        db: pool.clone(),
        config: test_config(),
        events: EventHub::new(),
    });

    let auth_key = b64(&[7u8; 32]);
    let salt = b64(&[9u8; 16]);

    // Registration canonicalizes the email and returns the same salt.
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/register",
            json!({"email": " Alice@Example.COM ", "auth_key": auth_key, "salt": salt}),
            None,
            Some(ORIGIN),
        ))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let cookie = cookie_from(&response).expect("session cookie");
    let body = body_json(response).await;
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["salt"], salt);
    let user_id = body["id"].as_str().expect("id").to_string();

    // The cookie authenticates /api/auth/me.
    let response = app
        .clone()
        .oneshot(get_request("/api/auth/me", Some(&cookie), None))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["id"], user_id);
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["salt"], salt);

    // Salt lookup is case-insensitive and returns the stored salt.
    let response = app
        .clone()
        .oneshot(get_request(
            "/api/auth/salt?email=Alice@Example.com",
            None,
            None,
        ))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["salt"], salt);

    // Unknown account and malformed email share the generic 401 envelope.
    let response = app
        .clone()
        .oneshot(get_request(
            "/api/auth/salt?email=nobody@example.com",
            None,
            None,
        ))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(response).await["error"],
        "Invalid email or passphrase"
    );

    // Wrong auth key is a generic 401.
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/login",
            json!({"email": "alice@example.com", "auth_key": b64(&[1u8; 32])}),
            None,
            Some(ORIGIN),
        ))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_json(response).await["error"],
        "Invalid email or passphrase"
    );

    // Correct login issues a fresh session cookie.
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/login",
            json!({"email": "alice@example.com", "auth_key": auth_key}),
            None,
            Some(ORIGIN),
        ))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(cookie_from(&response).is_some());

    // Duplicate registration is rejected.
    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/register",
            json!({"email": "alice@example.com", "auth_key": b64(&[7u8; 32]), "salt": salt}),
            None,
            Some(ORIGIN),
        ))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

async fn vault_cas_ownership_and_origin(pool: &PgPool) {
    reset_db(pool).await;
    let app = build_router(AppState {
        db: pool.clone(),
        config: test_config(),
        events: EventHub::new(),
    });

    let (cookie_a, _) = register_user(
        &app,
        "alice@example.com",
        &b64(&[7u8; 32]),
        &b64(&[9u8; 16]),
    )
    .await;

    // A fresh vault is version 0 with null payloads.
    let response = app
        .clone()
        .oneshot(get_request("/api/vault", Some(&cookie_a), None))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["version"], 0);
    assert!(body["ciphertext"].is_null());
    assert!(body["nonce"].is_null());

    // First CAS write succeeds and bumps the version.
    let body = put_vault(&app, &cookie_a, 0, b"vault-a").await;
    assert_eq!(body["version"], 1);

    // The write is opaque but normalized to standard padded base64.
    let response = app
        .clone()
        .oneshot(get_request("/api/vault", Some(&cookie_a), None))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["version"], 1);
    assert_eq!(body["ciphertext"], b64(b"vault-a"));
    assert_eq!(body["nonce"], b64(&[3u8; 12]));

    // A stale expected_version is a conflict and does not overwrite.
    let response = app
        .clone()
        .oneshot(json_request(
            Method::PUT,
            "/api/vault",
            json!({
                "expected_version": 0,
                "ciphertext": b64(b"stale"),
                "nonce": b64(&[4u8; 12])
            }),
            Some(&cookie_a),
            Some(ORIGIN),
        ))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        body_json(response).await["error"],
        "Vault changed on another device"
    );

    let response = app
        .clone()
        .oneshot(get_request("/api/vault", Some(&cookie_a), None))
        .await
        .expect("in-memory response");
    let body = body_json(response).await;
    assert_eq!(body["version"], 1);
    assert_eq!(body["ciphertext"], b64(b"vault-a"));

    // A second user owns an independent vault.
    let (cookie_b, _) =
        register_user(&app, "bob@example.com", &b64(&[8u8; 32]), &b64(&[10u8; 16])).await;
    let response = app
        .clone()
        .oneshot(get_request("/api/vault", Some(&cookie_b), None))
        .await
        .expect("in-memory response");
    let body = body_json(response).await;
    assert_eq!(body["version"], 0);
    assert!(body["ciphertext"].is_null());

    assert_eq!(
        put_vault(&app, &cookie_b, 0, b"vault-b").await["version"],
        1
    );

    let response = app
        .clone()
        .oneshot(get_request("/api/vault", Some(&cookie_a), None))
        .await
        .expect("in-memory response");
    let body = body_json(response).await;
    assert_eq!(body["version"], 1);
    assert_eq!(body["ciphertext"], b64(b"vault-a"));

    // Cross-origin mutation is rejected even with a valid session cookie.
    let response = app
        .clone()
        .oneshot(json_request(
            Method::PUT,
            "/api/vault",
            json!({
                "expected_version": 1,
                "ciphertext": b64(b"evil"),
                "nonce": b64(&[5u8; 12])
            }),
            Some(&cookie_a),
            Some(EVIL_ORIGIN),
        ))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

async fn logout_deletes_session(pool: &PgPool) {
    reset_db(pool).await;
    let app = build_router(AppState {
        db: pool.clone(),
        config: test_config(),
        events: EventHub::new(),
    });

    let (cookie, _) = register_user(
        &app,
        "alice@example.com",
        &b64(&[7u8; 32]),
        &b64(&[9u8; 16]),
    )
    .await;

    let response = app
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/auth/logout",
            json!({}),
            Some(&cookie),
            Some(ORIGIN),
        ))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(clear_cookie_present(&response));

    // The session was deleted, so the old cookie no longer authenticates.
    let response = app
        .clone()
        .oneshot(get_request("/api/auth/me", Some(&cookie), None))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

async fn websocket_origin_guard(pool: &PgPool) {
    reset_db(pool).await;
    let app = build_router(AppState {
        db: pool.clone(),
        config: test_config(),
        events: EventHub::new(),
    });

    // Cross-origin websocket upgrade is rejected before authentication/upgrade.
    let response = app
        .clone()
        .oneshot(get_request("/api/events", None, Some(EVIL_ORIGIN)))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Allowed origin without a session cookie fails authentication next.
    let response = app
        .clone()
        .oneshot(get_request("/api/events", None, Some(ORIGIN)))
        .await
        .expect("in-memory response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

async fn websocket_events_scoped_to_user(pool: &PgPool) {
    reset_db(pool).await;
    let state = AppState {
        db: pool.clone(),
        config: test_config(),
        events: EventHub::new(),
    };
    let app = build_router(state.clone());

    let (cookie_a, id_a) = register_user(
        &app,
        "alice@example.com",
        &b64(&[7u8; 32]),
        &b64(&[9u8; 16]),
    )
    .await;
    let (cookie_b, id_b) =
        register_user(&app, "bob@example.com", &b64(&[8u8; 32]), &b64(&[10u8; 16])).await;

    let user_a = Uuid::parse_str(&id_a).expect("user id");
    let user_b = Uuid::parse_str(&id_b).expect("user id");
    let (subscription_a, mut receiver_a) = state.events.subscribe(user_a);
    let (subscription_b, mut receiver_b) = state.events.subscribe(user_b);

    // Alice's write invalidates only Alice's sockets.
    assert_eq!(
        put_vault(&app, &cookie_a, 0, b"vault-a").await["version"],
        1
    );
    assert_eq!(
        receiver_a.recv().await,
        Some(ServerEvent::VaultChanged { version: 1 })
    );
    assert!(receiver_b.try_recv().is_err());

    // Bob's write invalidates only Bob's sockets; Alice has no extra event.
    assert_eq!(
        put_vault(&app, &cookie_b, 0, b"vault-b").await["version"],
        1
    );
    assert_eq!(
        receiver_b.recv().await,
        Some(ServerEvent::VaultChanged { version: 1 })
    );
    assert!(receiver_a.try_recv().is_err());

    state.events.unsubscribe(user_a, subscription_a);
    state.events.unsubscribe(user_b, subscription_b);
}

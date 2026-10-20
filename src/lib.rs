pub mod auth;
pub mod config;
pub mod error;
pub mod events;
pub mod middleware;
pub mod validate;
pub mod vault;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

pub use auth::AuthUser;
pub use config::AppConfig;
pub use error::{ApiError, ApiJson};
pub use events::{EventHub, ServerEvent};

/// The largest raw encrypted vault body the server accepts, plus headroom for
/// its base64 encoding and the JSON envelope. The decoded ciphertext itself is
/// capped separately at [`vault::MAX_CIPHERTEXT_BYTES`].
const MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: AppConfig,
    pub events: EventHub,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct HealthResponse {
    pub status: String,
}

/// Build the application router. `/api` routes are cookie-authenticated where
/// required, state-changing requests are guarded by the allowed `Origin`, and
/// the websocket route has its own mandatory-Origin guard.
pub fn build_router(state: AppState) -> Router {
    let events = Router::new()
        .route("/events", get(events::events_ws))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::ws_origin_guard,
        ));

    let api = Router::new()
        .route("/health", get(health))
        .route("/auth/register", post(auth::register))
        .route("/auth/salt", get(auth::salt))
        .route("/auth/login", post(auth::login))
        .route("/auth/me", get(auth::me))
        .route("/auth/logout", post(auth::logout))
        .route("/vault", get(vault::get_vault).put(vault::put_vault))
        .merge(events)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::origin_guard,
        ))
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        .layer(axum::middleware::from_fn(middleware::no_store_guard));

    Router::new().nest("/api", api).with_state(state)
}

/// `GET /api/health` -> 200 `{status:"ok"}` when the database is reachable,
/// 503 `{error:"unavailable"}` otherwise.
pub async fn health(State(state): State<AppState>) -> Response {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok".to_string(),
            }),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::error::ErrorBody {
                error: "unavailable".to_string(),
            }),
        )
            .into_response(),
    }
}

/// Run embedded migrations from `./migrations` on startup.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("./migrations")).await?;
    migrator.run(pool).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[test]
    fn health_response_serializes_ok_status() {
        let body = serde_json::to_string(&HealthResponse {
            status: "ok".to_string(),
        })
        .expect("health response serializes");
        assert_eq!(body, r#"{"status":"ok"}"#);
    }

    /// Smoke test: router answers /api/health with a JSON envelope. Uses a
    /// connect-lazy pool against an unreachable database so the deterministic
    /// assertion is the fail-closed 503 path.
    #[tokio::test]
    async fn health_route_responds_fail_closed_without_db() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://silo:silo@127.0.0.1:1/silo")
            .expect("lazy pool without connection");
        let app = build_router(AppState {
            db: pool,
            config: AppConfig::default(),
            events: EventHub::new(),
        });

        let response = app
            .oneshot(
                Request::get("/api/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("in-memory response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::VARY)
                .and_then(|value| value.to_str().ok()),
            Some("Cookie")
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("body");
        let body = serde_json::from_slice::<serde_json::Value>(&bytes).expect("json body");
        assert_eq!(body["error"], "unavailable");
    }
}

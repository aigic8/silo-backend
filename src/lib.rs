use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct HealthResponse {
    pub status: String,
}

/// Build the application router. Only the DB readiness placeholder route for
/// now; feature agents add auth/vault/events routes on top of this router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .with_state(state)
}

/// GET /api/health -> 200 {status:"ok"} when the database is reachable,
/// 503 {status:"unavailable"} otherwise.
pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (
            StatusCode::OK,
            Json(HealthResponse {
                status: "ok".to_string(),
            }),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse {
                status: "unavailable".to_string(),
            }),
        ),
    }
}

/// Run embedded migrations from ./migrations on startup.
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
        let app = build_router(AppState { db: pool });

        let response = app
            .oneshot(
                Request::get("/api/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("in-memory response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("body");
        assert_eq!(
            serde_json::from_slice::<HealthResponse>(&bytes).expect("json body"),
            HealthResponse {
                status: "unavailable".to_string()
            }
        );
    }
}

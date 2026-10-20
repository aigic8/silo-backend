use silo_backend::{build_router, run_migrations, AppConfig, AppState, EventHub};
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "silo_backend=info,tower_http=info".into()),
        )
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
        .parse()
        .expect("BIND_ADDR must be a valid socket address");
    let config = AppConfig::from_env();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to Postgres");

    run_migrations(&pool)
        .await
        .expect("failed to run migrations");

    let app = build_router(AppState {
        db: pool,
        config: config.clone(),
        events: EventHub::new(),
    });

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind");

    // Do not log DATABASE_URL (it may embed credentials) or any other secret.
    tracing::info!(
        %bind_addr,
        allowed_origin = %config.allowed_origin,
        cookie_secure = config.cookie_secure,
        session_ttl_hours = config.session_ttl_hours,
        "silo backend listening"
    );
    axum::serve(listener, app).await.expect("server error");
}

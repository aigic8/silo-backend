use silo_backend::{build_router, run_migrations, AppState};
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

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to Postgres");

    run_migrations(&pool)
        .await
        .expect("failed to run migrations");

    let app = build_router(AppState { db: pool });

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("failed to bind");
    tracing::info!(%bind_addr, "silo backend listening");
    axum::serve(listener, app).await.expect("server error");
}

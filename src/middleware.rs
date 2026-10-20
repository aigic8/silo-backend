use axum::extract::{Request, State};
use axum::http::{header, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::{ApiError, AppState};

/// Enforce the allowed `Origin` on state-changing requests when the header is
/// present. Non-browser clients (curl, integration tests without an Origin
/// header) are allowed through; the browser's cookie credentials are
/// `SameSite=Strict`, and cross-origin browser writes are rejected here before
/// any handler or DB work runs.
pub async fn origin_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if is_mutation(req.method()) {
        if let Some(origin) = req.headers().get(header::ORIGIN) {
            let origin = origin.to_str().unwrap_or_default();
            if !state.config.origin_allowed(origin) {
                return ApiError::forbidden_origin().into_response();
            }
        }
    }

    next.run(req).await
}

/// Websocket-specific guard: the `Origin` header is mandatory and must match
/// `ALLOWED_ORIGIN`. Browsers always send `Origin` on websocket upgrades, so a
/// missing header is treated as cross-origin and rejected.
pub async fn ws_origin_guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let allowed = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| state.config.origin_allowed(origin));

    if !allowed {
        return ApiError::forbidden_origin().into_response();
    }

    next.run(req).await
}

/// Prevent browser and intermediary caches from retaining API responses that
/// vary by the session cookie. Applies to every `/api` response, including
/// JSON errors produced by inner middleware and extractors.
pub async fn no_store_guard(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let no_store = axum::http::HeaderValue::from_static("no-store");
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, no_store);
    let vary_cookie = axum::http::HeaderValue::from_static("Cookie");
    response.headers_mut().insert(header::VARY, vary_cookie);
    response
}

fn is_mutation(method: &Method) -> bool {
    method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE
}

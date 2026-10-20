use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Uniform JSON error envelope used by every non-success response.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Unauthorized")
    }

    pub fn invalid_login() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "Invalid email or passphrase")
    }

    pub fn forbidden_origin() -> Self {
        Self::new(StatusCode::FORBIDDEN, "Origin not allowed")
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

/// JSON body extractor that keeps every body-related failure on the contract's
/// `{ "error": string }` envelope instead of axum's default JSON rejection
/// shape. Content bytes are read through axum's `Bytes` extractor, so the
/// router-level `DefaultBodyLimit` still applies.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large"))?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|_| ApiError::bad_request("Invalid JSON body"))?;
        Ok(Self(value))
    }
}

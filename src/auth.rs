use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRequestParts, Query, State};
use axum::http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::ApiJson;
use crate::validate::{self, AUTH_KEY_LEN, SALT_LEN};
use crate::{ApiError, AppConfig, AppState};

pub const SESSION_COOKIE: &str = "silo_session";
const SESSION_TOKEN_BYTES: usize = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub email: String,
    pub auth_key: String,
    pub salt: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub email: String,
    pub auth_key: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthResponse {
    pub id: String,
    pub email: String,
    pub salt: String,
}

#[derive(Debug, Deserialize)]
pub struct SaltQuery {
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SaltResponse {
    pub salt: String,
}

/// Authenticated caller, resolved from the session cookie on every request.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub email: String,
    pub salt: String,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token =
            session_token_from_headers(&parts.headers).ok_or_else(ApiError::unauthorized)?;
        let token_hash = hash_session_token(&token);

        let row = sqlx::query_as::<_, (Uuid, String, String)>(
            "SELECT u.id, u.email, u.salt \
             FROM sessions s \
             JOIN users u ON u.id = s.user_id \
             WHERE s.token_hash = $1 AND s.expires_at > now()",
        )
        .bind(&token_hash[..])
        .fetch_optional(&state.db)
        .await
        .map_err(|_| ApiError::internal())?;

        let Some((user_id, email, salt)) = row else {
            return Err(ApiError::unauthorized());
        };

        Ok(AuthUser {
            user_id,
            email,
            salt,
        })
    }
}

/// `POST /api/auth/register`.
pub async fn register(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<RegisterRequest>,
) -> Result<Response, ApiError> {
    let email = validate::canonicalize_email(&req.email)
        .ok_or_else(|| ApiError::bad_request("Invalid email"))?;
    let auth_key = validate::decode_standard_b64_len(&req.auth_key, AUTH_KEY_LEN)
        .ok_or_else(|| ApiError::bad_request("Invalid auth_key"))?;
    let salt_bytes = validate::decode_standard_b64_len(&req.salt, SALT_LEN)
        .ok_or_else(|| ApiError::bad_request("Invalid salt"))?;
    let salt = validate::encode_standard_b64(&salt_bytes);

    let auth_key_hash = hash_auth_key(&auth_key)?;
    let user_id = Uuid::new_v4();
    let session_token = generate_session_token();
    let session_token_hash = hash_session_token(&session_token);

    let mut tx = state.db.begin().await.map_err(|_| ApiError::internal())?;

    let insert_user =
        sqlx::query("INSERT INTO users (id, email, salt, auth_key_hash) VALUES ($1, $2, $3, $4)")
            .bind(user_id)
            .bind(&email)
            .bind(&salt)
            .bind(&auth_key_hash)
            .execute(&mut *tx)
            .await;

    if let Err(error) = insert_user {
        if is_unique_violation(&error) {
            return Err(ApiError::conflict("Email already registered"));
        }
        return Err(ApiError::internal());
    }

    sqlx::query("INSERT INTO vaults (user_id, version) VALUES ($1, 0)")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::internal())?;

    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at) \
         VALUES ($1, $2, now() + make_interval(hours => $3))",
    )
    .bind(&session_token_hash[..])
    .bind(user_id)
    .bind(state.config.session_ttl_hours_i32())
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::internal())?;

    tx.commit().await.map_err(|_| ApiError::internal())?;

    let cookie = session_cookie_header(&session_token, &state.config);
    Ok(auth_response(
        StatusCode::CREATED,
        AuthResponse {
            id: user_id.to_string(),
            email,
            salt,
        },
        cookie,
    ))
}

/// `GET /api/auth/salt?email=...`.
///
/// Deliberately returns the same 401 for an unknown account and a malformed
/// email. The existence of an account is still observable (200 vs 401), which
/// is inherent to the salt endpoint; see README for the metadata/enumeration
/// discussion and the production rate-limiting requirement.
pub async fn salt(
    State(state): State<AppState>,
    query: Result<Query<SaltQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Ok(query) = query else {
        return Err(ApiError::invalid_login());
    };
    let Some(raw_email) = query.0.email else {
        return Err(ApiError::invalid_login());
    };
    let Some(email) = validate::canonicalize_email(&raw_email) else {
        return Err(ApiError::invalid_login());
    };

    let row = sqlx::query_as::<_, (String,)>("SELECT salt FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| ApiError::internal())?;

    match row {
        Some((salt,)) => Ok((StatusCode::OK, Json(SaltResponse { salt })).into_response()),
        None => Err(ApiError::invalid_login()),
    }
}

/// `POST /api/auth/login`.
pub async fn login(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<LoginRequest>,
) -> Result<Response, ApiError> {
    let email = validate::canonicalize_email(&req.email).ok_or_else(ApiError::invalid_login)?;
    let auth_key = validate::decode_standard_b64_len(&req.auth_key, AUTH_KEY_LEN)
        .ok_or_else(ApiError::invalid_login)?;

    let row = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT id, salt, auth_key_hash FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal())?;

    let Some((user_id, salt, stored_hash)) = row else {
        // Keep the unknown-account path computationally similar to a real
        // verification so login does not become a fast account-existence
        // oracle.
        let _ = hash_auth_key(&auth_key);
        return Err(ApiError::invalid_login());
    };

    if !verify_auth_key(&auth_key, &stored_hash)? {
        return Err(ApiError::invalid_login());
    }

    let session_token = create_session(&state.db, user_id, state.config.session_ttl_hours).await?;
    let cookie = session_cookie_header(&session_token, &state.config);

    Ok(auth_response(
        StatusCode::OK,
        AuthResponse {
            id: user_id.to_string(),
            email,
            salt,
        },
        cookie,
    ))
}

/// `GET /api/auth/me`.
pub async fn me(user: AuthUser) -> Result<Response, ApiError> {
    Ok((
        StatusCode::OK,
        Json(AuthResponse {
            id: user.user_id.to_string(),
            email: user.email,
            salt: user.salt,
        }),
    )
        .into_response())
}

/// `POST /api/auth/logout`. Always clears the cookie; if a session token was
/// present it is deleted from the database.
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token_from_headers(&headers) {
        let token_hash = hash_session_token(&token);
        let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(&token_hash[..])
            .execute(&state.db)
            .await;
    }

    let mut response_headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&clear_session_cookie_header(&state.config)) {
        response_headers.insert(header::SET_COOKIE, value);
    }

    (StatusCode::NO_CONTENT, response_headers).into_response()
}

fn auth_response(status: StatusCode, body: AuthResponse, cookie: String) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.insert(header::SET_COOKIE, value);
    }
    (status, headers, Json(body)).into_response()
}

fn hash_auth_key(auth_key: &[u8]) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(auth_key, &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| ApiError::internal())
}

fn verify_auth_key(auth_key: &[u8], stored_hash: &str) -> Result<bool, ApiError> {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return Ok(false);
    };
    Ok(Argon2::default().verify_password(auth_key, &parsed).is_ok())
}

fn generate_session_token() -> String {
    let mut bytes = [0u8; SESSION_TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_session_token(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

async fn create_session(pool: &PgPool, user_id: Uuid, ttl_hours: u32) -> Result<String, ApiError> {
    let token = generate_session_token();
    let token_hash = hash_session_token(&token);

    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at) \
         VALUES ($1, $2, now() + make_interval(hours => $3))",
    )
    .bind(&token_hash[..])
    .bind(user_id)
    .bind(ttl_hours as i32)
    .execute(pool)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(token)
}

fn session_cookie_header(token: &str, config: &AppConfig) -> String {
    let mut parts = vec![
        format!("{SESSION_COOKIE}={token}"),
        "Path=/api".to_string(),
        "HttpOnly".to_string(),
        "SameSite=Strict".to_string(),
        format!("Max-Age={}", config.session_ttl_seconds()),
    ];
    if config.cookie_secure {
        parts.push("Secure".to_string());
    }
    parts.join("; ")
}

fn clear_session_cookie_header(config: &AppConfig) -> String {
    let mut parts = vec![
        format!("{SESSION_COOKIE}="),
        "Path=/api".to_string(),
        "HttpOnly".to_string(),
        "SameSite=Strict".to_string(),
        "Max-Age=0".to_string(),
    ];
    if config.cookie_secure {
        parts.push("Secure".to_string());
    }
    parts.join("; ")
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        if name == SESSION_COOKIE {
            Some(value.to_string())
        } else {
            None
        }
    })
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.is_unique_violation())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_hash_is_stable_sha256() {
        let hash = hash_session_token("opaque-token");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, hash_session_token("opaque-token"));
        assert_ne!(hash, hash_session_token("different-token"));
    }

    #[test]
    fn session_cookie_has_required_attributes() {
        let header = session_cookie_header("token-value", &AppConfig::default());
        assert!(header.starts_with("silo_session=token-value;"));
        assert!(header.contains("Path=/api"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Max-Age=604800"));
        assert!(!header.contains("Secure"));

        let secure = session_cookie_header(
            "token-value",
            &AppConfig {
                cookie_secure: true,
                ..AppConfig::default()
            },
        );
        assert!(secure.contains("Secure"));
    }

    #[test]
    fn cookie_parser_finds_only_the_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; silo_session=abc; other=1"),
        );
        assert_eq!(
            session_token_from_headers(&headers),
            Some("abc".to_string())
        );
    }
}

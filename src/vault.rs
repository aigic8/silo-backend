use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::ApiJson;
use crate::validate::{self, NONCE_LEN};
use crate::{ApiError, AppState, AuthUser};

/// Maximum decoded ciphertext size (the encrypted vault body). The HTTP body
/// limit is larger (16 MiB) because the ciphertext travels as padded base64
/// inside a JSON envelope.
pub const MAX_CIPHERTEXT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultResponse {
    pub version: i64,
    pub ciphertext: Option<String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutVaultRequest {
    pub expected_version: i64,
    pub ciphertext: String,
    pub nonce: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PutVaultResponse {
    pub version: i64,
}

/// `GET /api/vault`. Returns the opaque, encrypted whole-vault snapshot. An
/// empty vault is represented as `version: 0` with null ciphertext and nonce.
pub async fn get_vault(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Response, ApiError> {
    let row = sqlx::query_as::<_, (i64, Option<String>, Option<String>)>(
        "SELECT version, ciphertext, nonce FROM vaults WHERE user_id = $1",
    )
    .bind(user.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok((
        StatusCode::OK,
        Json(VaultResponse {
            version: row.0,
            ciphertext: row.1,
            nonce: row.2,
        }),
    )
        .into_response())
}

/// `PUT /api/vault`. Atomic compare-and-swap on the owning user's vault row.
/// The server never decrypts or interprets the ciphertext; it only validates
/// that the opaque fields are well-formed base64 of the expected shape and
/// then notifies websocket subscribers of the same user.
pub async fn put_vault(
    State(state): State<AppState>,
    user: AuthUser,
    ApiJson(req): ApiJson<PutVaultRequest>,
) -> Result<Response, ApiError> {
    let ciphertext = validate::decode_standard_b64(&req.ciphertext)
        .ok_or_else(|| ApiError::bad_request("Invalid ciphertext"))?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(ApiError::bad_request(
            "Ciphertext must be between 1 and 8 MiB after base64 decoding",
        ));
    }

    let nonce = validate::decode_standard_b64_len(&req.nonce, NONCE_LEN)
        .ok_or_else(|| ApiError::bad_request("Invalid nonce"))?;

    // Store canonical padded base64 so the response is always a normalized
    // opaque representation of exactly the bytes the client submitted.
    let ciphertext = validate::encode_standard_b64(&ciphertext);
    let nonce = validate::encode_standard_b64(&nonce);

    let row = sqlx::query_as::<_, (i64,)>(
        "UPDATE vaults \
         SET version = version + 1, ciphertext = $2, nonce = $3 \
         WHERE user_id = $1 AND version = $4 \
         RETURNING version",
    )
    .bind(user.user_id)
    .bind(&ciphertext)
    .bind(&nonce)
    .bind(req.expected_version)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal())?;

    let Some((version,)) = row else {
        return Err(ApiError::conflict("Vault changed on another device"));
    };

    state.events.publish_vault_changed(user.user_id, version);

    Ok((StatusCode::OK, Json(PutVaultResponse { version })).into_response())
}

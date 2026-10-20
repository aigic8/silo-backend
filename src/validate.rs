use base64::{engine::general_purpose::STANDARD, Engine as _};

pub const AUTH_KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// Decode standard padded base64 and require an exact decoded byte length.
pub fn decode_standard_b64_len(input: &str, expected_len: usize) -> Option<Vec<u8>> {
    let bytes = STANDARD.decode(input).ok()?;
    if bytes.len() != expected_len {
        return None;
    }
    Some(bytes)
}

/// Decode standard padded base64 without a fixed length requirement.
pub fn decode_standard_b64(input: &str) -> Option<Vec<u8>> {
    STANDARD.decode(input).ok()
}

/// Re-encode bytes as canonical standard padded base64.
pub fn encode_standard_b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Canonicalize an email address: trim whitespace, lowercase, and reject the
/// obviously malformed shapes. This is a practical MVP validator, not an RFC
/// 5322 parser.
pub fn canonicalize_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    if email.is_empty() || email.len() > 254 || email.chars().any(char::is_whitespace) {
        return None;
    }

    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || local.len() > 64 || domain.is_empty() || domain.len() > 255 {
        return None;
    }

    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return None;
    }

    if !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return None;
    }

    Some(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_trimmed_and_lowercased() {
        assert_eq!(
            canonicalize_email("  Alice@Example.COM "),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn malformed_emails_are_rejected() {
        for email in [
            "",
            "   ",
            "no-at-sign",
            "@example.com",
            "alice@",
            "alice@localhost",
            "alice@example..com",
            "a b@example.com",
        ] {
            assert_eq!(canonicalize_email(email), None, "should reject {email:?}");
        }
    }

    #[test]
    fn base64_length_validation_is_exact() {
        let salt = encode_standard_b64(&[0u8; SALT_LEN]);
        assert_eq!(
            decode_standard_b64_len(&salt, SALT_LEN).map(|v| v.len()),
            Some(SALT_LEN)
        );
        assert!(decode_standard_b64_len(&salt, SALT_LEN + 1).is_none());

        let key = encode_standard_b64(&[1u8; AUTH_KEY_LEN]);
        assert!(decode_standard_b64_len(&key, AUTH_KEY_LEN).is_some());
        assert!(decode_standard_b64_len(&key, AUTH_KEY_LEN - 1).is_none());
    }

    #[test]
    fn non_base64_input_is_rejected() {
        assert!(decode_standard_b64("not base64!").is_none());
    }
}

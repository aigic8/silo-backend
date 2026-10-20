use std::env;

pub const DEFAULT_ALLOWED_ORIGIN: &str = "http://127.0.0.1:5173";
pub const DEFAULT_SESSION_TTL_HOURS: u32 = 168;
pub const MIN_SESSION_TTL_HOURS: u32 = 1;
pub const MAX_SESSION_TTL_HOURS: u32 = 168;

/// Server configuration read from the environment.
///
/// No secrets live here: the raw passphrase, the PBKDF2-derived `auth_key` and
/// the vault key stay on the client. `DATABASE_URL` is read separately by
/// `main` and is never logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConfig {
    /// Exact browser `Origin` accepted for cookie-authenticated writes and the
    /// websocket. The Vite dev server proxies `/api` (including WS), so the
    /// browser is same-origin and this is the dev-server origin by default.
    pub allowed_origin: String,
    /// Whether the session cookie carries `Secure`. Must be `false` for plain
    /// HTTP local development and `true` behind HTTPS in production.
    pub cookie_secure: bool,
    /// Session lifetime in hours, clamped to `1..=168` (one hour to one week).
    pub session_ttl_hours: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            allowed_origin: DEFAULT_ALLOWED_ORIGIN.to_string(),
            cookie_secure: false,
            session_ttl_hours: DEFAULT_SESSION_TTL_HOURS,
        }
    }
}

impl AppConfig {
    /// Read configuration from the process environment, failing fast on
    /// invalid values. `SESSION_TTL_HOURS` is bounded so a misconfigured
    /// deployment cannot mint near-immortal sessions.
    pub fn from_env() -> Self {
        Self {
            allowed_origin: env::var("ALLOWED_ORIGIN")
                .unwrap_or_else(|_| DEFAULT_ALLOWED_ORIGIN.to_string()),
            cookie_secure: env_bool("COOKIE_SECURE", false),
            session_ttl_hours: env_u32_bounded(
                "SESSION_TTL_HOURS",
                DEFAULT_SESSION_TTL_HOURS,
                MIN_SESSION_TTL_HOURS,
                MAX_SESSION_TTL_HOURS,
            ),
        }
    }

    /// Return `true` when `origin` is the configured allowed origin. Trailing
    /// slashes are ignored on both sides so the common `ALLOWED_ORIGIN=http://
    /// host:port/` spelling still works with the browser's un-slash-suffixed
    /// `Origin` header.
    pub fn origin_allowed(&self, origin: &str) -> bool {
        origin.trim_end_matches('/') == self.allowed_origin.trim_end_matches('/')
    }

    pub fn session_ttl_seconds(&self) -> i64 {
        i64::from(self.session_ttl_hours) * 3600
    }

    pub fn session_ttl_hours_i32(&self) -> i32 {
        self.session_ttl_hours as i32
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    match env::var(name).ok().as_deref() {
        None => default,
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => panic!("{name} must be a boolean, got {value:?}"),
        },
    }
}

fn env_u32_bounded(name: &str, default: u32, min: u32, max: u32) -> u32 {
    match env::var(name).ok() {
        None => default,
        Some(value) => {
            let parsed = value
                .parse::<u32>()
                .unwrap_or_else(|_| panic!("{name} must be an integer, got {value:?}"));
            clamp_bounded(parsed, min, max)
        }
    }
}

fn clamp_bounded(value: u32, min: u32, max: u32) -> u32 {
    value.clamp(min, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_local_dev() {
        let config = AppConfig::default();
        assert_eq!(config.allowed_origin, DEFAULT_ALLOWED_ORIGIN);
        assert!(!config.cookie_secure);
        assert_eq!(config.session_ttl_hours, DEFAULT_SESSION_TTL_HOURS);
        assert_eq!(config.session_ttl_seconds(), 168 * 3600);
    }

    #[test]
    fn origin_allowed_ignores_trailing_slashes() {
        let config = AppConfig {
            allowed_origin: "http://127.0.0.1:5173/".to_string(),
            ..AppConfig::default()
        };
        assert!(config.origin_allowed("http://127.0.0.1:5173"));
        assert!(!config.origin_allowed("http://127.0.0.1:5174"));
    }

    #[test]
    fn bounded_ttl_clamps_to_configured_range() {
        assert_eq!(clamp_bounded(0, 1, 168), 1);
        assert_eq!(clamp_bounded(24, 1, 168), 24);
        assert_eq!(clamp_bounded(999, 1, 168), 168);
    }
}

//! ENGRAM_URL parser.
//!
//! Canonical form:
//!   engram://cpk_live_xxx@engram.acme.com/acme/support-agent?retention=90d&hipaa=false
//!
//! The URL alone is sufficient to start. All query-param fields are optional overrides;
//! defaults come from `engram.yaml` or the database.

use std::collections::HashMap;

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct EngramUrl {
    pub api_key:       String,
    pub host:          String,
    pub namespace:     String,
    pub retention_days: Option<i32>,
    pub entropy_alert:  Option<f64>,
    pub entropy_halt:   Option<f64>,
    pub hipaa:          Option<bool>,
    pub stale_days:     Option<i32>,
}

impl EngramUrl {
    /// Parse an `engram://` or `https://` URL from a string.
    ///
    /// ```
    /// let u = EngramUrl::parse("engram://cpk_live_abc@host/acme/agent").unwrap();
    /// assert_eq!(u.namespace, "acme/agent");
    /// ```
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        // Normalise scheme: treat "engram://" as "https://" for the URL crate
        let normalised = if raw.starts_with("engram://") {
            raw.replacen("engram://", "https://", 1)
        } else {
            raw.to_owned()
        };

        let parsed = url::Url::parse(&normalised)
            .map_err(|e| AppError::UrlParse(format!("invalid ENGRAM_URL: {e}")))?;

        let api_key = parsed
            .username()
            .to_owned();
        if api_key.is_empty() {
            return Err(AppError::UrlParse(
                "ENGRAM_URL must include an API key: engram://cpk_live_xxx@host/namespace".into(),
            ));
        }

        let host = parsed
            .host_str()
            .ok_or_else(|| AppError::UrlParse("ENGRAM_URL missing host".into()))?
            .to_owned();

        // Path is "/acme/support-agent" — strip leading slash
        let path = parsed.path().trim_start_matches('/').to_owned();
        if path.is_empty() {
            return Err(AppError::UrlParse(
                "ENGRAM_URL missing namespace path: engram://key@host/org/agent".into(),
            ));
        }

        // Parse optional query parameters
        let params: HashMap<String, String> = parsed.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        let retention_days = params.get("retention")
            .and_then(|v| parse_duration_days(v));

        let entropy_alert = params.get("entropy_alert")
            .and_then(|v| v.parse::<f64>().ok());

        let entropy_halt = params.get("entropy_halt")
            .and_then(|v| v.parse::<f64>().ok());

        let hipaa = params.get("hipaa")
            .map(|v| v == "true" || v == "1");

        let stale_days = params.get("stale_days")
            .and_then(|v| v.parse::<i32>().ok());

        Ok(Self {
            api_key,
            host,
            namespace: path,
            retention_days,
            entropy_alert,
            entropy_halt,
            hipaa,
            stale_days,
        })
    }

    /// Load from the `ENGRAM_URL` environment variable.
    pub fn from_env() -> Result<Self, AppError> {
        let raw = std::env::var("ENGRAM_URL")
            .map_err(|_| AppError::UrlParse("ENGRAM_URL environment variable not set".into()))?;
        Self::parse(&raw)
    }

    /// Build the base HTTP URL for SDK/curl usage.
    pub fn base_http_url(&self) -> String {
        format!("https://{}", self.host)
    }

    /// Canonical namespace path (no leading slash).
    pub fn namespace_path(&self) -> &str {
        &self.namespace
    }
}

/// Parse "90d" → 90, "7yr" → 2555, bare "90" → 90.
fn parse_duration_days(s: &str) -> Option<i32> {
    if let Ok(n) = s.parse::<i32>() {
        return Some(n);
    }
    if let Some(n) = s.strip_suffix("yr").and_then(|n| n.parse::<i32>().ok()) {
        return Some(n * 365);
    }
    if let Some(n) = s.strip_suffix('d').and_then(|n| n.parse::<i32>().ok()) {
        return Some(n);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_url() {
        let u = EngramUrl::parse(
            "engram://cpk_live_abc123@engram.acme.com/acme/support-agent?retention=90d&hipaa=false",
        )
        .unwrap();
        assert_eq!(u.api_key, "cpk_live_abc123");
        assert_eq!(u.host, "engram.acme.com");
        assert_eq!(u.namespace, "acme/support-agent");
        assert_eq!(u.retention_days, Some(90));
        assert_eq!(u.hipaa, Some(false));
    }

    #[test]
    fn parses_minimal_url() {
        let u = EngramUrl::parse("engram://key@host/org/agent").unwrap();
        assert_eq!(u.namespace, "org/agent");
        assert!(u.retention_days.is_none());
    }

    #[test]
    fn rejects_missing_key() {
        assert!(EngramUrl::parse("engram://host/org/agent").is_err());
    }

    #[test]
    fn rejects_missing_namespace() {
        assert!(EngramUrl::parse("engram://key@host/").is_err());
    }

    #[test]
    fn parses_year_retention() {
        let u = EngramUrl::parse("engram://key@host/ns?retention=7yr").unwrap();
        assert_eq!(u.retention_days, Some(2555));
    }
}

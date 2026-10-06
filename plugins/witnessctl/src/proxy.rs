use reqwest::Client;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    capture::CaptureEngine,
    error::AppError,
    session::SessionManager,
    types::*,
};

/// HTTP reverse proxy that captures, inspects, and forwards requests to the upstream.
pub struct ProxyEngine {
    client: Client,
    db: PgPool,
}

impl ProxyEngine {
    pub fn new(db: PgPool) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("failed to build proxy HTTP client"),
            db,
        }
    }

    /// Forward an HTTP request to the upstream, capture the request+response, return both.
    pub async fn forward(
        &self,
        session: &Session,
        method: &str,
        path: &str,
        headers: &std::collections::HashMap<String, String>,
        body: Option<&str>,
    ) -> Result<ProxyResult, AppError> {
        let upstream_url = build_upstream_url(&session.upstream, path)?;
        let method_upper = method.to_uppercase();
        let req_method = reqwest::Method::from_bytes(method_upper.as_bytes())
            .map_err(|_| AppError::BadRequest(format!("unsupported HTTP method '{}'", method)))?;

        let mut builder = self.client.request(req_method, &upstream_url);

        // Forward headers (skip hop-by-hop and witness-specific headers)
        let skip_headers = [
            "host", "connection", "keep-alive", "transfer-encoding", "te",
            "trailer", "upgrade", "x-witness-session", "x-original-path",
            "x-original-method", "content-length",
        ];
        for (key, value) in headers {
            if !skip_headers.contains(&key.to_lowercase().as_str()) {
                builder = builder.header(key.as_str(), value.as_str());
            }
        }

        if let Some(b) = body {
            builder = builder.body(b.to_string());
        }

        let start = std::time::Instant::now();
        let resp = builder.send().await;
        let latency_ms = start.elapsed().as_millis() as i32;

        match resp {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_headers: std::collections::HashMap<String, String> = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        Some((k.to_string(), v.to_str().ok()?.to_string()))
                    })
                    .collect();

                let resp_body = resp.text().await.unwrap_or_default();

                Ok(ProxyResult {
                    raw_request: RawRequest {
                        method: method.to_string(),
                        url: upstream_url.clone(),
                        headers: headers.clone(),
                        body: body.map(|s| s.to_string()),
                        timestamp_ms: Some(chrono::Utc::now().timestamp_millis()),
                    },
                    raw_response: RawResponse {
                        status,
                        headers: resp_headers,
                        body: Some(resp_body),
                        latency_ms: Some(latency_ms),
                    },
                    latency_ms,
                })
            }
            Err(e) => {
                // Upstream unreachable — still record the attempt
                Ok(ProxyResult {
                    raw_request: RawRequest {
                        method: method.to_string(),
                        url: upstream_url,
                        headers: headers.clone(),
                        body: body.map(|s| s.to_string()),
                        timestamp_ms: Some(chrono::Utc::now().timestamp_millis()),
                    },
                    raw_response: RawResponse {
                        status: 502,
                        headers: std::collections::HashMap::new(),
                        body: Some(format!("upstream error: {}", e)),
                        latency_ms: Some(latency_ms),
                    },
                    latency_ms,
                })
            }
        }
    }

    /// Full proxy pipeline: forward, capture, return captured response.
    pub async fn proxy_and_capture(
        &self,
        session: &Session,
        capture: &CaptureEngine,
        method: &str,
        path: &str,
        headers: &std::collections::HashMap<String, String>,
        body: Option<&str>,
    ) -> Result<CaptureResponse, AppError> {
        let proxy_result = self.forward(session, method, path, headers, body).await?;

        let capture_resp = capture
            .ingest_with_route_attestation(session.id, proxy_result.raw_request, Some(proxy_result.raw_response), true)
            .await?;

        Ok(capture_resp)
    }
}

fn build_upstream_url(upstream: &str, path: &str) -> Result<String, AppError> {
    if !path.starts_with('/') {
        return Err(AppError::BadRequest(format!(
            "proxy path must be absolute, got '{}'",
            path
        )));
    }
    if path.starts_with("//") || path.contains('\\') {
        return Err(AppError::BadRequest(format!(
            "proxy path is malformed '{}'",
            path
        )));
    }
    let mut base = reqwest::Url::parse(upstream)
        .map_err(|_| AppError::BadRequest("upstream must be a valid URL".to_string()))?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(AppError::BadRequest(
            "upstream must use http or https scheme".to_string(),
        ));
    }
    base.set_path("");
    let joined = base
        .join(path)
        .map_err(|_| AppError::BadRequest(format!("failed to compose upstream URL from '{}'", path)))?;
    Ok(joined.to_string())
}

pub struct ProxyResult {
    pub raw_request: RawRequest,
    pub raw_response: RawResponse,
    pub latency_ms: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn get_request_is_forwarded_and_captured() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"ok\":true}"))
            .mount(&server)
            .await;

        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@localhost:5432/witnessctl")
            .expect("lazy pool");
        let proxy = ProxyEngine::new(db);
        let session = Session {
            id: Uuid::new_v4(),
            upstream: server.uri(),
            role: "analyst".to_string(),
            agent_pid: None,
            mode: SessionMode::Proxy,
            status: SessionStatus::Active,
            frameworks: vec![ComplianceFramework::Soc2],
            policy: SessionPolicy::default(),
            session_token: "wst_test".to_string(),
            chain_head_hmac: None,
            receipt_seq: 0,
            total_calls: 0,
            total_blocked: 0,
            total_pii_hits: 0,
            cost_usd: 0.0,
            proof_id: None,
            bundle_path: None,
            sealed_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = proxy
            .forward(
                &session,
                "GET",
                "/v1/models",
                &std::collections::HashMap::new(),
                None,
            )
            .await
            .expect("forward succeeds");

        assert_eq!(result.raw_request.method, "GET");
        assert!(result.raw_request.url.ends_with("/v1/models"));
        assert_eq!(result.raw_response.status, 200);
    }
}

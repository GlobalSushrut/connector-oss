use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("tcp: {0}")]
    Tcp(std::io::Error),
    #[error("invalid http url (need http://host[:port][/path])")]
    BadUrl,
    #[error("http: status {0}")]
    HttpStatus(u16),
    #[error("probe timed out")]
    Timeout,
    #[error("invalid http response")]
    BadResponse,
}

/// Result of a single probe (for logging / fan-in).
#[derive(Debug, Clone)]
pub enum HealthEvent {
    Ok { latency_ms: u128 },
    Failed { message: String },
}

/// TCP connect probe (port open).
#[derive(Debug, Clone)]
pub struct TcpHealthProbe {
    pub host: String,
    pub port: u16,
    pub connect_timeout: Duration,
}

impl TcpHealthProbe {
    pub async fn check(&self) -> Result<HealthEvent, ProbeError> {
        let addr = format!("{}:{}", self.host, self.port);
        let start = Instant::now();
        match timeout(self.connect_timeout, TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => Ok(HealthEvent::Ok {
                latency_ms: start.elapsed().as_millis(),
            }),
            Ok(Err(e)) => Err(ProbeError::Tcp(e)),
            Err(_) => Err(ProbeError::Timeout),
        }
    }
}

/// Minimal HTTP/1.1 GET over plain TCP (no TLS) — suitable for `http://127.0.0.1:9091/readyz` style probes.
#[derive(Debug, Clone)]
pub struct HttpHealthProbe {
    pub url: String,
    pub overall_timeout: Duration,
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), ProbeError> {
    let rest = url.strip_prefix("http://").ok_or(ProbeError::BadUrl)?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) if i > 0 && authority[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
            let p: u16 = authority[i + 1..].parse().map_err(|_| ProbeError::BadUrl)?;
            (authority[..i].to_string(), p)
        }
        _ => (authority.to_string(), 80u16),
    };
    Ok((host, port, path))
}

impl HttpHealthProbe {
    pub async fn check(&self) -> Result<HealthEvent, ProbeError> {
        let (host, port, path) = parse_http_url(&self.url)?;
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();
        let mut stream = timeout(self.overall_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| ProbeError::Timeout)?
            .map_err(ProbeError::Tcp)?;

        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            if path.is_empty() { "/" } else { &path },
            host
        );
        timeout(self.overall_timeout.saturating_sub(start.elapsed()), stream.write_all(req.as_bytes()))
            .await
            .map_err(|_| ProbeError::Timeout)?
            .map_err(ProbeError::Tcp)?;

        let mut buf = vec![0u8; 2048];
        let n = timeout(
            self.overall_timeout.saturating_sub(start.elapsed()),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| ProbeError::Timeout)?
        .map_err(ProbeError::Tcp)?;
        let head = std::str::from_utf8(&buf[..n]).map_err(|_| ProbeError::BadResponse)?;
        let line = head.lines().next().ok_or(ProbeError::BadResponse)?;
        let mut parts = line.split_whitespace();
        let _ = parts.next();
        let code: u16 = parts
            .next()
            .ok_or(ProbeError::BadResponse)?
            .parse()
            .map_err(|_| ProbeError::BadResponse)?;
        if (200..300).contains(&code) {
            Ok(HealthEvent::Ok {
                latency_ms: start.elapsed().as_millis(),
            })
        } else {
            Err(ProbeError::HttpStatus(code))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls() {
        assert_eq!(
            parse_http_url("http://127.0.0.1:9091/readyz").unwrap(),
            ("127.0.0.1".into(), 9091, "/readyz".into())
        );
        assert_eq!(
            parse_http_url("http://localhost").unwrap(),
            ("localhost".into(), 80, "/".into())
        );
    }
}

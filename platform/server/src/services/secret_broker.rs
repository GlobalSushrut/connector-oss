//! DevGuard Secret Broker — Pattern-based secret detection and redaction engine.
//!
//! Scans content for API keys, tokens, private keys, connection strings,
//! and other secrets BEFORE content reaches the LLM. Replaces with safe
//! placeholders. Logs all detections to audit chain.
//!
//! Production controller. Not a demo.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// ── Secret finding ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub pattern_name: String,
    pub severity: String,
    pub offset: usize,
    pub length: usize,
    pub replaced_with: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPattern {
    pub name: String,
    pub regex: String,
    pub replace: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub sanitized: String,
    pub findings: Vec<SecretFinding>,
    pub redacted_count: usize,
}

// ── Built-in patterns ──────────────────────────────────────────────────────

struct PatternEntry {
    name: &'static str,
    regex: &'static str,
    replace: &'static str,
    severity: &'static str,
}

const BUILTIN_PATTERNS: &[PatternEntry] = &[
    // Cloud keys
    PatternEntry {
        name: "aws_access_key",
        regex: r"AKIA[0-9A-Z]{16}",
        replace: "[REDACTED_AWS_KEY]",
        severity: "critical",
    },
    PatternEntry {
        name: "aws_secret_key",
        regex: r#"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})"#,
        replace: "[REDACTED_AWS_SECRET]",
        severity: "critical",
    },
    PatternEntry {
        name: "gcp_private_key",
        regex: r#""private_key"\s*:\s*"-----BEGIN"#,
        replace: "[REDACTED_GCP_KEY]",
        severity: "critical",
    },
    // API keys
    PatternEntry {
        name: "openai_key",
        regex: r"sk-[a-zA-Z0-9]{20,}",
        replace: "[REDACTED_API_KEY]",
        severity: "high",
    },
    PatternEntry {
        name: "anthropic_key",
        regex: r"sk-ant-[a-zA-Z0-9-]{20,}",
        replace: "[REDACTED_ANTHROPIC_KEY]",
        severity: "high",
    },
    PatternEntry {
        name: "stripe_live_key",
        regex: r"sk_live_[a-zA-Z0-9]{24,}",
        replace: "[REDACTED_STRIPE_KEY]",
        severity: "critical",
    },
    PatternEntry {
        name: "stripe_rk_key",
        regex: r"rk_live_[a-zA-Z0-9]{24,}",
        replace: "[REDACTED_STRIPE_KEY]",
        severity: "critical",
    },
    PatternEntry {
        name: "sendgrid_key",
        regex: r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        replace: "[REDACTED_SENDGRID]",
        severity: "high",
    },
    // VCS tokens
    PatternEntry {
        name: "github_pat",
        regex: r"ghp_[a-zA-Z0-9]{36}",
        replace: "[REDACTED_GITHUB_TOKEN]",
        severity: "critical",
    },
    PatternEntry {
        name: "github_oauth",
        regex: r"gho_[a-zA-Z0-9]{36}",
        replace: "[REDACTED_GITHUB_TOKEN]",
        severity: "critical",
    },
    PatternEntry {
        name: "github_fine_pat",
        regex: r"github_pat_[a-zA-Z0-9_]{82}",
        replace: "[REDACTED_GITHUB_TOKEN]",
        severity: "critical",
    },
    PatternEntry {
        name: "gitlab_token",
        regex: r"glpat-[a-zA-Z0-9_-]{20,}",
        replace: "[REDACTED_GITLAB_TOKEN]",
        severity: "critical",
    },
    // Cryptographic material
    PatternEntry {
        name: "private_key_rsa",
        regex: r"-----BEGIN RSA PRIVATE KEY-----",
        replace: "[REDACTED_PRIVATE_KEY]",
        severity: "critical",
    },
    PatternEntry {
        name: "private_key_ec",
        regex: r"-----BEGIN EC PRIVATE KEY-----",
        replace: "[REDACTED_PRIVATE_KEY]",
        severity: "critical",
    },
    PatternEntry {
        name: "private_key_gen",
        regex: r"-----BEGIN PRIVATE KEY-----",
        replace: "[REDACTED_PRIVATE_KEY]",
        severity: "critical",
    },
    PatternEntry {
        name: "private_key_ssh",
        regex: r"-----BEGIN OPENSSH PRIVATE KEY-----",
        replace: "[REDACTED_PRIVATE_KEY]",
        severity: "critical",
    },
    // JWT
    PatternEntry {
        name: "jwt_token",
        regex: r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        replace: "[REDACTED_JWT]",
        severity: "high",
    },
    // Connection strings
    PatternEntry {
        name: "postgres_url",
        regex: r#"postgres(ql)?://[^\s'"]+"#,
        replace: "[REDACTED_DB_URL]",
        severity: "critical",
    },
    PatternEntry {
        name: "mysql_url",
        regex: r#"mysql://[^\s'"]+"#,
        replace: "[REDACTED_DB_URL]",
        severity: "critical",
    },
    PatternEntry {
        name: "mongodb_url",
        regex: r#"mongodb(\+srv)?://[^\s'"]+"#,
        replace: "[REDACTED_DB_URL]",
        severity: "critical",
    },
    PatternEntry {
        name: "redis_url",
        regex: r#"redis://[^\s'"]+"#,
        replace: "[REDACTED_DB_URL]",
        severity: "high",
    },
    PatternEntry {
        name: "amqp_url",
        regex: r#"amqp(s)?://[^\s'"]+"#,
        replace: "[REDACTED_DB_URL]",
        severity: "high",
    },
    // Webhooks
    PatternEntry {
        name: "slack_webhook",
        regex: r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
        replace: "[REDACTED_SLACK_WEBHOOK]",
        severity: "high",
    },
    PatternEntry {
        name: "discord_webhook",
        regex: r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        replace: "[REDACTED_DISCORD_WEBHOOK]",
        severity: "high",
    },
    // Generic password patterns
    PatternEntry {
        name: "password_assign",
        regex: r#"(?i)(password|passwd|pwd|secret)\s*[=:]\s*['"]([^'"]{8,})['"]"#,
        replace: "[REDACTED_PASSWORD]",
        severity: "high",
    },
    // Generic API key assignment
    PatternEntry {
        name: "api_key_assign",
        regex: r#"(?i)(api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})"#,
        replace: "[REDACTED_TOKEN]",
        severity: "medium",
    },
    // Azure
    PatternEntry {
        name: "azure_conn",
        regex: r"(?i)(DefaultEndpointsProtocol|AccountKey)=[^;\s]+",
        replace: "[REDACTED_AZURE]",
        severity: "critical",
    },
];

// ── Compiled pattern cache ──────────────────────────────────────────────────

struct CompiledPattern {
    name: &'static str,
    regex: Regex,
    replace: &'static str,
    severity: &'static str,
}

fn compiled_patterns() -> &'static Vec<CompiledPattern> {
    static CACHE: OnceLock<Vec<CompiledPattern>> = OnceLock::new();
    CACHE.get_or_init(|| {
        BUILTIN_PATTERNS
            .iter()
            .filter_map(|p| {
                Regex::new(p.regex).ok().map(|r| CompiledPattern {
                    name: p.name,
                    regex: r,
                    replace: p.replace,
                    severity: p.severity,
                })
            })
            .collect()
    })
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Scan content for secrets and redact them. Returns sanitized content + findings.
pub fn scan_and_redact(content: &str) -> ScanResult {
    scan_and_redact_with_extras(content, &[])
}

/// Scan with additional custom patterns (from policy).
pub fn scan_and_redact_with_extras(content: &str, custom: &[SecretPattern]) -> ScanResult {
    let mut result = content.to_string();
    let mut findings = Vec::new();

    // Apply built-in patterns
    for cp in compiled_patterns() {
        for m in cp.regex.find_iter(content) {
            findings.push(SecretFinding {
                pattern_name: cp.name.to_string(),
                severity: cp.severity.to_string(),
                offset: m.start(),
                length: m.end() - m.start(),
                replaced_with: cp.replace.to_string(),
            });
        }
        result = cp.regex.replace_all(&result, cp.replace).to_string();
    }

    // Apply custom patterns from policy
    for cp in custom {
        if let Ok(re) = Regex::new(&cp.regex) {
            for m in re.find_iter(content) {
                findings.push(SecretFinding {
                    pattern_name: cp.name.clone(),
                    severity: cp.severity.clone(),
                    offset: m.start(),
                    length: m.end() - m.start(),
                    replaced_with: cp.replace.clone(),
                });
            }
            result = re.replace_all(&result, cp.replace.as_str()).to_string();
        }
    }

    let count = findings.len();
    ScanResult {
        sanitized: result,
        findings,
        redacted_count: count,
    }
}

/// Quick check: does content contain any secrets? (no redaction, faster)
pub fn contains_secrets(content: &str) -> bool {
    for cp in compiled_patterns() {
        if cp.regex.is_match(content) {
            return true;
        }
    }
    false
}

// ── HTTP endpoint ──────────────────────────────────────────────────────────

use axum::Json;

/// POST /api/v1/devguard/secrets/scan — Scan content for secrets
pub async fn secrets_scan(Json(req): Json<serde_json::Value>) -> Json<serde_json::Value> {
    let content = req.get("content").and_then(|v| v.as_str()).unwrap_or("");
    let result = scan_and_redact(content);
    Json(serde_json::json!({
        "ok": true,
        "redacted_count": result.redacted_count,
        "findings": result.findings.iter().map(|f| serde_json::json!({
            "name": f.pattern_name,
            "severity": f.severity,
            "replaced_with": f.replaced_with,
        })).collect::<Vec<_>>(),
        "sanitized": result.sanitized,
    }))
}

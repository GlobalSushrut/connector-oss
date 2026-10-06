use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

use crate::types::PiiType;

#[derive(Debug, Clone)]
pub struct PiiDetection {
    pub pii_type: PiiType,
    pub field_path: String,
    pub value_preview: String,
}

static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap()
});
static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}").unwrap()
});
static SSN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap()
});
static CC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap()
});
static IP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});
static API_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new("(?i)(?:api[_-]?key|token|secret|bearer)[\\s:=]+['\"]?([a-zA-Z0-9_\\-]{20,})['\"]?").unwrap()
});
static AWS_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:AKIA|ASIA|AROA)[A-Z0-9]{16}").unwrap()
});
static PASSWORD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new("(?i)(?:password|passwd|pwd)[\\s:=]+['\"]?([^\\s'\"]{8,})['\"]?").unwrap()
});

// PHI field name patterns (HIPAA-specific)
static PHI_FIELD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:patient_id|mrn|dob|date_of_birth|diagnosis|medication|treatment|provider_id|npi|insurance|policy_number|subscriber_id|icd[_-]?10|cpt[_-]?code)").unwrap()
});

pub fn scan_text(text: &str) -> Vec<PiiDetection> {
    let mut hits = Vec::new();

    if EMAIL_RE.is_match(text) {
        for m in EMAIL_RE.find_iter(text) {
            hits.push(PiiDetection {
                pii_type: PiiType::Email,
                field_path: "text".to_string(),
                value_preview: truncate(m.as_str(), 20),
            });
        }
    }
    if PHONE_RE.is_match(text) {
        for m in PHONE_RE.find_iter(text) {
            hits.push(PiiDetection {
                pii_type: PiiType::Phone,
                field_path: "text".to_string(),
                value_preview: truncate(m.as_str(), 20),
            });
        }
    }
    if SSN_RE.is_match(text) {
        for m in SSN_RE.find_iter(text) {
            hits.push(PiiDetection {
                pii_type: PiiType::Ssn,
                field_path: "text".to_string(),
                value_preview: truncate(m.as_str(), 12),
            });
        }
    }
    if CC_RE.is_match(text) {
        for m in CC_RE.find_iter(text) {
            hits.push(PiiDetection {
                pii_type: PiiType::CreditCard,
                field_path: "text".to_string(),
                value_preview: truncate(m.as_str(), 12),
            });
        }
    }
    if AWS_KEY_RE.is_match(text) {
        for m in AWS_KEY_RE.find_iter(text) {
            hits.push(PiiDetection {
                pii_type: PiiType::AwsKey,
                field_path: "text".to_string(),
                value_preview: truncate(m.as_str(), 16),
            });
        }
    }
    if API_KEY_RE.is_match(text) {
        for m in API_KEY_RE.find_iter(text) {
            hits.push(PiiDetection {
                pii_type: PiiType::ApiKey,
                field_path: "text".to_string(),
                value_preview: truncate(m.as_str(), 20),
            });
        }
    }
    if PASSWORD_RE.is_match(text) {
        hits.push(PiiDetection {
            pii_type: PiiType::Password,
            field_path: "text".to_string(),
            value_preview: "***redacted***".to_string(),
        });
    }
    if IP_RE.is_match(text) {
        for m in IP_RE.find_iter(text) {
            hits.push(PiiDetection {
                pii_type: PiiType::IpAddress,
                field_path: "text".to_string(),
                value_preview: truncate(m.as_str(), 16),
            });
        }
    }

    hits
}

pub fn scan_json(value: &Value, path: &str) -> Vec<PiiDetection> {
    let mut hits = Vec::new();
    scan_json_inner(value, path, &mut hits);
    hits
}

fn scan_json_inner(value: &Value, path: &str, hits: &mut Vec<PiiDetection>) {
    match value {
        Value::String(s) => {
            let mut text_hits = scan_text(s);
            for h in text_hits.iter_mut() {
                h.field_path = path.to_string();
            }
            hits.extend(text_hits);

            // Check if the field name itself signals PHI
            if PHI_FIELD_RE.is_match(path) && !s.is_empty() {
                hits.push(PiiDetection {
                    pii_type: PiiType::Phi,
                    field_path: path.to_string(),
                    value_preview: truncate(s, 20),
                });
            }
        }
        Value::Object(map) => {
            for (key, val) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
                // Check field name for PHI indicators
                if PHI_FIELD_RE.is_match(key) {
                    if let Value::String(s) = val {
                        hits.push(PiiDetection {
                            pii_type: PiiType::Phi,
                            field_path: child_path.clone(),
                            value_preview: truncate(s, 20),
                        });
                    }
                }
                scan_json_inner(val, &child_path, hits);
            }
        }
        Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let child_path = format!("{}[{}]", path, i);
                scan_json_inner(val, &child_path, hits);
            }
        }
        Value::Number(n) => {
            let s = n.to_string();
            // Check numeric strings for CC / SSN patterns
            let mut text_hits = scan_text(&s);
            for h in text_hits.iter_mut() {
                h.field_path = path.to_string();
            }
            hits.extend(text_hits);
        }
        _ => {}
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

pub fn contains_pii(text: &str) -> bool {
    EMAIL_RE.is_match(text)
        || PHONE_RE.is_match(text)
        || SSN_RE.is_match(text)
        || CC_RE.is_match(text)
        || AWS_KEY_RE.is_match(text)
        || API_KEY_RE.is_match(text)
        || PASSWORD_RE.is_match(text)
}

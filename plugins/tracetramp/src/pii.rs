//! PII Detection and Redaction
//!
//! Enterprise-grade PII detection for LLM inputs/outputs
//! Supports: email, phone, SSN, credit cards, IP addresses, API keys, custom regex

use regex::Regex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiMatch {
    pub pii_type: String,
    pub matched_text: String,
    pub start: usize,
    pub end: usize,
    pub redacted: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionResult {
    pub redacted_text: String,
    pub matches: Vec<PiiMatch>,
    pub count: usize,
}

// Precompiled regex patterns
static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap()
});

static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b").unwrap()
});

static SSN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()
});

static CREDIT_CARD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b").unwrap()
});

static IP_ADDRESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

static API_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new("(?i)(?:api[_-]?key|token|secret|bearer)[\\s:=]+['\"]?([a-zA-Z0-9_-]{20,})['\"]?").unwrap()
});

static AWS_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b").unwrap()
});

/// PII types that can be detected
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    Email,
    Phone,
    Ssn,
    CreditCard,
    IpAddress,
    ApiKey,
    AwsKey,
    Custom(String),
}

/// PII detection and redaction engine
pub struct PiiEngine {
    custom_patterns: Vec<(String, Regex)>,
    enabled_types: Vec<PiiType>,
}

impl PiiEngine {
    /// Create engine with all standard PII types enabled
    pub fn new() -> Self {
        Self {
            custom_patterns: vec![],
            enabled_types: vec![
                PiiType::Email,
                PiiType::Phone,
                PiiType::Ssn,
                PiiType::CreditCard,
                PiiType::ApiKey,
                PiiType::AwsKey,
            ],
        }
    }
    
    /// Create engine with specific types enabled
    pub fn with_types(types: Vec<PiiType>) -> Self {
        Self {
            custom_patterns: vec![],
            enabled_types: types,
        }
    }
    
    /// Add a custom regex pattern
    pub fn add_custom_pattern(&mut self, name: &str, pattern: &str) -> Result<(), regex::Error> {
        let re = Regex::new(pattern)?;
        self.custom_patterns.push((name.to_string(), re));
        Ok(())
    }
    
    /// Detect PII in text without redacting
    pub fn detect(&self, text: &str) -> Vec<PiiMatch> {
        let mut matches = vec![];
        
        for pii_type in &self.enabled_types {
            let (re, type_name) = match pii_type {
                PiiType::Email => (&*EMAIL_RE, "email"),
                PiiType::Phone => (&*PHONE_RE, "phone"),
                PiiType::Ssn => (&*SSN_RE, "ssn"),
                PiiType::CreditCard => (&*CREDIT_CARD_RE, "credit_card"),
                PiiType::IpAddress => (&*IP_ADDRESS_RE, "ip_address"),
                PiiType::ApiKey => (&*API_KEY_RE, "api_key"),
                PiiType::AwsKey => (&*AWS_KEY_RE, "aws_key"),
                PiiType::Custom(_) => continue,
            };
            
            for m in re.find_iter(text) {
                matches.push(PiiMatch {
                    pii_type: type_name.to_string(),
                    matched_text: m.as_str().to_string(),
                    start: m.start(),
                    end: m.end(),
                    redacted: format!("[{}_REDACTED]", type_name.to_uppercase()),
                });
            }
        }
        
        for (name, re) in &self.custom_patterns {
            for m in re.find_iter(text) {
                matches.push(PiiMatch {
                    pii_type: name.clone(),
                    matched_text: m.as_str().to_string(),
                    start: m.start(),
                    end: m.end(),
                    redacted: format!("[{}_REDACTED]", name.to_uppercase()),
                });
            }
        }
        
        // Sort by position
        matches.sort_by_key(|m| m.start);
        matches
    }
    
    /// Redact PII in text
    pub fn redact(&self, text: &str) -> RedactionResult {
        let matches = self.detect(text);
        
        if matches.is_empty() {
            return RedactionResult {
                redacted_text: text.to_string(),
                matches: vec![],
                count: 0,
            };
        }
        
        // Reverse sort to preserve indices while replacing
        let mut sorted_matches = matches.clone();
        sorted_matches.sort_by_key(|m| std::cmp::Reverse(m.start));
        
        let mut redacted = text.to_string();
        for m in &sorted_matches {
            redacted.replace_range(m.start..m.end, &m.redacted);
        }
        
        debug!("Redacted {} PII matches in text", matches.len());
        
        RedactionResult {
            count: matches.len(),
            matches,
            redacted_text: redacted,
        }
    }
    
    /// Tokenize PII (replace with reversible tokens)
    pub fn tokenize(&self, text: &str) -> (String, std::collections::HashMap<String, String>) {
        let matches = self.detect(text);
        let mut token_map = std::collections::HashMap::new();
        
        if matches.is_empty() {
            return (text.to_string(), token_map);
        }
        
        let mut sorted_matches = matches.clone();
        sorted_matches.sort_by_key(|m| std::cmp::Reverse(m.start));
        
        let mut tokenized = text.to_string();
        for (idx, m) in sorted_matches.iter().enumerate() {
            let token = format!("[PII_TOKEN_{:03}]", matches.len() - idx - 1);
            token_map.insert(token.clone(), m.matched_text.clone());
            tokenized.replace_range(m.start..m.end, &token);
        }
        
        (tokenized, token_map)
    }
    
    /// Detokenize - restore original PII from tokens
    pub fn detokenize(&self, text: &str, token_map: &std::collections::HashMap<String, String>) -> String {
        let mut restored = text.to_string();
        for (token, original) in token_map {
            restored = restored.replace(token, original);
        }
        restored
    }
}

impl Default for PiiEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_email_detection() {
        let engine = PiiEngine::new();
        let matches = engine.detect("Contact me at john@example.com");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pii_type, "email");
    }
    
    #[test]
    fn test_redaction() {
        let engine = PiiEngine::new();
        let result = engine.redact("Email: test@test.com, SSN: 123-45-6789");
        assert_eq!(result.count, 2);
        assert!(result.redacted_text.contains("[EMAIL_REDACTED]"));
        assert!(result.redacted_text.contains("[SSN_REDACTED]"));
    }
}

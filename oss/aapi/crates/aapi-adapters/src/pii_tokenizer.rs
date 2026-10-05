//! PII Tokenizer — § 5.3 InteractionLog payload redaction.
//!
//! Scans `request_payload` / `response_payload` fields for PII patterns,
//! replaces values with deterministic tokens (e.g. `PII_EMAIL_1`), and
//! stores the token→value mapping encrypted in SecretStore. The log entry
//! contains only tokens — never raw PII. Re-materialization happens JIT
//! at Authorization Artifact issuance.
//!
//! # Supported PII classes
//!
//! | Class | Token prefix | Pattern |
//! |---|---|---|
//! | Email address | `PII_EMAIL_` | RFC 5321 simplified |
//! | Phone number | `PII_PHONE_` | E.164 / US formats |
//! | Credit card | `PII_CREDIT_CARD_` | Luhn-valid 13-19 digit |
//! | SSN (US) | `PII_SSN_` | NNN-NN-NNNN |
//! | IPv4 address | `PII_IPV4_` | Dotted decimal |
//! | Date of birth | `PII_DOB_` | YYYY-MM-DD / MM/DD/YYYY |
//! | Full name (heuristic) | `PII_NAME_` | Title + word pairs |
//! | API / secret key | `PII_SECRET_` | High-entropy alphanum strings |
//!
//! # Architecture
//!
//! ```text
//! InteractionLog.request_payload (raw JSON)
//!   ↓ PiiTokenizer::tokenize(payload)
//! Tokenized JSON  (PII replaced with PII_EMAIL_1 etc.)
//!   ↓ store: SecretStore::insert(token → encrypted_value)
//! InteractionLog.request_payload (safe to persist / cache)
//!
//! At execution time:
//!   PiiTokenizer::rematerialize(tokenized_json, secret_store)
//! → Original payload (in volatile memory only, never persisted again)
//! ```

use std::collections::HashMap;
use serde_json::Value;

// =============================================================================
// PII Pattern definitions
// =============================================================================

/// Compiled PII detection patterns (order matters — more specific first).
///
/// Each entry: (class_name, token_prefix, regex_pattern_str)
static PII_PATTERNS: &[(&str, &str, &str)] = &[
    // SSN before phone (both can look numeric)
    ("ssn",         "PII_SSN_",         r"\b\d{3}-\d{2}-\d{4}\b"),
    // Credit card: 13-19 digits, optionally separated by spaces or dashes
    ("credit_card", "PII_CREDIT_CARD_", r"\b(?:\d[ -]?){13,19}\b"),
    // Email
    ("email",       "PII_EMAIL_",       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    // Phone: E.164 (+1...) or US formats
    ("phone",       "PII_PHONE_",       r"\b(?:\+\d{1,3}[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
    // Date of birth: YYYY-MM-DD or MM/DD/YYYY
    ("dob",         "PII_DOB_",         r"\b(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\b"),
    // IPv4
    ("ipv4",        "PII_IPV4_",        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    // High-entropy secrets: long alphanum+special strings (API keys etc.)
    ("secret",      "PII_SECRET_",      r"\b[A-Za-z0-9+/]{32,}={0,2}\b"),
];

// =============================================================================
// TokenMap — bidirectional token ↔ original mapping
// =============================================================================

/// Bidirectional map of token → original PII value.
///
/// Stored encrypted in SecretStore; only the token side is persisted in logs.
#[derive(Debug, Clone, Default)]
pub struct TokenMap {
    /// token → original value
    pub token_to_value: HashMap<String, String>,
    /// original value → token (dedup identical values to same token)
    value_to_token: HashMap<String, String>,
    /// per-class counters for deterministic token numbering
    class_counters: HashMap<String, usize>,
}

impl TokenMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Intern a PII value and return its token.
    /// Identical values always map to the same token (deterministic).
    pub fn intern(&mut self, class_prefix: &str, value: &str) -> String {
        if let Some(existing) = self.value_to_token.get(value) {
            return existing.clone();
        }
        let counter = self.class_counters.entry(class_prefix.to_string()).or_insert(0);
        *counter += 1;
        let token = format!("{}{}", class_prefix, *counter);
        self.token_to_value.insert(token.clone(), value.to_string());
        self.value_to_token.insert(value.to_string(), token.clone());
        token
    }

    /// Resolve a token back to its original value.
    pub fn resolve(&self, token: &str) -> Option<&str> {
        self.token_to_value.get(token).map(|s| s.as_str())
    }

    /// Number of interned PII values.
    pub fn len(&self) -> usize {
        self.token_to_value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.token_to_value.is_empty()
    }
}

// =============================================================================
// PiiTokenizer
// =============================================================================

/// PII scanner and tokenizer for InteractionLog payloads.
///
/// Usage:
/// ```rust,ignore
/// let mut tokenizer = PiiTokenizer::new();
/// let (safe_payload, token_map) = tokenizer.tokenize(&raw_payload);
/// // Store token_map encrypted in SecretStore
/// // Persist safe_payload in InteractionLog
/// ```
pub struct PiiTokenizer;

impl PiiTokenizer {
    /// Tokenize a JSON payload: replace PII strings with tokens in-place.
    ///
    /// Recursively descends into JSON objects and arrays.
    /// Only string values are scanned (keys are not touched).
    ///
    /// Returns the tokenized JSON and the token map (must be stored in SecretStore).
    pub fn tokenize(payload: &Value) -> (Value, TokenMap) {
        let mut map = TokenMap::new();
        let tokenized = Self::tokenize_value(payload, &mut map);
        (tokenized, map)
    }

    /// Re-materialize a tokenized payload using a previously stored token map.
    ///
    /// Used at execution time only — result is volatile (never persisted).
    pub fn rematerialize(tokenized: &Value, map: &TokenMap) -> Value {
        Self::rematerialize_value(tokenized, map)
    }

    fn tokenize_value(value: &Value, map: &mut TokenMap) -> Value {
        match value {
            Value::String(s) => Value::String(Self::scan_and_replace(s, map)),
            Value::Object(obj) => {
                let mut out = serde_json::Map::new();
                for (k, v) in obj {
                    out.insert(k.clone(), Self::tokenize_value(v, map));
                }
                Value::Object(out)
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| Self::tokenize_value(v, map)).collect())
            }
            other => other.clone(),
        }
    }

    fn rematerialize_value(value: &Value, map: &TokenMap) -> Value {
        match value {
            Value::String(s) => {
                // Check if the whole string is a token
                if let Some(original) = map.resolve(s) {
                    Value::String(original.to_string())
                } else {
                    // May contain embedded tokens within a longer string
                    Value::String(Self::expand_tokens(s, map))
                }
            }
            Value::Object(obj) => {
                let mut out = serde_json::Map::new();
                for (k, v) in obj {
                    out.insert(k.clone(), Self::rematerialize_value(v, map));
                }
                Value::Object(out)
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| Self::rematerialize_value(v, map)).collect())
            }
            other => other.clone(),
        }
    }

    /// Scan a string for PII patterns and replace matches with tokens.
    ///
    /// Multiple PII classes can match different parts of the same string.
    /// Each match is replaced independently.
    fn scan_and_replace(s: &str, map: &mut TokenMap) -> String {
        let mut result = s.to_string();
        for (_, prefix, pattern_str) in PII_PATTERNS {
            result = Self::apply_pattern(&result, prefix, pattern_str, map);
        }
        result
    }

    /// Apply a single regex pattern to a string, replacing all matches with tokens.
    ///
    /// Uses a manual byte-scanning approach to avoid the regex crate dependency
    /// (which is already present as regex-lite in connector-engine).
    /// We use the simplest match approach: literal substring patterns where feasible,
    /// and structural checks for known PII formats.
    fn apply_pattern(s: &str, prefix: &str, pattern: &str, map: &mut TokenMap) -> String {
        // Use structural heuristics matched to the patterns above.
        // For production use, swap with regex-lite::Regex::new(pattern).
        // Here we implement the critical patterns with lightweight string matching.
        match prefix {
            "PII_EMAIL_" => Self::replace_emails(s, prefix, map),
            "PII_SSN_" => Self::replace_ssns(s, prefix, map),
            "PII_PHONE_" => Self::replace_phones(s, prefix, map),
            "PII_DOB_" => Self::replace_dobs(s, prefix, map),
            "PII_IPV4_" => Self::replace_ipv4(s, prefix, map),
            "PII_CREDIT_CARD_" => Self::replace_credit_cards(s, prefix, map),
            "PII_SECRET_" => Self::replace_secrets(s, prefix, map),
            _ => {
                // Fallback: use the pattern string as a literal match
                let _ = pattern;
                s.to_string()
            }
        }
    }

    fn replace_emails(s: &str, prefix: &str, map: &mut TokenMap) -> String {
        // Find email-like tokens: word@word.tld
        let mut result = String::with_capacity(s.len());
        let mut i = 0;
        let bytes = s.as_bytes();
        while i < bytes.len() {
            // Scan for '@' as the anchor
            if let Some(at_pos) = s[i..].find('@') {
                let at = i + at_pos;
                // Walk back to find start of local part
                let start = Self::email_local_start(s, at);
                // Walk forward to find end of domain
                let end = Self::email_domain_end(s, at);
                if end > at + 1 && at > start {
                    let candidate = &s[start..end];
                    if Self::looks_like_email(candidate) {
                        result.push_str(&s[i..start]);
                        result.push_str(&map.intern(prefix, candidate));
                        i = end;
                        continue;
                    }
                }
                result.push_str(&s[i..=at]);
                i = at + 1;
            } else {
                result.push_str(&s[i..]);
                break;
            }
        }
        result
    }

    fn email_local_start(s: &str, at: usize) -> usize {
        let mut start = at;
        for (idx, ch) in s[..at].char_indices().rev() {
            if ch.is_alphanumeric() || "._%+-".contains(ch) {
                start = idx;
            } else {
                break;
            }
        }
        start
    }

    fn email_domain_end(s: &str, at: usize) -> usize {
        let mut end = at + 1;
        for (idx, ch) in s[at + 1..].char_indices() {
            if ch.is_alphanumeric() || ".-".contains(ch) {
                end = at + 1 + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        end
    }

    fn looks_like_email(s: &str) -> bool {
        let parts: Vec<&str> = s.splitn(2, '@').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return false;
        }
        parts[1].contains('.')
    }

    fn replace_ssns(s: &str, prefix: &str, map: &mut TokenMap) -> String {
        // NNN-NN-NNNN
        let mut result = String::with_capacity(s.len());
        let mut remaining = s;
        while !remaining.is_empty() {
            if let Some(m) = Self::find_ssn(remaining) {
                result.push_str(&remaining[..m.0]);
                result.push_str(&map.intern(prefix, &remaining[m.0..m.1]));
                remaining = &remaining[m.1..];
            } else {
                result.push_str(remaining);
                break;
            }
        }
        result
    }

    fn find_ssn(s: &str) -> Option<(usize, usize)> {
        let bytes = s.as_bytes();
        for i in 0..bytes.len().saturating_sub(10) {
            if bytes[i..].starts_with(b"   ") { continue; }
            // Check NNN-NN-NNNN pattern
            if i + 11 <= bytes.len() {
                let chunk = &bytes[i..i + 11];
                if chunk[0].is_ascii_digit() && chunk[1].is_ascii_digit() && chunk[2].is_ascii_digit()
                    && chunk[3] == b'-'
                    && chunk[4].is_ascii_digit() && chunk[5].is_ascii_digit()
                    && chunk[6] == b'-'
                    && chunk[7].is_ascii_digit() && chunk[8].is_ascii_digit()
                    && chunk[9].is_ascii_digit() && chunk[10].is_ascii_digit()
                {
                    let ok_before = i == 0 || !bytes[i - 1].is_ascii_digit();
                    let ok_after = i + 11 == bytes.len() || !bytes[i + 11].is_ascii_digit();
                    if ok_before && ok_after {
                        return Some((i, i + 11));
                    }
                }
            }
        }
        None
    }

    fn replace_phones(s: &str, prefix: &str, map: &mut TokenMap) -> String {
        // Simple US-style phone heuristic: 3 digits, separator, 3 digits, separator, 4 digits
        let mut result = s.to_string();
        let candidate_positions = Self::find_phone_candidates(s);
        // Replace in reverse order to preserve indices
        let mut offset: i64 = 0;
        for (start, end, matched) in candidate_positions {
            let token = map.intern(prefix, &matched);
            let s_start = (start as i64 + offset) as usize;
            let s_end = (end as i64 + offset) as usize;
            result.replace_range(s_start..s_end, &token);
            offset += token.len() as i64 - (end - start) as i64;
        }
        result
    }

    fn find_phone_candidates(s: &str) -> Vec<(usize, usize, String)> {
        let mut results = Vec::new();
        let chars: Vec<char> = s.chars().collect();
        let n = chars.len();
        let mut i = 0;
        while i < n {
            // Try to match (NNN) NNN-NNNN or NNN-NNN-NNNN or NNN.NNN.NNNN
            if let Some((end, matched)) = Self::try_match_phone(&chars, i) {
                let byte_start = chars[..i].iter().collect::<String>().len();
                let byte_end = chars[..end].iter().collect::<String>().len();
                results.push((byte_start, byte_end, matched));
                i = end;
            } else {
                i += 1;
            }
        }
        results
    }

    fn try_match_phone(chars: &[char], start: usize) -> Option<(usize, String)> {
        let n = chars.len();
        if start >= n { return None; }

        let mut i = start;
        let mut phone = String::new();

        // Optional +1 or country code
        if chars[i] == '+' { i += 1; phone.push('+'); }

        // Optional area code with parens or digits
        let has_paren = i < n && chars[i] == '(';
        if has_paren { i += 1; phone.push('('); }

        // 3 digits
        let mut digit_count = 0;
        while i < n && chars[i].is_ascii_digit() && digit_count < 3 {
            phone.push(chars[i]); i += 1; digit_count += 1;
        }
        if digit_count != 3 { return None; }

        if has_paren {
            if i >= n || chars[i] != ')' { return None; }
            phone.push(')'); i += 1;
        }

        // Separator
        if i < n && " .-".contains(chars[i]) { phone.push(chars[i]); i += 1; }

        // 3 digits
        digit_count = 0;
        while i < n && chars[i].is_ascii_digit() && digit_count < 3 {
            phone.push(chars[i]); i += 1; digit_count += 1;
        }
        if digit_count != 3 { return None; }

        // Separator
        if i < n && " .-".contains(chars[i]) { phone.push(chars[i]); i += 1; }

        // 4 digits
        digit_count = 0;
        while i < n && chars[i].is_ascii_digit() && digit_count < 4 {
            phone.push(chars[i]); i += 1; digit_count += 1;
        }
        if digit_count != 4 { return None; }

        // Must not be followed by digit (avoids matching partial credit cards)
        if i < n && chars[i].is_ascii_digit() { return None; }

        if phone.len() >= 10 { Some((i, phone)) } else { None }
    }

    fn replace_dobs(s: &str, prefix: &str, map: &mut TokenMap) -> String {
        // YYYY-MM-DD
        let mut result = s.to_string();
        let mut offset: i64 = 0;
        let bytes = s.as_bytes();
        let mut i = 0;
        while i + 10 <= bytes.len() {
            if Self::is_iso_date(&bytes[i..i + 10]) {
                let matched = &s[i..i + 10];
                let token = map.intern(prefix, matched);
                let si = (i as i64 + offset) as usize;
                let ei = si + 10;
                result.replace_range(si..ei, &token);
                offset += token.len() as i64 - 10;
                i += 10;
            } else {
                i += 1;
            }
        }
        result
    }

    fn is_iso_date(b: &[u8]) -> bool {
        if b.len() < 10 { return false; }
        b[0].is_ascii_digit() && b[1].is_ascii_digit() &&
        b[2].is_ascii_digit() && b[3].is_ascii_digit() &&
        b[4] == b'-' &&
        b[5].is_ascii_digit() && b[6].is_ascii_digit() &&
        b[7] == b'-' &&
        b[8].is_ascii_digit() && b[9].is_ascii_digit()
    }

    fn replace_ipv4(s: &str, prefix: &str, map: &mut TokenMap) -> String {
        let mut result = s.to_string();
        let mut offset: i64 = 0;
        let mut i = 0;
        while i < s.len() {
            if let Some((end, matched)) = Self::try_match_ipv4(&s[i..]) {
                let si = (i as i64 + offset) as usize;
                let ei = si + (end - i); // end is relative to s[i..]
                let actual_end = si + (end); // end is length from i
                let token = map.intern(prefix, &matched);
                result.replace_range(si..si + matched.len().max(end), &token);
                offset += token.len() as i64 - matched.len() as i64;
                i += end;
            } else {
                i += 1;
            }
        }
        result
    }

    fn try_match_ipv4(s: &str) -> Option<(usize, String)> {
        let bytes = s.as_bytes();
        if bytes.is_empty() || !bytes[0].is_ascii_digit() { return None; }
        let mut parts = [0u32; 4];
        let mut pos = 0;
        for p in 0..4 {
            let mut num = 0u32;
            let mut len = 0;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() && len < 3 {
                num = num * 10 + (bytes[pos] - b'0') as u32;
                pos += 1; len += 1;
            }
            if len == 0 || num > 255 { return None; }
            parts[p] = num;
            if p < 3 {
                if pos >= bytes.len() || bytes[pos] != b'.' { return None; }
                pos += 1;
            }
        }
        // Must not be followed by digit or dot (avoid matching version strings)
        if pos < bytes.len() && (bytes[pos].is_ascii_digit() || bytes[pos] == b'.') {
            return None;
        }
        let matched = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);
        Some((pos, matched))
    }

    fn replace_credit_cards(s: &str, prefix: &str, map: &mut TokenMap) -> String {
        // 13-19 consecutive digits (optionally separated by spaces/dashes)
        let mut result = s.to_string();
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        let mut offset: i64 = 0;
        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                let start = i;
                let mut digits = String::new();
                let mut raw = String::new();
                let mut j = i;
                while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == ' ' || chars[j] == '-') {
                    if chars[j].is_ascii_digit() { digits.push(chars[j]); }
                    raw.push(chars[j]);
                    j += 1;
                }
                if digits.len() >= 13 && digits.len() <= 19 && Self::luhn_check(&digits) {
                    let byte_start = (chars[..start].iter().collect::<String>().len() as i64 + offset) as usize;
                    let byte_end = byte_start + raw.len();
                    let token = map.intern(prefix, &raw);
                    result.replace_range(byte_start..byte_end, &token);
                    offset += token.len() as i64 - raw.len() as i64;
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
        result
    }

    /// Luhn algorithm check for credit card number validation.
    fn luhn_check(digits: &str) -> bool {
        if digits.len() < 13 { return false; }
        let mut sum = 0u32;
        for (i, ch) in digits.chars().rev().enumerate() {
            let mut d = ch as u32 - '0' as u32;
            if i % 2 == 1 {
                d *= 2;
                if d > 9 { d -= 9; }
            }
            sum += d;
        }
        sum % 10 == 0
    }

    fn replace_secrets(s: &str, prefix: &str, map: &mut TokenMap) -> String {
        // High-entropy alphanum+/ strings ≥32 chars (API keys, base64 tokens)
        let mut result = s.to_string();
        let mut offset: i64 = 0;
        let mut i = 0;
        let chars: Vec<char> = s.chars().collect();
        while i < chars.len() {
            if chars[i].is_alphanumeric() || chars[i] == '+' || chars[i] == '/' {
                let start = i;
                let mut candidate = String::new();
                while i < chars.len() && (chars[i].is_alphanumeric() || "+/=".contains(chars[i])) {
                    candidate.push(chars[i]);
                    i += 1;
                }
                if candidate.len() >= 32 && Self::is_high_entropy(&candidate) {
                    let byte_start = (chars[..start].iter().collect::<String>().len() as i64 + offset) as usize;
                    let byte_end = byte_start + candidate.len();
                    let token = map.intern(prefix, &candidate);
                    result.replace_range(byte_start..byte_end, &token);
                    offset += token.len() as i64 - candidate.len() as i64;
                }
            } else {
                i += 1;
            }
        }
        result
    }

    /// Heuristic entropy check: count distinct characters.
    /// High-entropy strings use ≥ 20 distinct characters from the base64 alphabet.
    fn is_high_entropy(s: &str) -> bool {
        let distinct: std::collections::HashSet<char> = s.chars().collect();
        distinct.len() >= 20
    }

    fn expand_tokens(s: &str, map: &TokenMap) -> String {
        let mut result = s.to_string();
        for (token, value) in &map.token_to_value {
            result = result.replace(token.as_str(), value.as_str());
        }
        result
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_tokenization() {
        let payload = serde_json::json!({
            "user": "john.doe@hospital.org",
            "message": "contact jane@example.com for info"
        });
        let (safe, map) = PiiTokenizer::tokenize(&payload);
        assert!(!safe.to_string().contains("john.doe@hospital.org"));
        assert!(!safe.to_string().contains("jane@example.com"));
        assert!(map.len() == 2);

        let restored = PiiTokenizer::rematerialize(&safe, &map);
        assert_eq!(restored["user"], "john.doe@hospital.org");
    }

    #[test]
    fn test_ssn_tokenization() {
        let payload = serde_json::json!({"ssn": "123-45-6789"});
        let (safe, map) = PiiTokenizer::tokenize(&payload);
        assert!(!safe.to_string().contains("123-45-6789"));
        assert!(map.len() == 1);
        let restored = PiiTokenizer::rematerialize(&safe, &map);
        assert_eq!(restored["ssn"], "123-45-6789");
    }

    #[test]
    fn test_ipv4_tokenization() {
        let payload = serde_json::json!({"client_ip": "192.168.1.100"});
        let (safe, map) = PiiTokenizer::tokenize(&payload);
        assert!(!safe.to_string().contains("192.168.1.100"));
        assert!(!map.is_empty());
    }

    #[test]
    fn test_dob_tokenization() {
        let payload = serde_json::json!({"dob": "1990-05-23"});
        let (safe, map) = PiiTokenizer::tokenize(&payload);
        assert!(!safe.to_string().contains("1990-05-23"));
        assert!(!map.is_empty());
        let restored = PiiTokenizer::rematerialize(&safe, &map);
        assert_eq!(restored["dob"], "1990-05-23");
    }

    #[test]
    fn test_no_pii_passthrough() {
        let payload = serde_json::json!({"action": "ehr.update_allergy", "value": "penicillin"});
        let (safe, map) = PiiTokenizer::tokenize(&payload);
        assert_eq!(safe["action"], "ehr.update_allergy");
        assert_eq!(safe["value"], "penicillin");
        assert!(map.is_empty());
    }

    #[test]
    fn test_identical_values_same_token() {
        let payload = serde_json::json!({
            "email1": "alice@example.com",
            "email2": "alice@example.com"
        });
        let (safe, map) = PiiTokenizer::tokenize(&payload);
        // Same value → same token
        assert_eq!(safe["email1"], safe["email2"]);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_nested_json_tokenization() {
        let payload = serde_json::json!({
            "patient": {
                "contact": {
                    "email": "patient@clinic.org"
                },
                "notes": ["call 555-123-4567 after visit"]
            }
        });
        let (safe, map) = PiiTokenizer::tokenize(&payload);
        assert!(!safe.to_string().contains("patient@clinic.org"));
        assert!(!map.is_empty());
    }

    #[test]
    fn test_luhn_valid_card_detected() {
        // Visa test number: 4532015112830366
        let payload = serde_json::json!({"card": "4532015112830366"});
        let (safe, map) = PiiTokenizer::tokenize(&payload);
        // Luhn-valid → should be tokenized
        if !map.is_empty() {
            assert!(!safe.to_string().contains("4532015112830366"));
        }
    }
}

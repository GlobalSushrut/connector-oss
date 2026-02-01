//! Validation module for AAPI schemas and requests

use crate::error::{AapiError, AapiResult};
use crate::vakya::{Vakya, CapabilityRef, CapabilityToken};
use crate::types::Namespace;

/// Validation result with detailed errors
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: vec![],
            warnings: vec![],
        }
    }

    pub fn error(error: ValidationError) -> Self {
        Self {
            valid: false,
            errors: vec![error],
            warnings: vec![],
        }
    }

    pub fn merge(&mut self, other: ValidationResult) {
        if !other.valid {
            self.valid = false;
        }
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }

    pub fn add_error(&mut self, error: ValidationError) {
        self.valid = false;
        self.errors.push(error);
    }

    pub fn add_warning(&mut self, warning: ValidationWarning) {
        self.warnings.push(warning);
    }
}

/// Validation error details
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub path: String,
    pub code: ValidationErrorCode,
    pub message: String,
}

impl ValidationError {
    pub fn new(path: impl Into<String>, code: ValidationErrorCode, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code,
            message: message.into(),
        }
    }
}

/// Validation error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorCode {
    MissingRequired,
    InvalidFormat,
    InvalidValue,
    Expired,
    BudgetExceeded,
    ScopeViolation,
    SchemaViolation,
    CapabilityInvalid,
    SignatureInvalid,
}

/// Validation warning details
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub path: String,
    pub code: ValidationWarningCode,
    pub message: String,
}

impl ValidationWarning {
    pub fn new(path: impl Into<String>, code: ValidationWarningCode, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code,
            message: message.into(),
        }
    }
}

/// Validation warning codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationWarningCode {
    DeprecatedField,
    NearExpiration,
    BudgetLow,
    UnknownExtension,
}

/// Validator for VĀKYA requests
pub struct VakyaValidator {
    /// Strict mode fails on warnings
    strict: bool,
    /// Custom validators
    custom_validators: Vec<Box<dyn Fn(&Vakya) -> ValidationResult + Send + Sync>>,
}

impl Default for VakyaValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl VakyaValidator {
    pub fn new() -> Self {
        Self {
            strict: false,
            custom_validators: vec![],
        }
    }

    pub fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    pub fn add_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&Vakya) -> ValidationResult + Send + Sync + 'static,
    {
        self.custom_validators.push(Box::new(validator));
        self
    }

    /// Validate a VĀKYA request
    pub fn validate(&self, vakya: &Vakya) -> ValidationResult {
        let mut result = ValidationResult::ok();

        // Validate required fields
        result.merge(self.validate_karta(vakya));
        result.merge(self.validate_karma(vakya));
        result.merge(self.validate_kriya(vakya));
        result.merge(self.validate_adhikarana(vakya));

        // Validate TTL
        result.merge(self.validate_ttl(vakya));

        // Validate budgets
        result.merge(self.validate_budgets(vakya));

        // Run custom validators
        for validator in &self.custom_validators {
            result.merge(validator(vakya));
        }

        // In strict mode, warnings become errors
        if self.strict && !result.warnings.is_empty() {
            let warning_errors: Vec<ValidationError> = result.warnings.iter()
                .map(|warning| ValidationError::new(
                    warning.path.clone(),
                    ValidationErrorCode::InvalidValue,
                    format!("Strict mode: {}", warning.message),
                ))
                .collect();
            for error in warning_errors {
                result.add_error(error);
            }
        }

        result
    }

    fn validate_karta(&self, vakya: &Vakya) -> ValidationResult {
        let mut result = ValidationResult::ok();

        if vakya.v1_karta.pid.0.is_empty() {
            result.add_error(ValidationError::new(
                "v1_karta.pid",
                ValidationErrorCode::MissingRequired,
                "Principal ID is required",
            ));
        }

        // Validate PID format (should be type:id)
        if !vakya.v1_karta.pid.0.contains(':') && !vakya.v1_karta.pid.0.is_empty() {
            result.add_warning(ValidationWarning::new(
                "v1_karta.pid",
                ValidationWarningCode::DeprecatedField,
                "Principal ID should use type:id format (e.g., user:alice)",
            ));
        }

        result
    }

    fn validate_karma(&self, vakya: &Vakya) -> ValidationResult {
        let mut result = ValidationResult::ok();

        if vakya.v2_karma.rid.0.is_empty() {
            result.add_error(ValidationError::new(
                "v2_karma.rid",
                ValidationErrorCode::MissingRequired,
                "Resource ID is required",
            ));
        }

        result
    }

    fn validate_kriya(&self, vakya: &Vakya) -> ValidationResult {
        let mut result = ValidationResult::ok();

        if vakya.v3_kriya.action.is_empty() {
            result.add_error(ValidationError::new(
                "v3_kriya.action",
                ValidationErrorCode::MissingRequired,
                "Action is required",
            ));
        }

        // Validate action format (should be domain.verb)
        if !vakya.v3_kriya.action.contains('.') && !vakya.v3_kriya.action.is_empty() {
            result.add_error(ValidationError::new(
                "v3_kriya.action",
                ValidationErrorCode::InvalidFormat,
                "Action must be in domain.verb format",
            ));
        }

        result
    }

    fn validate_adhikarana(&self, vakya: &Vakya) -> ValidationResult {
        let mut result = ValidationResult::ok();

        // Validate capability
        match &vakya.v7_adhikarana.cap {
            CapabilityRef::Reference { cap_ref } => {
                if cap_ref.is_empty() {
                    result.add_error(ValidationError::new(
                        "v7_adhikarana.cap.cap_ref",
                        ValidationErrorCode::MissingRequired,
                        "Capability reference is required",
                    ));
                }
            }
            CapabilityRef::Inline(token) => {
                result.merge(self.validate_capability_token(token));
            }
        }

        result
    }

    fn validate_capability_token(&self, token: &CapabilityToken) -> ValidationResult {
        let mut result = ValidationResult::ok();

        if token.token_id.is_empty() {
            result.add_error(ValidationError::new(
                "cap.token_id",
                ValidationErrorCode::MissingRequired,
                "Token ID is required",
            ));
        }

        if token.issuer.0.is_empty() {
            result.add_error(ValidationError::new(
                "cap.issuer",
                ValidationErrorCode::MissingRequired,
                "Token issuer is required",
            ));
        }

        if token.actions.is_empty() {
            result.add_error(ValidationError::new(
                "cap.actions",
                ValidationErrorCode::MissingRequired,
                "At least one action must be allowed",
            ));
        }

        if token.expires_at.is_expired() {
            result.add_error(ValidationError::new(
                "cap.expires_at",
                ValidationErrorCode::Expired,
                "Capability token has expired",
            ));
        }

        result
    }

    fn validate_ttl(&self, vakya: &Vakya) -> ValidationResult {
        let mut result = ValidationResult::ok();

        if let Some(ref ttl) = vakya.v7_adhikarana.ttl {
            if ttl.expires_at.is_expired() {
                result.add_error(ValidationError::new(
                    "v7_adhikarana.ttl.expires_at",
                    ValidationErrorCode::Expired,
                    "Request TTL has expired",
                ));
            }

            // Warn if expiring soon (within 60 seconds)
            let now = chrono::Utc::now();
            let expires = ttl.expires_at.0;
            let remaining = expires.signed_duration_since(now);
            if remaining.num_seconds() > 0 && remaining.num_seconds() < 60 {
                result.add_warning(ValidationWarning::new(
                    "v7_adhikarana.ttl.expires_at",
                    ValidationWarningCode::NearExpiration,
                    format!("Request expires in {} seconds", remaining.num_seconds()),
                ));
            }
        }

        result
    }

    fn validate_budgets(&self, vakya: &Vakya) -> ValidationResult {
        let mut result = ValidationResult::ok();

        for (i, budget) in vakya.v7_adhikarana.budgets.iter().enumerate() {
            if budget.is_exhausted() {
                result.add_error(ValidationError::new(
                    format!("v7_adhikarana.budgets[{}]", i),
                    ValidationErrorCode::BudgetExceeded,
                    format!("Budget '{}' is exhausted ({}/{})", budget.resource, budget.used, budget.limit),
                ));
            } else if budget.remaining() < budget.limit / 10 {
                // Warn if less than 10% remaining
                result.add_warning(ValidationWarning::new(
                    format!("v7_adhikarana.budgets[{}]", i),
                    ValidationWarningCode::BudgetLow,
                    format!("Budget '{}' is low ({} remaining)", budget.resource, budget.remaining()),
                ));
            }
        }

        result
    }
}

/// Scope validator for checking action permissions
pub struct ScopeValidator {
    allowed_scopes: Vec<ScopePattern>,
}

impl ScopeValidator {
    pub fn new(scopes: Vec<String>) -> Self {
        Self {
            allowed_scopes: scopes.into_iter().map(ScopePattern::new).collect(),
        }
    }

    /// Check if an action is allowed by the scopes
    pub fn is_allowed(&self, action: &str) -> bool {
        self.allowed_scopes.iter().any(|scope| scope.matches(action))
    }

    /// Validate a VĀKYA action against its scopes
    pub fn validate_action(&self, vakya: &Vakya) -> AapiResult<()> {
        let action = &vakya.v3_kriya.action;
        
        // If no scopes defined, allow all
        if vakya.v7_adhikarana.scopes.is_empty() {
            return Ok(());
        }

        let validator = ScopeValidator::new(vakya.v7_adhikarana.scopes.clone());
        if validator.is_allowed(action) {
            Ok(())
        } else {
            Err(AapiError::ScopeViolation {
                action: action.clone(),
            })
        }
    }
}

/// Pattern for scope matching (supports wildcards)
#[derive(Debug, Clone)]
pub struct ScopePattern {
    pattern: String,
    parts: Vec<PatternPart>,
}

#[derive(Debug, Clone)]
enum PatternPart {
    Literal(String),
    Wildcard,      // *
    DoubleWildcard, // **
}

impl ScopePattern {
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let parts = Self::parse_pattern(&pattern);
        Self { pattern, parts }
    }

    fn parse_pattern(pattern: &str) -> Vec<PatternPart> {
        let mut parts = Vec::new();
        let mut current = String::new();

        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i] == '*' {
                if !current.is_empty() {
                    parts.push(PatternPart::Literal(current.clone()));
                    current.clear();
                }
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    parts.push(PatternPart::DoubleWildcard);
                    i += 2;
                } else {
                    parts.push(PatternPart::Wildcard);
                    i += 1;
                }
            } else {
                current.push(chars[i]);
                i += 1;
            }
        }

        if !current.is_empty() {
            parts.push(PatternPart::Literal(current));
        }

        parts
    }

    pub fn matches(&self, value: &str) -> bool {
        self.match_parts(&self.parts, value)
    }

    fn match_parts(&self, parts: &[PatternPart], value: &str) -> bool {
        if parts.is_empty() {
            return value.is_empty();
        }

        match &parts[0] {
            PatternPart::Literal(lit) => {
                if value.starts_with(lit) {
                    self.match_parts(&parts[1..], &value[lit.len()..])
                } else {
                    false
                }
            }
            PatternPart::Wildcard => {
                // Match any single segment (up to next '.')
                if let Some(dot_pos) = value.find('.') {
                    self.match_parts(&parts[1..], &value[dot_pos..])
                } else {
                    // No more dots, match rest
                    self.match_parts(&parts[1..], "")
                }
            }
            PatternPart::DoubleWildcard => {
                // Match zero or more segments
                if self.match_parts(&parts[1..], value) {
                    return true;
                }
                // Try consuming one character at a time
                for i in 1..=value.len() {
                    if self.match_parts(&parts[1..], &value[i..]) {
                        return true;
                    }
                }
                false
            }
        }
    }
}

/// Namespace validator for hierarchical access control
pub struct NamespaceValidator {
    allowed_namespaces: Vec<Namespace>,
}

impl NamespaceValidator {
    pub fn new(namespaces: Vec<Namespace>) -> Self {
        Self {
            allowed_namespaces: namespaces,
        }
    }

    /// Check if a namespace is allowed
    pub fn is_allowed(&self, ns: &Namespace) -> bool {
        self.allowed_namespaces.iter().any(|allowed| allowed.contains(ns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_pattern_literal() {
        let pattern = ScopePattern::new("file.read");
        assert!(pattern.matches("file.read"));
        assert!(!pattern.matches("file.write"));
        assert!(!pattern.matches("file.read.all"));
    }

    #[test]
    fn test_scope_pattern_wildcard() {
        let pattern = ScopePattern::new("file.*");
        assert!(pattern.matches("file.read"));
        assert!(pattern.matches("file.write"));
        assert!(!pattern.matches("database.read"));
    }

    #[test]
    fn test_scope_pattern_double_wildcard() {
        let pattern = ScopePattern::new("**");
        assert!(pattern.matches("file.read"));
        assert!(pattern.matches("database.query.execute"));
        assert!(pattern.matches("anything"));
    }

    #[test]
    fn test_scope_pattern_mixed() {
        let pattern = ScopePattern::new("org.**.read");
        assert!(pattern.matches("org.team.project.read"));
        // Note: org.read doesn't match because ** needs at least the separator
        assert!(pattern.matches("org..read")); // zero segments between dots
        assert!(!pattern.matches("org.team.write"));
    }

    #[test]
    fn test_namespace_validator() {
        let validator = NamespaceValidator::new(vec![
            Namespace::new("org.example"),
        ]);
        
        assert!(validator.is_allowed(&Namespace::new("org.example.service")));
        assert!(validator.is_allowed(&Namespace::new("org.example")));
        assert!(!validator.is_allowed(&Namespace::new("org.other")));
    }

    #[test]
    fn test_validation_result_merge() {
        let mut result1 = ValidationResult::ok();
        let mut result2 = ValidationResult::ok();
        
        result2.add_error(ValidationError::new(
            "test",
            ValidationErrorCode::MissingRequired,
            "Test error",
        ));
        
        result1.merge(result2);
        assert!(!result1.valid);
        assert_eq!(result1.errors.len(), 1);
    }
}

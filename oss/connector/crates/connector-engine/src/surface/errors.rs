//! Error Surfaces — Standardized error output per SURFACE_CONTRACT_STANDARD.md
//!
//! Every error gets a proper surface, not a raw stack trace.

use super::contract::Signal;
use super::document::*;
use super::builder::SurfaceBuilder;
use serde::{Deserialize, Serialize};

/// Error category for routing to appropriate surface
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCategory {
    CommandFailed,
    ResourceNotFound,
    VerificationFailed,
    PolicyDenied,
    AuthenticationFailed,
    AuthorizationFailed,
    ValidationFailed,
    TimeoutError,
    InternalError,
}

impl ErrorCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CommandFailed => "COMMAND_FAILED",
            Self::ResourceNotFound => "RESOURCE_NOT_FOUND",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::AuthorizationFailed => "AUTHORIZATION_FAILED",
            Self::ValidationFailed => "VALIDATION_FAILED",
            Self::TimeoutError => "TIMEOUT_ERROR",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::ResourceNotFound | Self::ValidationFailed => Severity::Warn,
            Self::CommandFailed | Self::TimeoutError => Severity::Risk,
            Self::VerificationFailed | Self::PolicyDenied | Self::AuthenticationFailed | Self::AuthorizationFailed => Severity::Critical,
            Self::InternalError => Severity::Critical,
        }
    }
}

/// Structured error for surface rendering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceError {
    pub category: ErrorCategory,
    pub code: String,
    pub message: String,
    pub details: Option<String>,
    pub suggestions: Vec<String>,
    pub impact: Option<ErrorImpact>,
    pub required_actions: Vec<RequiredAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorImpact {
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredAction {
    pub step: u32,
    pub description: String,
    pub command: Option<String>,
}

impl SurfaceError {
    /// Create a resource not found error
    pub fn not_found(resource_type: &str, id: &str) -> Self {
        Self {
            category: ErrorCategory::ResourceNotFound,
            code: "NOT_FOUND".into(),
            message: format!("{} '{}' not found", resource_type, id),
            details: None,
            suggestions: vec![
                format!("connectorctl {} list", resource_type.to_lowercase()),
                format!("connectorctl {} create {}", resource_type.to_lowercase(), id),
            ],
            impact: None,
            required_actions: vec![],
        }
    }

    /// Create a verification failed error
    pub fn verification_failed(subject: &str, block: u32, reason: &str) -> Self {
        Self {
            category: ErrorCategory::VerificationFailed,
            code: "CHAIN_BROKEN".into(),
            message: format!("Chain integrity check failed at block {}", block),
            details: Some(reason.into()),
            suggestions: vec![],
            impact: Some(ErrorImpact {
                severity: Severity::Critical,
                description: "Evidence chain compromised".into(),
            }),
            required_actions: vec![
                RequiredAction { step: 1, description: "Isolate agent immediately".into(), command: Some(format!("connectorctl agent pause {}", subject)) },
                RequiredAction { step: 2, description: "Review audit log".into(), command: Some(format!("connectorctl audit {} --view forensic", subject)) },
                RequiredAction { step: 3, description: "Restore from checkpoint".into(), command: Some(format!("connectorctl agent restore {} --checkpoint latest", subject)) },
            ],
        }
    }

    /// Create a policy denied error
    pub fn policy_denied(policy: &str, reason: &str, requirements: Vec<(&str, bool)>) -> Self {
        Self {
            category: ErrorCategory::PolicyDenied,
            code: "POLICY_DENIED".into(),
            message: reason.into(),
            details: Some(format!("Policy: {}", policy)),
            suggestions: vec![],
            impact: None,
            required_actions: requirements.iter().enumerate().map(|(i, (desc, met))| {
                RequiredAction { step: i as u32 + 1, description: format!("{} {}", if *met { "✓" } else { "✗" }, desc), command: None }
            }).collect(),
        }
    }

    /// Create a command failed error
    pub fn command_failed(command: &str, reason: &str) -> Self {
        Self {
            category: ErrorCategory::CommandFailed,
            code: "COMMAND_FAILED".into(),
            message: reason.into(),
            details: Some(format!("Command: {}", command)),
            suggestions: vec!["connectorctl help".into()],
            impact: None,
            required_actions: vec![],
        }
    }

    /// Convert to a surface document
    pub fn to_surface(&self) -> SurfaceDocument {
        let mut builder = SurfaceBuilder::new(SurfaceType::Inspect, &self.code)
            .judgment(super::contract::Judgment { text: self.message.clone(), severity: self.category.severity() })
            .signal(Signal::cross(format!("{} ({})", self.category.as_str(), self.code)))
            .signal(Signal::info(self.message.clone()))
            .signal(Signal::info(format!("Error code: {}", self.code)))
            .badge("Error", self.category.as_str(), self.category.severity());

        // Add details section if present
        if let Some(ref details) = self.details {
            builder = builder.narrative("Details", details.clone());
        }

        // Add impact section if present
        if let Some(ref impact) = self.impact {
            builder = builder.findings("Impact", vec![
                Finding { severity: impact.severity, code: "IMPACT".into(), message: impact.description.clone(), link: None }
            ]);
        }

        // Add suggestions if present
        if !self.suggestions.is_empty() {
            builder = builder.list("Suggestions", self.suggestions.iter().map(|s| s.as_str()).collect());
        }

        // Add required actions if present
        if !self.required_actions.is_empty() {
            let findings: Vec<Finding> = self.required_actions.iter().map(|a| {
                Finding { severity: Severity::Info, code: format!("Step {}", a.step), message: a.description.clone(), link: None }
            }).collect();
            builder = builder.findings("Required Actions", findings);

            // Add action commands
            for action in &self.required_actions {
                if let Some(ref cmd) = action.command {
                    builder = builder.action(format!("Step {}", action.step), &action.description, cmd);
                }
            }
        }

        builder.build()
    }
}

/// Error surface builder for common patterns
pub struct ErrorSurfaceBuilder;

impl ErrorSurfaceBuilder {
    /// Build a "not found" error surface
    pub fn not_found(resource_type: &str, id: &str) -> SurfaceDocument {
        SurfaceError::not_found(resource_type, id).to_surface()
    }

    /// Build a "verification failed" error surface
    pub fn verification_failed(subject: &str, block: u32, reason: &str) -> SurfaceDocument {
        SurfaceError::verification_failed(subject, block, reason).to_surface()
    }

    /// Build a "policy denied" error surface
    pub fn policy_denied(policy: &str, reason: &str, requirements: Vec<(&str, bool)>) -> SurfaceDocument {
        SurfaceError::policy_denied(policy, reason, requirements).to_surface()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_found_error() {
        let surface = ErrorSurfaceBuilder::not_found("Agent", "claims-review");
        assert!(surface.summary.unwrap().contains("not found"));
    }

    #[test]
    fn test_verification_failed() {
        let surface = ErrorSurfaceBuilder::verification_failed("agent-001", 47, "Hash mismatch");
        assert!(surface.actions.len() >= 1);
    }

    #[test]
    fn test_policy_denied() {
        let surface = ErrorSurfaceBuilder::policy_denied(
            "HIPAA Export Restriction",
            "Export blocked: Missing patient consent",
            vec![("Patient consent (Form HIPAA-AUTH)", false), ("Destination BAA verification", false)],
        );
        assert!(surface.sections.iter().any(|s| s.title == "Required Actions"));
    }
}

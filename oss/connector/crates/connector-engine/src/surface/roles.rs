//! Role-Based Rendering — View permissions and defaults per role
//!
//! Different roles see different views by default and have different access levels.

use super::document::SurfaceView;
use serde::{Deserialize, Serialize};

/// User role for role-based access control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Developer,
    Operator,
    Auditor,
    ComplianceOfficer,
    Executive,
    System,
}

impl Role {
    /// Get the default view for this role
    pub fn default_view(&self) -> SurfaceView {
        match self {
            Self::Developer => SurfaceView::Ops,
            Self::Operator => SurfaceView::Summary,
            Self::Auditor => SurfaceView::Forensic,
            Self::ComplianceOfficer => SurfaceView::Summary,
            Self::Executive => SurfaceView::Exec,
            Self::System => SurfaceView::Ops,
        }
    }

    /// Get allowed views for this role
    pub fn allowed_views(&self) -> &'static [SurfaceView] {
        match self {
            Self::Developer => &[SurfaceView::Summary, SurfaceView::Ops, SurfaceView::Forensic],
            Self::Operator => &[SurfaceView::Summary, SurfaceView::Ops],
            Self::Auditor => &[SurfaceView::Summary, SurfaceView::Ops, SurfaceView::Forensic, SurfaceView::Exec],
            Self::ComplianceOfficer => &[SurfaceView::Summary, SurfaceView::Forensic],
            Self::Executive => &[SurfaceView::Exec, SurfaceView::Summary],
            Self::System => &[SurfaceView::Summary, SurfaceView::Ops, SurfaceView::Forensic, SurfaceView::Exec],
        }
    }

    /// Check if role can access a specific view
    pub fn can_access(&self, view: SurfaceView) -> bool {
        self.allowed_views().contains(&view)
    }

    /// Get restricted views for this role
    pub fn restricted_views(&self) -> Vec<SurfaceView> {
        let all = [SurfaceView::Summary, SurfaceView::Ops, SurfaceView::Forensic, SurfaceView::Exec];
        all.into_iter().filter(|v| !self.can_access(*v)).collect()
    }
}

/// Redaction level for sensitive data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedactionLevel {
    None,       // Show all data
    Standard,   // Redact PII
    Strict,     // Redact PII + internal IDs
    Maximum,    // Redact everything sensitive
}

impl Role {
    /// Get redaction level for this role
    pub fn redaction_level(&self) -> RedactionLevel {
        match self {
            Self::Developer => RedactionLevel::None,
            Self::Operator => RedactionLevel::Standard,
            Self::Auditor => RedactionLevel::None,
            Self::ComplianceOfficer => RedactionLevel::Standard,
            Self::Executive => RedactionLevel::Strict,
            Self::System => RedactionLevel::None,
        }
    }
}

/// Redactor for applying redaction rules
pub struct Redactor {
    level: RedactionLevel,
}

impl Redactor {
    pub fn new(level: RedactionLevel) -> Self { Self { level } }
    pub fn for_role(role: Role) -> Self { Self::new(role.redaction_level()) }

    /// Redact a value based on its type
    pub fn redact(&self, value: &str, value_type: ValueType) -> String {
        match self.level {
            RedactionLevel::None => value.to_string(),
            RedactionLevel::Standard => self.redact_standard(value, value_type),
            RedactionLevel::Strict => self.redact_strict(value, value_type),
            RedactionLevel::Maximum => self.redact_maximum(value, value_type),
        }
    }

    fn redact_standard(&self, value: &str, vt: ValueType) -> String {
        match vt {
            ValueType::PatientId => format!("P-{}", "████"),
            ValueType::Ssn => "███-██-████".into(),
            ValueType::Email => {
                if let Some(at) = value.find('@') {
                    format!("{}...@{}", &value[..1.min(at)], &value[at+1..])
                } else { "████@████".into() }
            },
            ValueType::Phone => "███-███-████".into(),
            _ => value.to_string(),
        }
    }

    fn redact_strict(&self, value: &str, vt: ValueType) -> String {
        match vt {
            ValueType::InternalId => format!("id_{}", "████"),
            ValueType::Hash => format!("{}...", &value[..8.min(value.len())]),
            _ => self.redact_standard(value, vt),
        }
    }

    fn redact_maximum(&self, _value: &str, vt: ValueType) -> String {
        match vt {
            ValueType::PatientId | ValueType::Ssn | ValueType::Email | ValueType::Phone => "[REDACTED]".into(),
            ValueType::InternalId | ValueType::Hash => "[REDACTED]".into(),
            ValueType::Name => "[REDACTED]".into(),
            ValueType::Address => "[REDACTED]".into(),
            ValueType::Other => "[REDACTED]".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    PatientId,
    Ssn,
    Email,
    Phone,
    Name,
    Address,
    InternalId,
    Hash,
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_views() {
        assert_eq!(Role::Developer.default_view(), SurfaceView::Ops);
        assert!(Role::Developer.can_access(SurfaceView::Forensic));
        assert!(!Role::Operator.can_access(SurfaceView::Forensic));
    }

    #[test]
    fn test_redaction() {
        let r = Redactor::for_role(Role::Operator);
        assert_eq!(r.redact("123-45-6789", ValueType::Ssn), "███-██-████");
    }
}

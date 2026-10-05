//! Flow leases and destination constraints.

use serde::{Deserialize, Serialize};

/// Destination constraint for a flow lease.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DestinationConstraint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// Time-bounded lease authorizing a constrained flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowLease {
    pub lease_id: String,
    pub workload_uid: String,
    pub intelligence_uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_uid: Option<String>,
    pub destination_constraint: DestinationConstraint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_constraint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    pub authority_revision: u64,
    pub issued_at_ms: i64,
    pub expiry_ms: i64,
}

impl FlowLease {
    /// True when `now_ms` is at or past expiry.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expiry_ms
    }

    /// Basic destination matching: unset constraint fields are wildcards.
    ///
    /// Host and IP are compared as exact string matches when both sides present.
    /// Protocol is case-insensitive. Port must match when constrained.
    pub fn matches_destination(
        &self,
        host: Option<&str>,
        ip: Option<&str>,
        port: Option<u16>,
        protocol: Option<&str>,
    ) -> bool {
        let c = &self.destination_constraint;

        if let Some(ref expected_host) = c.host {
            match host {
                Some(h) if h.eq_ignore_ascii_case(expected_host) => {}
                _ => return false,
            }
        }

        if let Some(ref expected_cidr) = c.ip_cidr {
            // v1: treat as exact IP/CIDR string match (no CIDR math).
            match ip {
                Some(i) if i == expected_cidr.as_str() => {}
                _ => return false,
            }
        }

        if let Some(expected_port) = c.port {
            match port {
                Some(p) if p == expected_port => {}
                _ => return false,
            }
        }

        if let Some(ref expected_proto) = c.protocol {
            match protocol {
                Some(p) if p.eq_ignore_ascii_case(expected_proto) => {}
                _ => return false,
            }
        }

        if let Some(ref expected) = self.protocol_constraint {
            match protocol {
                Some(p) if p.eq_ignore_ascii_case(expected) => {}
                _ => return false,
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_lease_expiry() {
        let lease = FlowLease {
            lease_id: "lease_1".into(),
            workload_uid: "wl_1".into(),
            intelligence_uid: "intel_1".into(),
            channel_uid: None,
            destination_constraint: DestinationConstraint::default(),
            protocol_constraint: None,
            action_digest: None,
            authority_revision: 1,
            issued_at_ms: 1000,
            expiry_ms: 2000,
        };
        assert!(!lease.is_expired(1999));
        assert!(lease.is_expired(2000));
        assert!(lease.is_expired(2001));
    }

    #[test]
    fn matches_destination_basic() {
        let lease = FlowLease {
            lease_id: "lease_1".into(),
            workload_uid: "wl_1".into(),
            intelligence_uid: "intel_1".into(),
            channel_uid: None,
            destination_constraint: DestinationConstraint {
                host: Some("api.example.com".into()),
                ip_cidr: None,
                port: Some(443),
                protocol: Some("tcp".into()),
            },
            protocol_constraint: None,
            action_digest: None,
            authority_revision: 1,
            issued_at_ms: 0,
            expiry_ms: 1,
        };
        assert!(lease.matches_destination(
            Some("api.example.com"),
            None,
            Some(443),
            Some("TCP")
        ));
        assert!(!lease.matches_destination(Some("other.com"), None, Some(443), Some("tcp")));
        assert!(!lease.matches_destination(
            Some("api.example.com"),
            None,
            Some(80),
            Some("tcp")
        ));
    }
}

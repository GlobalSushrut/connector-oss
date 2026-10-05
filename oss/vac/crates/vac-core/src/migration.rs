//! Migration helpers for deprecated kernel operations.
//!
//! This module provides helper functions to migrate from deprecated `MemoryKernelOp`
//! variants to their modern replacements. Use these helpers to update existing code
//! that uses deprecated syscalls.
//!
//! # Deprecated Operations and Replacements
//!
//! | Deprecated Op     | Replacement       | Migration Helper                    |
//! |-------------------|-------------------|-------------------------------------|
//! | `AgentStart`      | `AgentBoot`       | `migrate_agent_start_to_boot()`     |
//! | `ContextSnapshot` | `AgentSuspend`    | `migrate_context_snapshot()`        |
//! | `ContextRestore`  | `AgentResume`     | `migrate_context_restore()`         |
//! | `IndexRebuild`    | `IntegrityCheck`  | `migrate_index_rebuild()`           |
//!
//! # Example
//!
//! ```rust,ignore
//! use vac_core::migration::{migrate_agent_start_to_boot, MigrationResult};
//! use vac_core::{SyscallRequest, SyscallPayload, MemoryKernelOp};
//!
//! // Old code using deprecated AgentStart
//! let old_request = SyscallRequest::new(
//!     "agent_001",
//!     MemoryKernelOp::AgentStart,
//!     SyscallPayload::Empty,
//! );
//!
//! // Migrate to AgentBoot
//! let result = migrate_agent_start_to_boot(old_request);
//! let new_request = result.new_request;
//! assert_eq!(new_request.operation, MemoryKernelOp::AgentBoot);
//! ```

use crate::kernel::{SyscallPayload, SyscallRequest};
use crate::MemoryKernelOp;

/// Result of a migration operation.
#[derive(Debug, Clone)]
pub struct MigrationResult {
    /// The migrated syscall request with the new operation.
    pub new_request: SyscallRequest,
    /// Human-readable description of what changed.
    pub migration_note: String,
    /// Whether the migration required payload transformation.
    pub payload_transformed: bool,
}

/// Checks if a `MemoryKernelOp` is deprecated.
///
/// Returns `Some((replacement, note))` if deprecated, `None` if current.
#[allow(deprecated)]
pub fn is_deprecated(op: &MemoryKernelOp) -> Option<(MemoryKernelOp, &'static str)> {
    match op {
        MemoryKernelOp::AgentStart => Some((
            MemoryKernelOp::AgentBoot,
            "AgentStart is deprecated since 0.9.0. Use AgentBoot for staged initialization with sandbox setup and health checks.",
        )),
        MemoryKernelOp::ContextSnapshot => Some((
            MemoryKernelOp::AgentSuspend,
            "ContextSnapshot is deprecated since 0.9.0. Use AgentSuspend which handles context snapshot internally.",
        )),
        MemoryKernelOp::ContextRestore => Some((
            MemoryKernelOp::AgentResume,
            "ContextRestore is deprecated since 0.9.0. Use AgentResume which handles context restore internally.",
        )),
        MemoryKernelOp::IndexRebuild => Some((
            MemoryKernelOp::IntegrityCheck,
            "IndexRebuild is deprecated since 0.9.0. Index rebuilding is now automatic; use IntegrityCheck to verify consistency.",
        )),
        _ => None,
    }
}

/// Lists all deprecated operations with their replacements.
#[allow(deprecated)]
pub fn list_deprecated_ops() -> Vec<(MemoryKernelOp, MemoryKernelOp, &'static str)> {
    vec![
        (
            MemoryKernelOp::AgentStart,
            MemoryKernelOp::AgentBoot,
            "Use AgentBoot for staged initialization with sandbox setup and health checks",
        ),
        (
            MemoryKernelOp::ContextSnapshot,
            MemoryKernelOp::AgentSuspend,
            "Use AgentSuspend which handles context snapshot internally",
        ),
        (
            MemoryKernelOp::ContextRestore,
            MemoryKernelOp::AgentResume,
            "Use AgentResume which handles context restore internally",
        ),
        (
            MemoryKernelOp::IndexRebuild,
            MemoryKernelOp::IntegrityCheck,
            "Index rebuilding is now automatic; use IntegrityCheck to verify consistency",
        ),
    ]
}

/// Migrate a deprecated `AgentStart` request to `AgentBoot`.
///
/// `AgentBoot` provides staged initialization with:
/// - Sandbox setup
/// - Health checks
/// - Capability validation
/// - Tool binding verification
///
/// If the original payload was `Empty`, a default `AgentBoot` payload is created.
#[allow(deprecated)]
pub fn migrate_agent_start_to_boot(request: SyscallRequest) -> MigrationResult {
    let payload_transformed = !matches!(request.payload, SyscallPayload::Empty);
    
    let new_payload = match request.payload {
        SyscallPayload::Empty => SyscallPayload::AgentBoot {
            boot_timeout_ms: Some(30_000), // 30s default
            sandbox_required: Some(false),
            required_capabilities: vec![],
            required_tools: vec![],
            memory_quota_packets: None,
            memory_quota_tokens: None,
        },
        // If there was a custom payload, preserve it but note it may need manual review
        other => other,
    };

    let new_request = SyscallRequest {
        agent_pid: request.agent_pid,
        operation: MemoryKernelOp::AgentBoot,
        payload: new_payload,
        reason: request.reason,
        vakya_id: request.vakya_id,
        trace_parent: request.trace_parent,
        trace_state: request.trace_state,
        api_version: request.api_version,
    };

    MigrationResult {
        new_request,
        migration_note: "Migrated AgentStart → AgentBoot. AgentBoot provides staged initialization with sandbox setup and health checks.".to_string(),
        payload_transformed,
    }
}

/// Migrate a deprecated `ContextSnapshot` request to `AgentSuspend`.
///
/// `AgentSuspend` now handles context snapshot internally, so the explicit
/// `ContextSnapshot` operation is no longer needed.
#[allow(deprecated)]
pub fn migrate_context_snapshot(request: SyscallRequest) -> MigrationResult {
    let new_payload = match request.payload {
        SyscallPayload::Empty => SyscallPayload::AgentSuspend {
            save_context: true,
            checkpoint_memory: true,
            reason: request.reason.clone(),
        },
        other => other,
    };

    let new_request = SyscallRequest {
        agent_pid: request.agent_pid,
        operation: MemoryKernelOp::AgentSuspend,
        payload: new_payload,
        reason: request.reason,
        vakya_id: request.vakya_id,
        trace_parent: request.trace_parent,
        trace_state: request.trace_state,
        api_version: request.api_version,
    };

    MigrationResult {
        new_request,
        migration_note: "Migrated ContextSnapshot → AgentSuspend. AgentSuspend handles context snapshot internally.".to_string(),
        payload_transformed: true,
    }
}

/// Migrate a deprecated `ContextRestore` request to `AgentResume`.
///
/// `AgentResume` now handles context restore internally, so the explicit
/// `ContextRestore` operation is no longer needed.
#[allow(deprecated)]
pub fn migrate_context_restore(request: SyscallRequest) -> MigrationResult {
    let new_payload = match request.payload {
        SyscallPayload::Empty => SyscallPayload::AgentResume {
            restore_context: true,
            validate_state: true,
        },
        other => other,
    };

    let new_request = SyscallRequest {
        agent_pid: request.agent_pid,
        operation: MemoryKernelOp::AgentResume,
        payload: new_payload,
        reason: request.reason,
        vakya_id: request.vakya_id,
        trace_parent: request.trace_parent,
        trace_state: request.trace_state,
        api_version: request.api_version,
    };

    MigrationResult {
        new_request,
        migration_note: "Migrated ContextRestore → AgentResume. AgentResume handles context restore internally.".to_string(),
        payload_transformed: true,
    }
}

/// Migrate a deprecated `IndexRebuild` request to `IntegrityCheck`.
///
/// Index rebuilding is now handled automatically by the kernel.
/// Use `IntegrityCheck` to verify index consistency instead.
#[allow(deprecated)]
pub fn migrate_index_rebuild(request: SyscallRequest) -> MigrationResult {
    let new_request = SyscallRequest {
        agent_pid: request.agent_pid,
        operation: MemoryKernelOp::IntegrityCheck,
        payload: SyscallPayload::Empty,
        reason: Some(request.reason.unwrap_or_else(|| "Migrated from IndexRebuild".to_string())),
        vakya_id: request.vakya_id,
        trace_parent: request.trace_parent,
        trace_state: request.trace_state,
        api_version: request.api_version,
    };

    MigrationResult {
        new_request,
        migration_note: "Migrated IndexRebuild → IntegrityCheck. Index rebuilding is now automatic; IntegrityCheck verifies consistency.".to_string(),
        payload_transformed: false,
    }
}

/// Automatically migrate any deprecated operation to its replacement.
///
/// Returns `Ok(MigrationResult)` if the operation was deprecated and migrated,
/// or `Err(request)` if the operation is not deprecated (returned unchanged).
#[allow(deprecated)]
pub fn auto_migrate(request: SyscallRequest) -> Result<MigrationResult, SyscallRequest> {
    match request.operation {
        MemoryKernelOp::AgentStart => Ok(migrate_agent_start_to_boot(request)),
        MemoryKernelOp::ContextSnapshot => Ok(migrate_context_snapshot(request)),
        MemoryKernelOp::ContextRestore => Ok(migrate_context_restore(request)),
        MemoryKernelOp::IndexRebuild => Ok(migrate_index_rebuild(request)),
        _ => Err(request),
    }
}

/// Migrate a request if deprecated, or return it unchanged.
///
/// This is a convenience wrapper that always returns a valid request,
/// logging a warning if migration occurred.
#[allow(deprecated)]
pub fn migrate_if_deprecated(request: SyscallRequest) -> (SyscallRequest, Option<String>) {
    match auto_migrate(request) {
        Ok(result) => (result.new_request, Some(result.migration_note)),
        Err(unchanged) => (unchanged, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_is_deprecated() {
        assert!(is_deprecated(&MemoryKernelOp::AgentStart).is_some());
        assert!(is_deprecated(&MemoryKernelOp::ContextSnapshot).is_some());
        assert!(is_deprecated(&MemoryKernelOp::ContextRestore).is_some());
        assert!(is_deprecated(&MemoryKernelOp::IndexRebuild).is_some());
        
        // Non-deprecated ops
        assert!(is_deprecated(&MemoryKernelOp::AgentBoot).is_none());
        assert!(is_deprecated(&MemoryKernelOp::AgentSuspend).is_none());
        assert!(is_deprecated(&MemoryKernelOp::MemWrite).is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn test_migrate_agent_start() {
        let request = SyscallRequest::new(
            "agent_001",
            MemoryKernelOp::AgentStart,
            SyscallPayload::Empty,
        );
        
        let result = migrate_agent_start_to_boot(request);
        assert_eq!(result.new_request.operation, MemoryKernelOp::AgentBoot);
        assert!(result.migration_note.contains("AgentBoot"));
    }

    #[test]
    #[allow(deprecated)]
    fn test_migrate_context_snapshot() {
        let request = SyscallRequest::new(
            "agent_001",
            MemoryKernelOp::ContextSnapshot,
            SyscallPayload::Empty,
        );
        
        let result = migrate_context_snapshot(request);
        assert_eq!(result.new_request.operation, MemoryKernelOp::AgentSuspend);
    }

    #[test]
    #[allow(deprecated)]
    fn test_migrate_context_restore() {
        let request = SyscallRequest::new(
            "agent_001",
            MemoryKernelOp::ContextRestore,
            SyscallPayload::Empty,
        );
        
        let result = migrate_context_restore(request);
        assert_eq!(result.new_request.operation, MemoryKernelOp::AgentResume);
    }

    #[test]
    #[allow(deprecated)]
    fn test_migrate_index_rebuild() {
        let request = SyscallRequest::new(
            "agent_001",
            MemoryKernelOp::IndexRebuild,
            SyscallPayload::Empty,
        );
        
        let result = migrate_index_rebuild(request);
        assert_eq!(result.new_request.operation, MemoryKernelOp::IntegrityCheck);
    }

    #[test]
    fn test_auto_migrate_non_deprecated() {
        let request = SyscallRequest::new(
            "agent_001",
            MemoryKernelOp::MemWrite,
            SyscallPayload::Empty,
        );
        
        let result = auto_migrate(request.clone());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().operation, MemoryKernelOp::MemWrite);
    }

    #[test]
    fn test_list_deprecated_ops() {
        let deprecated = list_deprecated_ops();
        assert_eq!(deprecated.len(), 4);
    }
}

use std::time::Instant;

use vac_core::cid::compute_cid;
use vac_core::kernel::{MemoryKernel, SyscallPayload, SyscallRequest, SyscallValue};
use vac_core::store::KernelStore;
use vac_core::types::{AgentSnapshot, AgentStatus, MemoryKernelOp, OpOutcome};

use crate::cell::Cell;
use crate::error::{ClusterError, ClusterResult};

#[derive(Debug, Clone)]
pub struct AgentMigrationReport {
    pub agent_pid: String,
    pub source_cell_id: String,
    pub target_cell_id: String,
    pub snapshot_cid: String,
    pub source_status: AgentStatus,
    pub resumed_on_target: bool,
    pub stripped_embedded_audits: bool,
    pub snapshot_audit_entries: usize,
    pub imported_audit_entries: usize,
    pub source_flush_writes: usize,
    pub target_flush_writes: usize,
    pub migration_ms: u64,
}

pub fn migrate_agent(
    source_cell: &Cell,
    source_kernel: &mut MemoryKernel,
    source_store: &mut dyn KernelStore,
    target_cell: &Cell,
    target_kernel: &mut MemoryKernel,
    target_store: &mut dyn KernelStore,
    agent_pid: &str,
) -> ClusterResult<AgentMigrationReport> {
    let started = Instant::now();
    let source_agent = source_kernel
        .get_agent(agent_pid)
        .cloned()
        .ok_or_else(|| ClusterError::Migration(format!("Agent {} not found on source cell {}", agent_pid, source_cell.cell_id)))?;

    if source_agent.is_terminated() {
        return Err(ClusterError::Migration(format!(
            "Agent {} is already terminated on source cell {}",
            agent_pid,
            source_cell.cell_id
        )));
    }

    if target_kernel.get_agent(agent_pid).is_some() {
        return Err(ClusterError::Migration(format!(
            "Agent {} already exists on target cell {}",
            agent_pid,
            target_cell.cell_id
        )));
    }

    let source_status = source_agent.status.clone();
    let should_suspend = matches!(source_status, AgentStatus::Running | AgentStatus::Waiting);
    if should_suspend {
        ensure_kernel_success(
            source_kernel.dispatch(
                SyscallRequest::new(agent_pid, MemoryKernelOp::AgentSuspend, SyscallPayload::Empty)
                    .with_reason(format!(
                        "Migrating agent from {} to {}",
                        source_cell.cell_id, target_cell.cell_id
                    )),
            ),
            "suspend source agent for migration",
        )?;
    }

    let snapshot = source_kernel
        .export_agent_snapshot(agent_pid)
        .map_err(ClusterError::Migration)?;
    let snapshot_cid = snapshot
        .snapshot_cid
        .clone()
        .map(|cid| cid.to_string())
        .ok_or_else(|| ClusterError::Migration(format!("Snapshot for {} is missing snapshot_cid", agent_pid)))?;
    let snapshot_audit_entries = snapshot.audit_entries.len();

    let target_has_audit = !target_kernel.audit_log().is_empty() || target_kernel.audit_batch_pending() > 0;
    let (snapshot_for_import, stripped_embedded_audits, imported_audit_entries) =
        prepare_snapshot_for_import(snapshot, target_has_audit)?;

    let imported_pid = match target_kernel.import_agent_snapshot(snapshot_for_import, &source_cell.cell_id) {
        Ok(pid) => pid,
        Err(err) => {
            if should_suspend {
                let _ = source_kernel.dispatch(
                    SyscallRequest::new(agent_pid, MemoryKernelOp::AgentResume, SyscallPayload::Empty)
                        .with_reason(format!("Rollback failed migration to {}", target_cell.cell_id)),
                );
            }
            return Err(ClusterError::Migration(err));
        }
    };

    if imported_pid != agent_pid {
        return Err(ClusterError::Migration(format!(
            "Imported PID mismatch: expected {}, got {}",
            agent_pid,
            imported_pid
        )));
    }

    if let Err(err) = ensure_kernel_success(
        source_kernel.dispatch(
            SyscallRequest::new(
                agent_pid,
                MemoryKernelOp::AgentTerminate,
                SyscallPayload::AgentTerminate {
                    target_pid: Some(agent_pid.to_string()),
                    reason: format!("Migrated to {}", target_cell.cell_id),
                },
            )
            .with_reason(format!(
                "Finalize migration from {} to {}",
                source_cell.cell_id, target_cell.cell_id
            )),
        ),
        "terminate source agent after migration",
    ) {
        let _ = target_kernel.dispatch(
            SyscallRequest::new(
                agent_pid,
                MemoryKernelOp::AgentTerminate,
                SyscallPayload::AgentTerminate {
                    target_pid: Some(agent_pid.to_string()),
                    reason: format!("Rollback incomplete migration from {}", source_cell.cell_id),
                },
            )
            .with_reason(format!(
                "Rollback migration from {} to {}",
                source_cell.cell_id, target_cell.cell_id
            )),
        );
        return Err(err);
    }

    let resumed_on_target = if should_suspend {
        ensure_kernel_success(
            target_kernel.dispatch(
                SyscallRequest::new(agent_pid, MemoryKernelOp::AgentResume, SyscallPayload::Empty)
                    .with_reason(format!("Resume migrated agent from {}", source_cell.cell_id)),
            ),
            "resume target agent after migration",
        )?;
        true
    } else {
        false
    };

    source_kernel.flush_audit_batch();
    target_kernel.flush_audit_batch();

    let source_flush_writes = source_kernel
        .flush_to_store(source_store)
        .map_err(ClusterError::Store)?;
    let target_flush_writes = target_kernel
        .flush_to_store(target_store)
        .map_err(ClusterError::Store)?;

    Ok(AgentMigrationReport {
        agent_pid: agent_pid.to_string(),
        source_cell_id: source_cell.cell_id.clone(),
        target_cell_id: target_cell.cell_id.clone(),
        snapshot_cid,
        source_status,
        resumed_on_target,
        stripped_embedded_audits,
        snapshot_audit_entries,
        imported_audit_entries,
        source_flush_writes,
        target_flush_writes,
        migration_ms: started.elapsed().as_millis() as u64,
    })
}

fn prepare_snapshot_for_import(
    mut snapshot: AgentSnapshot,
    target_has_audit: bool,
) -> ClusterResult<(AgentSnapshot, bool, usize)> {
    let imported_audit_entries = snapshot.audit_entries.len();
    if target_has_audit && imported_audit_entries > 0 {
        snapshot.audit_entries.clear();
        snapshot.snapshot_cid = None;
        let snapshot_cid = compute_cid(&snapshot)
            .map_err(|e| ClusterError::Serialization(format!("Failed to re-CID migration snapshot: {}", e)))?;
        snapshot.snapshot_cid = Some(snapshot_cid);
        return Ok((snapshot, true, 0));
    }
    Ok((snapshot, false, imported_audit_entries))
}

fn ensure_kernel_success(result: vac_core::kernel::SyscallResult, action: &str) -> ClusterResult<()> {
    if result.outcome == OpOutcome::Success {
        return Ok(());
    }

    let message = match result.value {
        SyscallValue::Error(msg) => msg,
        other => format!("unexpected syscall result: {:?}", other),
    };
    Err(ClusterError::Migration(format!("Failed to {}: {}", action, message)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use vac_core::kernel::{SyscallPayload, SyscallRequest};
    use vac_core::store::InMemoryKernelStore;
    use vac_core::types::{MemoryKernelOp, PacketType, Source, SourceKind};

    fn register_agent(kernel: &mut MemoryKernel, name: &str, namespace: &str) -> String {
        let result = kernel.dispatch(
            SyscallRequest::new(
                String::new(),
                MemoryKernelOp::AgentRegister,
                SyscallPayload::AgentRegister {
                    agent_name: name.to_string(),
                    namespace: namespace.to_string(),
                    role: None,
                    model: None,
                    framework: None,
                },
            )
            .with_reason("test register"),
        );
        match result.value {
            SyscallValue::AgentPid(pid) => pid,
            other => panic!("unexpected register result: {:?}", other),
        }
    }

    fn start_agent(kernel: &mut MemoryKernel, pid: &str) {
        let result = kernel.dispatch(
            SyscallRequest::new(pid, MemoryKernelOp::AgentStart, SyscallPayload::Empty)
                .with_reason("test start"),
        );
        assert_eq!(result.outcome, OpOutcome::Success);
    }

    fn write_packet(kernel: &mut MemoryKernel, pid: &str, namespace: &str) {
        let packet = vac_core::types::MemPacket::new(
            PacketType::Extraction,
            serde_json::json!({"migrate": true}),
            cid::Cid::default(),
            pid.to_string(),
            "pipeline:test".to_string(),
            Source {
                kind: SourceKind::Tool,
                principal_id: pid.to_string(),
            },
            chrono::Utc::now().timestamp_millis(),
        )
        .with_namespace(namespace.to_string());

        let result = kernel.dispatch(
            SyscallRequest::new(
                pid,
                MemoryKernelOp::MemWrite,
                SyscallPayload::MemWrite { packet },
            )
            .with_reason("test write"),
        );
        assert_eq!(result.outcome, OpOutcome::Success);
    }

    #[test]
    fn migrate_agent_moves_snapshot_and_terminates_source() {
        let source_cell = Cell::new("cell-a");
        let target_cell = Cell::new("cell-b");
        let mut source_kernel = MemoryKernel::new();
        let mut target_kernel = MemoryKernel::new();
        let mut source_store = InMemoryKernelStore::new();
        let mut target_store = InMemoryKernelStore::new();

        let pid = register_agent(&mut source_kernel, "triage", "ns:triage");
        start_agent(&mut source_kernel, &pid);
        write_packet(&mut source_kernel, &pid, "ns:triage");

        let report = migrate_agent(
            &source_cell,
            &mut source_kernel,
            &mut source_store,
            &target_cell,
            &mut target_kernel,
            &mut target_store,
            &pid,
        )
        .unwrap();

        assert_eq!(report.agent_pid, pid);
        assert!(report.resumed_on_target);
        assert_eq!(source_kernel.get_agent(&report.agent_pid).unwrap().status, AgentStatus::Terminated);
        assert_eq!(target_kernel.get_agent(&report.agent_pid).unwrap().status, AgentStatus::Running);
        assert!(target_store.load_agent(&report.agent_pid).unwrap().is_some());
        assert!(!report.snapshot_cid.is_empty());
    }

    #[test]
    fn migrate_agent_strips_embedded_audits_for_nonfresh_target() {
        let source_cell = Cell::new("cell-a");
        let target_cell = Cell::new("cell-b");
        let mut source_kernel = MemoryKernel::new();
        let mut target_kernel = MemoryKernel::new();
        let mut source_store = InMemoryKernelStore::new();
        let mut target_store = InMemoryKernelStore::new();

        let _padding_pid = register_agent(&mut source_kernel, "padding", "ns:padding");
        let source_pid = register_agent(&mut source_kernel, "source", "ns:source");
        start_agent(&mut source_kernel, &source_pid);
        write_packet(&mut source_kernel, &source_pid, "ns:source");

        let target_pid = register_agent(&mut target_kernel, "existing", "ns:existing");
        start_agent(&mut target_kernel, &target_pid);
        target_kernel.flush_audit_batch();

        let report = migrate_agent(
            &source_cell,
            &mut source_kernel,
            &mut source_store,
            &target_cell,
            &mut target_kernel,
            &mut target_store,
            &source_pid,
        )
        .unwrap();

        assert!(report.snapshot_audit_entries > 0);
        assert!(report.stripped_embedded_audits);
        assert_eq!(report.imported_audit_entries, 0);
        assert!(target_kernel.get_agent(&source_pid).is_some());
    }
}

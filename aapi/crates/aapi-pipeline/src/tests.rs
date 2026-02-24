//! Tests for aapi-pipeline.

use std::collections::HashMap;

use async_trait::async_trait;

use aapi_adapters::effect::CapturedEffect;
use aapi_adapters::error::{AdapterError, AdapterResult};
use aapi_adapters::registry::{AdapterRegistry, Dispatcher};
use aapi_adapters::traits::{Adapter, ExecutionContext, ExecutionResult, HealthStatus};
use aapi_core::types::*;
use aapi_core::vakya::{CapabilityRef, TtlConstraint};
use aapi_core::Vakya;

use crate::pipeline::*;
use crate::router::*;

// ============================================================================
// Test helpers
// ============================================================================

fn make_test_vakya(domain: &str, verb: &str, agent_pid: &str) -> Vakya {
    Vakya::builder()
        .karta(aapi_core::vakya::Karta {
            pid: PrincipalId::new(agent_pid),
            role: Some("agent".to_string()),
            realm: None,
            key_id: None,
            actor_type: aapi_core::vakya::ActorType::Agent,
            delegation_chain: vec![],
        })
        .karma(aapi_core::vakya::Karma {
            rid: ResourceId::new("res:test"),
            kind: Some("test".to_string()),
            ns: Some(Namespace::new("test")),
            version: None,
            labels: HashMap::new(),
        })
        .kriya(aapi_core::vakya::Kriya::new(domain, verb))
        .adhikarana(aapi_core::vakya::Adhikarana {
            cap: CapabilityRef::Reference {
                cap_ref: "cap:test:all".to_string(),
            },
            policy_ref: None,
            ttl: Some(TtlConstraint {
                expires_at: Timestamp(chrono::Utc::now() + chrono::Duration::hours(1)),
                max_duration_ms: None,
            }),
            budgets: vec![],
            approval_lane: ApprovalLane::None,
            scopes: vec!["*".to_string()],
            context: None,
            delegation_chain_cid: None,
            execution_constraints: None,
            port_id: None,
            required_phase: None,
            required_role: None,
        })
        .build()
        .expect("test vakya should be valid")
}

/// A mock adapter that always succeeds.
struct MockAdapter {
    domain: String,
}

impl MockAdapter {
    fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
        }
    }
}

#[async_trait]
impl Adapter for MockAdapter {
    fn domain(&self) -> &str {
        &self.domain
    }
    fn version(&self) -> &str {
        "1.0.0-mock"
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec![]
    }
    fn supports_action(&self, action: &str) -> bool {
        action.starts_with(&format!("{}.", self.domain))
    }
    async fn execute(
        &self,
        vakya: &Vakya,
        _context: &ExecutionContext,
    ) -> AdapterResult<ExecutionResult> {
        Ok(ExecutionResult::success(
            serde_json::json!({
                "action": vakya.v3_kriya.action,
                "mock": true,
            }),
            vec![],
            1,
        ))
    }
    fn can_rollback(&self, _action: &str) -> bool {
        false
    }
    async fn rollback(&self, _effect: &CapturedEffect) -> AdapterResult<()> {
        Ok(())
    }
    async fn health_check(&self) -> AdapterResult<HealthStatus> {
        Ok(HealthStatus::healthy())
    }
}

/// A mock adapter that always fails.
struct FailingAdapter {
    domain: String,
}

impl FailingAdapter {
    fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
        }
    }
}

#[async_trait]
impl Adapter for FailingAdapter {
    fn domain(&self) -> &str {
        &self.domain
    }
    fn version(&self) -> &str {
        "1.0.0-fail"
    }
    fn supported_actions(&self) -> Vec<&str> {
        vec![]
    }
    fn supports_action(&self, action: &str) -> bool {
        action.starts_with(&format!("{}.", self.domain))
    }
    async fn execute(
        &self,
        _vakya: &Vakya,
        _context: &ExecutionContext,
    ) -> AdapterResult<ExecutionResult> {
        Err(AdapterError::Internal("intentional failure".into()))
    }
    fn can_rollback(&self, _action: &str) -> bool {
        false
    }
    async fn rollback(&self, _effect: &CapturedEffect) -> AdapterResult<()> {
        Ok(())
    }
    async fn health_check(&self) -> AdapterResult<HealthStatus> {
        Ok(HealthStatus::unhealthy("always fails"))
    }
}

fn make_dispatcher_with_mock(adapter: MockAdapter) -> Dispatcher {
    let mut registry = AdapterRegistry::new();
    registry.register(adapter);
    Dispatcher::new(registry)
}

fn make_dispatcher_with_failing(adapter: FailingAdapter) -> Dispatcher {
    let mut registry = AdapterRegistry::new();
    registry.register(adapter);
    Dispatcher::new(registry)
}

// ============================================================================
// Router tests
// ============================================================================

#[test]
fn test_router_local_fallback() {
    let router = VakyaRouter::new();
    let vakya = make_test_vakya("file", "read", "pid:001");
    let target = router.route_vakya(&vakya, "cell-1");
    assert_eq!(target, RouteTarget::Local);
}

#[test]
fn test_router_adapter_location() {
    let mut router = VakyaRouter::new();
    router.register_adapter("database", "cell-2");

    let vakya = make_test_vakya("database", "query", "pid:001");
    let target = router.route_vakya(&vakya, "cell-1");
    assert_eq!(
        target,
        RouteTarget::Remote {
            cell_id: "cell-2".into()
        }
    );

    // Same cell → local
    let target = router.route_vakya(&vakya, "cell-2");
    assert_eq!(target, RouteTarget::Local);
}

#[test]
fn test_router_agent_location() {
    let mut router = VakyaRouter::new();
    router.register_agent("pid:001", "cell-3");

    let vakya = make_test_vakya("file", "read", "pid:001");
    let target = router.route_vakya(&vakya, "cell-1");
    assert_eq!(
        target,
        RouteTarget::Remote {
            cell_id: "cell-3".into()
        }
    );
}

#[test]
fn test_router_adapter_priority_over_agent() {
    let mut router = VakyaRouter::new();
    router.register_adapter("database", "cell-2");
    router.register_agent("pid:001", "cell-3");

    // Adapter location takes priority
    let vakya = make_test_vakya("database", "query", "pid:001");
    let target = router.route_vakya(&vakya, "cell-1");
    assert_eq!(
        target,
        RouteTarget::Remote {
            cell_id: "cell-2".into()
        }
    );
}

#[test]
fn test_router_register_deregister() {
    let mut router = VakyaRouter::new();

    router.register_adapter("http", "cell-2");
    assert_eq!(router.adapter_count(), 1);
    assert!(router.has_adapter("http"));
    assert_eq!(router.adapter_cell("http"), Some("cell-2"));

    router.deregister_adapter("http");
    assert_eq!(router.adapter_count(), 0);
    assert!(!router.has_adapter("http"));

    router.register_agent("pid:001", "cell-3");
    assert_eq!(router.agent_count(), 1);
    assert_eq!(router.agent_cell("pid:001"), Some("cell-3"));

    router.deregister_agent("pid:001");
    assert_eq!(router.agent_count(), 0);
}

// ============================================================================
// Pipeline validation tests
// ============================================================================

#[test]
fn test_pipeline_validate_ok() {
    let mut pipeline = VakyaPipeline::new("p1", "cell-1");
    pipeline.add_step(PipelineStep::new("s1", make_test_vakya("file", "read", "pid:001")));
    pipeline.add_step(
        PipelineStep::new("s2", make_test_vakya("file", "write", "pid:001"))
            .with_dependency("s1"),
    );
    assert!(pipeline.validate().is_ok());
}

#[test]
fn test_pipeline_validate_missing_dep() {
    let mut pipeline = VakyaPipeline::new("p1", "cell-1");
    pipeline.add_step(
        PipelineStep::new("s1", make_test_vakya("file", "read", "pid:001"))
            .with_dependency("nonexistent"),
    );
    let err = pipeline.validate().unwrap_err();
    assert!(matches!(err, crate::error::PipelineError::DependencyNotMet { .. }));
}

#[test]
fn test_pipeline_validate_cycle() {
    let mut pipeline = VakyaPipeline::new("p1", "cell-1");
    pipeline.add_step(
        PipelineStep::new("s1", make_test_vakya("file", "read", "pid:001"))
            .with_dependency("s2"),
    );
    pipeline.add_step(
        PipelineStep::new("s2", make_test_vakya("file", "write", "pid:001"))
            .with_dependency("s1"),
    );
    let err = pipeline.validate().unwrap_err();
    assert!(matches!(err, crate::error::PipelineError::CircularDependency(_)));
}

#[test]
fn test_pipeline_execution_order() {
    let mut pipeline = VakyaPipeline::new("p1", "cell-1");
    pipeline.add_step(PipelineStep::new("s1", make_test_vakya("file", "read", "pid:001")));
    pipeline.add_step(
        PipelineStep::new("s2", make_test_vakya("file", "write", "pid:001"))
            .with_dependency("s1"),
    );
    pipeline.add_step(
        PipelineStep::new("s3", make_test_vakya("file", "delete", "pid:001"))
            .with_dependency("s2"),
    );

    let order = pipeline.execution_order().unwrap();
    // s1 must come before s2, s2 before s3
    let pos_s1 = order.iter().position(|&i| pipeline.steps[i].step_id == "s1").unwrap();
    let pos_s2 = order.iter().position(|&i| pipeline.steps[i].step_id == "s2").unwrap();
    let pos_s3 = order.iter().position(|&i| pipeline.steps[i].step_id == "s3").unwrap();
    assert!(pos_s1 < pos_s2);
    assert!(pos_s2 < pos_s3);
}

// ============================================================================
// Pipeline execution tests
// ============================================================================

#[tokio::test]
async fn test_pipeline_execute_single_step() {
    let dispatcher = make_dispatcher_with_mock(MockAdapter::new("file"));
    let router = VakyaRouter::new();

    let mut pipeline = VakyaPipeline::new("p1", "cell-1");
    pipeline.add_step(PipelineStep::new("s1", make_test_vakya("file", "read", "pid:001")));

    let result = pipeline.execute(&dispatcher, &router).await.unwrap();
    assert_eq!(result.state, PipelineState::Completed);
    assert_eq!(result.steps_completed, 1);
    assert_eq!(result.steps_failed, 0);
    assert!(result.step_results["s1"].status.is_success());
}

#[tokio::test]
async fn test_pipeline_execute_chain() {
    let dispatcher = make_dispatcher_with_mock(MockAdapter::new("file"));
    let router = VakyaRouter::new();

    let mut pipeline = VakyaPipeline::new("p1", "cell-1");
    pipeline.add_step(PipelineStep::new("s1", make_test_vakya("file", "read", "pid:001")));
    pipeline.add_step(
        PipelineStep::new("s2", make_test_vakya("file", "write", "pid:001"))
            .with_dependency("s1"),
    );

    let result = pipeline.execute(&dispatcher, &router).await.unwrap();
    assert_eq!(result.state, PipelineState::Completed);
    assert_eq!(result.steps_completed, 2);
}

#[tokio::test]
async fn test_pipeline_step_failure_stops_pipeline() {
    let dispatcher = make_dispatcher_with_failing(FailingAdapter::new("file"));
    let router = VakyaRouter::new();

    let mut pipeline = VakyaPipeline::new("p1", "cell-1");
    pipeline.add_step(PipelineStep::new("s1", make_test_vakya("file", "read", "pid:001")));
    pipeline.add_step(
        PipelineStep::new("s2", make_test_vakya("file", "write", "pid:001"))
            .with_dependency("s1"),
    );

    let result = pipeline.execute(&dispatcher, &router).await.unwrap();
    assert_eq!(result.state, PipelineState::Failed);
    assert_eq!(result.steps_failed, 1);
    // s2 should not have run (dependency failed)
    assert!(matches!(
        result.step_results["s1"].status,
        StepStatus::Failed { .. }
    ));
}

#[tokio::test]
async fn test_pipeline_remote_step_skipped() {
    let dispatcher = make_dispatcher_with_mock(MockAdapter::new("file"));
    let mut router = VakyaRouter::new();
    router.register_adapter("database", "cell-2");

    let mut pipeline = VakyaPipeline::new("p1", "cell-1");
    pipeline.add_step(PipelineStep::new("s1", make_test_vakya("file", "read", "pid:001")));
    pipeline.add_step(
        PipelineStep::new("s2", make_test_vakya("database", "query", "pid:001")),
    );

    let result = pipeline.execute(&dispatcher, &router).await.unwrap();
    assert_eq!(result.state, PipelineState::Completed);
    // s1 completed locally, s2 skipped (remote)
    assert!(result.step_results["s1"].status.is_success());
    assert!(matches!(
        result.step_results["s2"].status,
        StepStatus::Skipped { .. }
    ));
}

// ============================================================================
// Saga Coordinator tests
// ============================================================================

use aapi_adapters::effect::ReversalInstructions;
use crate::saga::*;

fn make_reversible_effect(vakya_id: &str, target: &str) -> CapturedEffect {
    CapturedEffect::new(vakya_id, EffectBucket::Update, target)
        .reversible(ReversalInstructions {
            method: aapi_adapters::effect::ReversalMethod::RestoreState,
            data: serde_json::json!({"restore": true}),
            description: Some("undo test".into()),
        })
}

fn make_non_reversible_effect(vakya_id: &str, target: &str) -> CapturedEffect {
    CapturedEffect::new(vakya_id, EffectBucket::None, target)
}

#[test]
fn test_saga_coordinator_creation() {
    let steps = vec![
        CompletedStep {
            step_id: "s1".into(),
            cell_id: "local".into(),
            effects: vec![make_reversible_effect("v1", "res:a")],
        },
        CompletedStep {
            step_id: "s2".into(),
            cell_id: "local".into(),
            effects: vec![make_reversible_effect("v2", "res:b")],
        },
    ];

    let saga = SagaCoordinator::new("saga-1", "cell-1", steps);
    assert_eq!(saga.step_count(), 2);
    assert_eq!(saga.reversible_count(), 2);
}

#[test]
fn test_saga_reversible_count() {
    let steps = vec![
        CompletedStep {
            step_id: "s1".into(),
            cell_id: "local".into(),
            effects: vec![make_reversible_effect("v1", "res:a")],
        },
        CompletedStep {
            step_id: "s2".into(),
            cell_id: "local".into(),
            effects: vec![make_non_reversible_effect("v2", "res:b")],
        },
        CompletedStep {
            step_id: "s3".into(),
            cell_id: "local".into(),
            effects: vec![],
        },
    ];

    let saga = SagaCoordinator::new("saga-1", "cell-1", steps);
    assert_eq!(saga.step_count(), 3);
    assert_eq!(saga.reversible_count(), 1); // only s1 has reversible effects
}

#[tokio::test]
async fn test_saga_rollback_no_ops() {
    // All steps have non-reversible effects → all NoOp
    let steps = vec![
        CompletedStep {
            step_id: "s1".into(),
            cell_id: "local".into(),
            effects: vec![make_non_reversible_effect("v1", "res:a")],
        },
        CompletedStep {
            step_id: "s2".into(),
            cell_id: "local".into(),
            effects: vec![],
        },
    ];

    let saga = SagaCoordinator::new("saga-1", "cell-1", steps);
    let dispatcher = make_dispatcher_with_mock(MockAdapter::new("file"));

    let result = saga.rollback(&dispatcher).await.unwrap();
    assert_eq!(result.total_steps, 2);
    assert_eq!(result.no_ops, 2);
    assert_eq!(result.rolled_back, 0);
    assert_eq!(result.failures, 0);
}

#[tokio::test]
async fn test_saga_rollback_local_steps() {
    // MockAdapter rollback always succeeds
    let steps = vec![
        CompletedStep {
            step_id: "s1".into(),
            cell_id: "cell-1".into(),
            effects: vec![make_reversible_effect("v1", "file:a")],
        },
        CompletedStep {
            step_id: "s2".into(),
            cell_id: "cell-1".into(),
            effects: vec![make_reversible_effect("v2", "file:b")],
        },
    ];

    let saga = SagaCoordinator::new("saga-1", "cell-1", steps);
    let dispatcher = make_dispatcher_with_mock(MockAdapter::new("file"));

    let result = saga.rollback(&dispatcher).await.unwrap();
    assert_eq!(result.rolled_back, 2);
    assert_eq!(result.failures, 0);

    // Verify reverse order: s2 should be rolled back before s1
    // (Both succeed, so we just check counts)
    assert!(matches!(
        result.step_outcomes["s1"],
        RollbackOutcome::RolledBack
    ));
    assert!(matches!(
        result.step_outcomes["s2"],
        RollbackOutcome::RolledBack
    ));
}

#[tokio::test]
async fn test_saga_rollback_remote_steps() {
    let steps = vec![
        CompletedStep {
            step_id: "s1".into(),
            cell_id: "cell-1".into(),
            effects: vec![make_reversible_effect("v1", "file:a")],
        },
        CompletedStep {
            step_id: "s2".into(),
            cell_id: "cell-2".into(), // remote
            effects: vec![make_reversible_effect("v2", "file:b")],
        },
    ];

    let saga = SagaCoordinator::new("saga-1", "cell-1", steps);
    let dispatcher = make_dispatcher_with_mock(MockAdapter::new("file"));

    let result = saga.rollback(&dispatcher).await.unwrap();
    assert_eq!(result.rolled_back, 1);       // s1 local
    assert_eq!(result.remote_requested, 1);  // s2 remote
    assert!(matches!(
        result.step_outcomes["s1"],
        RollbackOutcome::RolledBack
    ));
    assert!(matches!(
        result.step_outcomes["s2"],
        RollbackOutcome::RemoteRequested { .. }
    ));
}

#[tokio::test]
async fn test_saga_rollback_mixed() {
    let steps = vec![
        CompletedStep {
            step_id: "s1".into(),
            cell_id: "cell-1".into(),
            effects: vec![make_reversible_effect("v1", "file:a")],
        },
        CompletedStep {
            step_id: "s2".into(),
            cell_id: "cell-1".into(),
            effects: vec![make_non_reversible_effect("v2", "file:b")],
        },
        CompletedStep {
            step_id: "s3".into(),
            cell_id: "cell-2".into(),
            effects: vec![make_reversible_effect("v3", "file:c")],
        },
    ];

    let saga = SagaCoordinator::new("saga-1", "cell-1", steps);
    let dispatcher = make_dispatcher_with_mock(MockAdapter::new("file"));

    let result = saga.rollback(&dispatcher).await.unwrap();
    assert_eq!(result.total_steps, 3);
    assert_eq!(result.rolled_back, 1);       // s1
    assert_eq!(result.no_ops, 1);            // s2
    assert_eq!(result.remote_requested, 1);  // s3
}

#[test]
fn test_saga_from_pipeline_steps() {
    let pipeline_steps = vec![
        PipelineStep {
            step_id: "s1".into(),
            vakya: make_test_vakya("file", "read", "pid:001"),
            target_cell: None,
            depends_on: vec![],
            effects: vec![make_reversible_effect("v1", "file:a")],
            status: StepStatus::Completed { duration_ms: 10 },
        },
        PipelineStep {
            step_id: "s2".into(),
            vakya: make_test_vakya("file", "write", "pid:001"),
            target_cell: Some("cell-2".into()),
            depends_on: vec!["s1".into()],
            effects: vec![],
            status: StepStatus::Failed { error: "boom".into() },
        },
    ];

    let saga = SagaCoordinator::from_pipeline("saga-1", "cell-1", &pipeline_steps);
    // Only s1 was completed (s2 failed)
    assert_eq!(saga.step_count(), 1);
    assert_eq!(saga.completed_steps[0].step_id, "s1");
}

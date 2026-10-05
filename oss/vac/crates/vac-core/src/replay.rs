//! Deterministic Execution Replay — Replay from Audit Log
//!
//! This module implements deterministic execution replay:
//! - Capture execution events for replay
//! - Replay execution from audit log
//! - Time-travel debugging (step forward/backward)
//! - Divergence detection (actual vs expected)
//! - Checkpoint/restore for replay sessions
//!
//! Design sources: rr (Mozilla), QEMU record/replay, Hermit deterministic runtime

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{MemoryKernelOp, OpOutcome};

// =============================================================================
// Replay Event Types
// =============================================================================

/// Replay event — a single recorded operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayEvent {
    /// Event sequence number (monotonic)
    pub seq: u64,
    /// Timestamp (epoch nanoseconds)
    pub timestamp_ns: u64,
    /// Agent PID
    pub agent_pid: String,
    /// Thread ID (if applicable)
    pub thread_id: Option<String>,
    /// Operation type
    pub operation: MemoryKernelOp,
    /// Operation payload (serialized)
    pub payload: serde_json::Value,
    /// Operation outcome
    pub outcome: OpOutcome,
    /// Return value (serialized)
    pub return_value: Option<serde_json::Value>,
    /// Duration (nanoseconds)
    pub duration_ns: u64,
    /// Causal dependencies (seq numbers of events this depends on)
    pub depends_on: Vec<u64>,
    /// Random values consumed (for determinism)
    pub random_values: Vec<u64>,
    /// External inputs (network, time, etc.)
    pub external_inputs: HashMap<String, serde_json::Value>,
}

impl ReplayEvent {
    pub fn new(
        seq: u64,
        agent_pid: String,
        operation: MemoryKernelOp,
        payload: serde_json::Value,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            seq,
            timestamp_ns: now,
            agent_pid,
            thread_id: None,
            operation,
            payload,
            outcome: OpOutcome::Success,
            return_value: None,
            duration_ns: 0,
            depends_on: vec![],
            random_values: vec![],
            external_inputs: HashMap::new(),
        }
    }

    pub fn with_outcome(mut self, outcome: OpOutcome, return_value: Option<serde_json::Value>) -> Self {
        self.outcome = outcome;
        self.return_value = return_value;
        self
    }

    pub fn with_duration(mut self, duration_ns: u64) -> Self {
        self.duration_ns = duration_ns;
        self
    }

    pub fn with_thread(mut self, thread_id: String) -> Self {
        self.thread_id = Some(thread_id);
        self
    }

    pub fn with_dependency(mut self, dep_seq: u64) -> Self {
        self.depends_on.push(dep_seq);
        self
    }

    pub fn with_random(mut self, value: u64) -> Self {
        self.random_values.push(value);
        self
    }

    pub fn with_external_input(mut self, key: String, value: serde_json::Value) -> Self {
        self.external_inputs.insert(key, value);
        self
    }
}

// =============================================================================
// Replay Session
// =============================================================================

/// Replay mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayMode {
    /// Recording mode — capture events
    Record,
    /// Replay mode — replay from log
    Replay,
    /// Paused — replay is paused
    Paused,
    /// Stepping — single-step execution
    Stepping,
}

/// Replay session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayState {
    /// Session is idle
    Idle,
    /// Session is running
    Running,
    /// Session is paused
    Paused,
    /// Session completed successfully
    Completed,
    /// Session diverged from expected
    Diverged,
    /// Session encountered an error
    Error,
}

/// Replay session — manages a single replay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySession {
    /// Session ID
    pub session_id: String,
    /// Replay mode
    pub mode: ReplayMode,
    /// Session state
    pub state: ReplayState,
    /// Current position (event seq)
    pub position: u64,
    /// Total events
    pub total_events: u64,
    /// Start timestamp
    pub started_at: i64,
    /// End timestamp (if completed)
    pub ended_at: Option<i64>,
    /// Divergence point (if diverged)
    pub divergence_point: Option<u64>,
    /// Divergence reason
    pub divergence_reason: Option<String>,
    /// Checkpoints (seq -> checkpoint_id)
    pub checkpoints: HashMap<u64, String>,
    /// Breakpoints (seq numbers to pause at)
    pub breakpoints: Vec<u64>,
    /// Watch expressions
    pub watches: Vec<WatchExpression>,
}

impl ReplaySession {
    pub fn new_record(session_id: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            session_id,
            mode: ReplayMode::Record,
            state: ReplayState::Running,
            position: 0,
            total_events: 0,
            started_at: now,
            ended_at: None,
            divergence_point: None,
            divergence_reason: None,
            checkpoints: HashMap::new(),
            breakpoints: vec![],
            watches: vec![],
        }
    }

    pub fn new_replay(session_id: String, total_events: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            session_id,
            mode: ReplayMode::Replay,
            state: ReplayState::Idle,
            position: 0,
            total_events,
            started_at: now,
            ended_at: None,
            divergence_point: None,
            divergence_reason: None,
            checkpoints: HashMap::new(),
            breakpoints: vec![],
            watches: vec![],
        }
    }

    /// Start replay
    pub fn start(&mut self) {
        self.state = ReplayState::Running;
    }

    /// Pause replay
    pub fn pause(&mut self) {
        self.state = ReplayState::Paused;
        self.mode = ReplayMode::Paused;
    }

    /// Resume replay
    pub fn resume(&mut self) {
        self.state = ReplayState::Running;
        self.mode = ReplayMode::Replay;
    }

    /// Step forward
    pub fn step(&mut self) {
        self.mode = ReplayMode::Stepping;
        self.state = ReplayState::Running;
    }

    /// Advance position
    pub fn advance(&mut self) -> bool {
        if self.position < self.total_events {
            self.position += 1;
            
            // Check breakpoints
            if self.breakpoints.contains(&self.position) {
                self.pause();
                return false;
            }
            
            // Check completion
            if self.position >= self.total_events {
                self.complete();
            }
            
            true
        } else {
            false
        }
    }

    /// Go to position
    pub fn goto(&mut self, position: u64) -> bool {
        if position <= self.total_events {
            self.position = position;
            true
        } else {
            false
        }
    }

    /// Mark as diverged
    pub fn diverge(&mut self, reason: String) {
        self.state = ReplayState::Diverged;
        self.divergence_point = Some(self.position);
        self.divergence_reason = Some(reason);
    }

    /// Mark as completed
    pub fn complete(&mut self) {
        self.state = ReplayState::Completed;
        self.ended_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64
        );
    }

    /// Add breakpoint
    pub fn add_breakpoint(&mut self, seq: u64) {
        if !self.breakpoints.contains(&seq) {
            self.breakpoints.push(seq);
            self.breakpoints.sort();
        }
    }

    /// Remove breakpoint
    pub fn remove_breakpoint(&mut self, seq: u64) {
        self.breakpoints.retain(|&s| s != seq);
    }

    /// Add checkpoint
    pub fn add_checkpoint(&mut self, checkpoint_id: String) {
        self.checkpoints.insert(self.position, checkpoint_id);
    }

    /// Get nearest checkpoint before position
    pub fn nearest_checkpoint(&self, position: u64) -> Option<(u64, &String)> {
        self.checkpoints
            .iter()
            .filter(|(&seq, _)| seq <= position)
            .max_by_key(|(&seq, _)| seq)
            .map(|(seq, id)| (*seq, id))
    }

    /// Progress percentage
    pub fn progress(&self) -> f32 {
        if self.total_events == 0 {
            0.0
        } else {
            (self.position as f32 / self.total_events as f32) * 100.0
        }
    }
}

/// Watch expression for debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchExpression {
    /// Watch ID
    pub id: String,
    /// Expression to evaluate
    pub expression: String,
    /// Last value
    pub last_value: Option<serde_json::Value>,
    /// Trigger on change
    pub break_on_change: bool,
}

// =============================================================================
// Replay Log
// =============================================================================

/// Replay log — stores events for replay
#[derive(Debug, Default)]
pub struct ReplayLog {
    /// Events in order
    events: Vec<ReplayEvent>,
    /// Index by agent PID
    by_agent: HashMap<String, Vec<usize>>,
    /// Index by operation type (keyed by operation string)
    by_operation: HashMap<String, Vec<usize>>,
    /// Next sequence number
    next_seq: u64,
}

impl ReplayLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an event
    pub fn record(&mut self, mut event: ReplayEvent) -> u64 {
        let seq = self.next_seq;
        event.seq = seq;
        self.next_seq += 1;

        let idx = self.events.len();
        
        // Index by agent
        self.by_agent
            .entry(event.agent_pid.clone())
            .or_default()
            .push(idx);

        // Index by operation (using string representation)
        let op_key = event.operation.to_string();
        self.by_operation
            .entry(op_key)
            .or_default()
            .push(idx);

        self.events.push(event);
        seq
    }

    /// Get event by sequence number
    pub fn get(&self, seq: u64) -> Option<&ReplayEvent> {
        self.events.iter().find(|e| e.seq == seq)
    }

    /// Get events in range
    pub fn range(&self, start: u64, end: u64) -> Vec<&ReplayEvent> {
        self.events
            .iter()
            .filter(|e| e.seq >= start && e.seq < end)
            .collect()
    }

    /// Get events for agent
    pub fn by_agent(&self, agent_pid: &str) -> Vec<&ReplayEvent> {
        self.by_agent
            .get(agent_pid)
            .map(|indices| indices.iter().filter_map(|&i| self.events.get(i)).collect())
            .unwrap_or_default()
    }

    /// Get events by operation
    pub fn by_operation(&self, op: &MemoryKernelOp) -> Vec<&ReplayEvent> {
        let op_key = op.to_string();
        self.by_operation
            .get(&op_key)
            .map(|indices| indices.iter().filter_map(|&i| self.events.get(i)).collect())
            .unwrap_or_default()
    }

    /// Total events
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clear the log
    pub fn clear(&mut self) {
        self.events.clear();
        self.by_agent.clear();
        self.by_operation.clear();
        self.next_seq = 0;
    }

    /// Export to JSON
    pub fn export(&self) -> serde_json::Value {
        serde_json::json!({
            "events": self.events,
            "total": self.events.len(),
        })
    }

    /// Import from JSON
    pub fn import(data: &serde_json::Value) -> Result<Self, String> {
        let events: Vec<ReplayEvent> = serde_json::from_value(
            data.get("events").cloned().unwrap_or(serde_json::Value::Array(vec![]))
        ).map_err(|e| e.to_string())?;

        let mut log = Self::new();
        for event in events {
            log.record(event);
        }
        Ok(log)
    }
}

// =============================================================================
// Replay Engine
// =============================================================================

/// Divergence type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DivergenceType {
    /// Operation outcome differs
    OutcomeMismatch { expected: OpOutcome, actual: OpOutcome },
    /// Return value differs
    ReturnValueMismatch { expected: serde_json::Value, actual: serde_json::Value },
    /// Operation type differs
    OperationMismatch { expected: MemoryKernelOp, actual: MemoryKernelOp },
    /// Missing event
    MissingEvent { expected_seq: u64 },
    /// Extra event
    ExtraEvent { actual_seq: u64 },
    /// Timing violation (too slow/fast)
    TimingViolation { expected_ns: u64, actual_ns: u64, threshold_ns: u64 },
}

/// Divergence record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Divergence {
    /// Sequence number where divergence occurred
    pub seq: u64,
    /// Divergence type
    pub divergence_type: DivergenceType,
    /// Expected event
    pub expected: Option<ReplayEvent>,
    /// Actual event
    pub actual: Option<ReplayEvent>,
    /// Timestamp
    pub detected_at: i64,
}

/// Replay engine — orchestrates replay execution
pub struct ReplayEngine {
    /// Replay log
    log: ReplayLog,
    /// Active sessions
    sessions: HashMap<String, ReplaySession>,
    /// Checkpoints (checkpoint_id -> state snapshot)
    checkpoints: HashMap<String, ReplayCheckpoint>,
    /// Divergences detected
    divergences: Vec<Divergence>,
    /// Configuration
    config: ReplayConfig,
}

/// Replay configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Enable timing checks
    pub check_timing: bool,
    /// Timing tolerance (nanoseconds)
    pub timing_tolerance_ns: u64,
    /// Auto-checkpoint interval (events)
    pub checkpoint_interval: u64,
    /// Max checkpoints to keep
    pub max_checkpoints: usize,
    /// Stop on first divergence
    pub stop_on_divergence: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            check_timing: false,
            timing_tolerance_ns: 1_000_000_000, // 1 second
            checkpoint_interval: 1000,
            max_checkpoints: 100,
            stop_on_divergence: true,
        }
    }
}

/// Replay checkpoint — state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayCheckpoint {
    /// Checkpoint ID
    pub id: String,
    /// Sequence number
    pub seq: u64,
    /// Timestamp
    pub timestamp: i64,
    /// State snapshot (serialized)
    pub state: serde_json::Value,
}

impl ReplayEngine {
    pub fn new(config: ReplayConfig) -> Self {
        Self {
            log: ReplayLog::new(),
            sessions: HashMap::new(),
            checkpoints: HashMap::new(),
            divergences: vec![],
            config,
        }
    }

    /// Start recording
    pub fn start_recording(&mut self, session_id: String) -> &ReplaySession {
        let session = ReplaySession::new_record(session_id.clone());
        self.sessions.insert(session_id.clone(), session);
        self.sessions.get(&session_id).unwrap()
    }

    /// Stop recording
    pub fn stop_recording(&mut self, session_id: &str) -> Option<u64> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.complete();
            session.total_events = self.log.len() as u64;
            Some(session.total_events)
        } else {
            None
        }
    }

    /// Record an event
    pub fn record_event(&mut self, event: ReplayEvent) -> u64 {
        let seq = self.log.record(event);

        // Auto-checkpoint
        if self.config.checkpoint_interval > 0 && seq % self.config.checkpoint_interval == 0 {
            self.create_checkpoint(format!("auto-{}", seq), serde_json::Value::Null);
        }

        seq
    }

    /// Start replay
    pub fn start_replay(&mut self, session_id: String) -> &ReplaySession {
        let total = self.log.len() as u64;
        let session = ReplaySession::new_replay(session_id.clone(), total);
        self.sessions.insert(session_id.clone(), session);
        
        let session = self.sessions.get_mut(&session_id).unwrap();
        session.start();
        session
    }

    /// Get next event to replay
    pub fn next_event(&self, session_id: &str) -> Option<&ReplayEvent> {
        let session = self.sessions.get(session_id)?;
        if session.state != ReplayState::Running {
            return None;
        }
        self.log.get(session.position)
    }

    /// Advance replay
    pub fn advance(&mut self, session_id: &str) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.advance()
        } else {
            false
        }
    }

    /// Check for divergence
    pub fn check_divergence(
        &mut self,
        session_id: &str,
        actual: &ReplayEvent,
    ) -> Option<Divergence> {
        let session = self.sessions.get(session_id)?;
        let expected = self.log.get(session.position)?;

        let mut divergence = None;

        // Check operation match
        if expected.operation != actual.operation {
            divergence = Some(Divergence {
                seq: session.position,
                divergence_type: DivergenceType::OperationMismatch {
                    expected: expected.operation.clone(),
                    actual: actual.operation.clone(),
                },
                expected: Some(expected.clone()),
                actual: Some(actual.clone()),
                detected_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
            });
        }

        // Check outcome match
        if divergence.is_none() && expected.outcome != actual.outcome {
            divergence = Some(Divergence {
                seq: session.position,
                divergence_type: DivergenceType::OutcomeMismatch {
                    expected: expected.outcome.clone(),
                    actual: actual.outcome.clone(),
                },
                expected: Some(expected.clone()),
                actual: Some(actual.clone()),
                detected_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64,
            });
        }

        // Check timing (if enabled)
        if divergence.is_none() && self.config.check_timing {
            let diff = if actual.duration_ns > expected.duration_ns {
                actual.duration_ns - expected.duration_ns
            } else {
                expected.duration_ns - actual.duration_ns
            };

            if diff > self.config.timing_tolerance_ns {
                divergence = Some(Divergence {
                    seq: session.position,
                    divergence_type: DivergenceType::TimingViolation {
                        expected_ns: expected.duration_ns,
                        actual_ns: actual.duration_ns,
                        threshold_ns: self.config.timing_tolerance_ns,
                    },
                    expected: Some(expected.clone()),
                    actual: Some(actual.clone()),
                    detected_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64,
                });
            }
        }

        if let Some(ref div) = divergence {
            self.divergences.push(div.clone());

            if self.config.stop_on_divergence {
                if let Some(session) = self.sessions.get_mut(session_id) {
                    session.diverge(format!("{:?}", div.divergence_type));
                }
            }
        }

        divergence
    }

    /// Create checkpoint
    pub fn create_checkpoint(&mut self, checkpoint_id: String, state: serde_json::Value) -> String {
        let seq = self.log.len() as u64;
        let checkpoint = ReplayCheckpoint {
            id: checkpoint_id.clone(),
            seq,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
            state,
        };

        self.checkpoints.insert(checkpoint_id.clone(), checkpoint);

        // Prune old checkpoints
        while self.checkpoints.len() > self.config.max_checkpoints {
            if let Some(oldest) = self.checkpoints.values().min_by_key(|c| c.seq).map(|c| c.id.clone()) {
                self.checkpoints.remove(&oldest);
            } else {
                break;
            }
        }

        checkpoint_id
    }

    /// Restore from checkpoint
    pub fn restore_checkpoint(&mut self, session_id: &str, checkpoint_id: &str) -> Option<&ReplayCheckpoint> {
        let checkpoint = self.checkpoints.get(checkpoint_id)?;
        
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.goto(checkpoint.seq);
            session.state = ReplayState::Paused;
        }

        Some(checkpoint)
    }

    /// Get session
    pub fn session(&self, session_id: &str) -> Option<&ReplaySession> {
        self.sessions.get(session_id)
    }

    /// Get log
    pub fn log(&self) -> &ReplayLog {
        &self.log
    }

    /// Get divergences
    pub fn divergences(&self) -> &[Divergence] {
        &self.divergences
    }

    /// Clear divergences
    pub fn clear_divergences(&mut self) {
        self.divergences.clear();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_event() {
        let event = ReplayEvent::new(
            1,
            "pid:001".to_string(),
            MemoryKernelOp::MemWrite,
            serde_json::json!({"key": "value"}),
        )
        .with_outcome(OpOutcome::Success, Some(serde_json::json!({"cid": "cid:001"})))
        .with_duration(1000);

        assert_eq!(event.seq, 1);
        assert_eq!(event.outcome, OpOutcome::Success);
        assert_eq!(event.duration_ns, 1000);
    }

    #[test]
    fn test_replay_log() {
        let mut log = ReplayLog::new();

        let event1 = ReplayEvent::new(0, "pid:001".to_string(), MemoryKernelOp::MemWrite, serde_json::json!({}));
        let event2 = ReplayEvent::new(0, "pid:001".to_string(), MemoryKernelOp::MemRead, serde_json::json!({}));
        let event3 = ReplayEvent::new(0, "pid:002".to_string(), MemoryKernelOp::MemWrite, serde_json::json!({}));

        log.record(event1);
        log.record(event2);
        log.record(event3);

        assert_eq!(log.len(), 3);
        assert_eq!(log.by_agent("pid:001").len(), 2);
        assert_eq!(log.by_agent("pid:002").len(), 1);
    }

    #[test]
    fn test_replay_session() {
        let mut session = ReplaySession::new_replay("session:001".to_string(), 100);
        
        assert_eq!(session.state, ReplayState::Idle);
        assert_eq!(session.position, 0);

        session.start();
        assert_eq!(session.state, ReplayState::Running);

        session.advance();
        assert_eq!(session.position, 1);

        session.add_breakpoint(5);
        while session.position < 5 {
            session.advance();
        }
        assert_eq!(session.state, ReplayState::Paused);

        session.resume();
        session.goto(50);
        assert_eq!(session.position, 50);
        assert_eq!(session.progress(), 50.0);
    }

    #[test]
    fn test_replay_engine() {
        let config = ReplayConfig::default();
        let mut engine = ReplayEngine::new(config);

        // Record events
        engine.start_recording("record:001".to_string());
        
        for i in 0..10 {
            let event = ReplayEvent::new(
                i,
                "pid:001".to_string(),
                MemoryKernelOp::MemWrite,
                serde_json::json!({"i": i}),
            );
            engine.record_event(event);
        }

        engine.stop_recording("record:001");
        assert_eq!(engine.log().len(), 10);

        // Replay
        engine.start_replay("replay:001".to_string());
        
        let event = engine.next_event("replay:001");
        assert!(event.is_some());
        assert_eq!(event.unwrap().seq, 0);

        engine.advance("replay:001");
        let event = engine.next_event("replay:001");
        assert_eq!(event.unwrap().seq, 1);
    }

    #[test]
    fn test_divergence_detection() {
        let config = ReplayConfig {
            stop_on_divergence: false,
            ..Default::default()
        };
        let mut engine = ReplayEngine::new(config);

        // Record
        engine.start_recording("record:001".to_string());
        let event = ReplayEvent::new(0, "pid:001".to_string(), MemoryKernelOp::MemWrite, serde_json::json!({}))
            .with_outcome(OpOutcome::Success, None);
        engine.record_event(event);
        engine.stop_recording("record:001");

        // Replay with different outcome
        engine.start_replay("replay:001".to_string());
        
        let actual = ReplayEvent::new(0, "pid:001".to_string(), MemoryKernelOp::MemWrite, serde_json::json!({}))
            .with_outcome(OpOutcome::Denied, None);

        let divergence = engine.check_divergence("replay:001", &actual);
        assert!(divergence.is_some());
        
        match divergence.unwrap().divergence_type {
            DivergenceType::OutcomeMismatch { expected, actual } => {
                assert_eq!(expected, OpOutcome::Success);
                assert_eq!(actual, OpOutcome::Denied);
            }
            _ => panic!("Expected OutcomeMismatch"),
        }
    }
}

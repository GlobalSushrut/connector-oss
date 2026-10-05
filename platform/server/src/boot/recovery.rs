//! Boot Failure Recovery — Automatic rollback and recovery mechanisms
//!
//! This module implements boot failure recovery:
//! - Checkpoint creation before each stage
//! - Automatic rollback on failure
//! - Recovery strategies per stage
//! - Boot attempt tracking and limits
//!
//! Design sources: systemd failure handling, Kubernetes pod restart policies

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{StageResult, BOOT_STAGE_NAMES, BOOT_STAGE_COUNT};

// =============================================================================
// Recovery Configuration
// =============================================================================

/// Recovery strategy for a stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStrategy {
    /// Retry the stage with exponential backoff
    Retry,
    /// Skip the stage and continue (if non-critical)
    Skip,
    /// Rollback to previous checkpoint
    Rollback,
    /// Abort boot entirely
    Abort,
    /// Run recovery action then retry
    RecoverAndRetry,
}

impl Default for RecoveryStrategy {
    fn default() -> Self {
        Self::Abort
    }
}

/// Stage criticality level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageCriticality {
    /// Stage must succeed for boot to continue
    Critical,
    /// Stage failure is logged but boot continues
    Optional,
    /// Stage can be deferred to post-boot
    Deferrable,
}

impl Default for StageCriticality {
    fn default() -> Self {
        Self::Critical
    }
}

/// Recovery configuration for a stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageRecoveryConfig {
    /// Stage number
    pub stage: u16,
    /// Stage name
    pub name: String,
    /// Criticality level
    pub criticality: StageCriticality,
    /// Primary recovery strategy
    pub strategy: RecoveryStrategy,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Retry delay (base, for exponential backoff)
    pub retry_delay_ms: u64,
    /// Timeout for the stage
    pub timeout_ms: u64,
    /// Recovery action (command or function name)
    pub recovery_action: Option<String>,
    /// Rollback action (command or function name)
    pub rollback_action: Option<String>,
}

impl StageRecoveryConfig {
    pub fn new(stage: u16) -> Self {
        let name = BOOT_STAGE_NAMES.get(stage as usize)
            .unwrap_or(&"UNKNOWN")
            .to_string();

        Self {
            stage,
            name,
            criticality: StageCriticality::Critical,
            strategy: RecoveryStrategy::Retry,
            max_retries: 3,
            retry_delay_ms: 1000,
            timeout_ms: 30000,
            recovery_action: None,
            rollback_action: None,
        }
    }

    pub fn critical(mut self) -> Self {
        self.criticality = StageCriticality::Critical;
        self
    }

    pub fn optional(mut self) -> Self {
        self.criticality = StageCriticality::Optional;
        self.strategy = RecoveryStrategy::Skip;
        self
    }

    pub fn deferrable(mut self) -> Self {
        self.criticality = StageCriticality::Deferrable;
        self.strategy = RecoveryStrategy::Skip;
        self
    }

    pub fn with_strategy(mut self, strategy: RecoveryStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    pub fn with_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn with_recovery_action(mut self, action: &str) -> Self {
        self.recovery_action = Some(action.into());
        self
    }

    pub fn with_rollback_action(mut self, action: &str) -> Self {
        self.rollback_action = Some(action.into());
        self
    }
}

// =============================================================================
// Boot Checkpoint
// =============================================================================

/// Boot checkpoint for rollback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootCheckpoint {
    /// Checkpoint ID
    pub id: String,
    /// Stage number this checkpoint was taken before
    pub before_stage: u16,
    /// Timestamp
    pub created_at: i64,
    /// State snapshot (serialized)
    pub state: HashMap<String, String>,
    /// Files backed up
    pub backed_up_files: Vec<String>,
}

impl BootCheckpoint {
    pub fn new(before_stage: u16) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            id: format!("ckpt-{}-{}", before_stage, now),
            before_stage,
            created_at: now,
            state: HashMap::new(),
            backed_up_files: vec![],
        }
    }

    pub fn save_state(&mut self, key: &str, value: &str) {
        self.state.insert(key.into(), value.into());
    }

    pub fn get_state(&self, key: &str) -> Option<&str> {
        self.state.get(key).map(|s| s.as_str())
    }

    pub fn add_backup_file(&mut self, path: &str) {
        self.backed_up_files.push(path.into());
    }
}

// =============================================================================
// Boot Attempt
// =============================================================================

/// Record of a boot attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootAttempt {
    /// Attempt number
    pub attempt: u32,
    /// Start timestamp
    pub started_at: i64,
    /// End timestamp
    pub ended_at: Option<i64>,
    /// Success flag
    pub success: bool,
    /// Failed stage (if any)
    pub failed_stage: Option<u16>,
    /// Error message
    pub error: Option<String>,
    /// Stage results
    pub stages: Vec<StageAttemptResult>,
}

/// Result of a stage attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageAttemptResult {
    pub stage: u16,
    pub attempt: u32,
    pub success: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub recovery_action_taken: Option<String>,
}

impl BootAttempt {
    pub fn new(attempt: u32) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            attempt,
            started_at: now,
            ended_at: None,
            success: false,
            failed_stage: None,
            error: None,
            stages: vec![],
        }
    }

    pub fn record_stage(&mut self, result: StageAttemptResult) {
        self.stages.push(result);
    }

    pub fn complete(&mut self, success: bool) {
        self.ended_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64
        );
        self.success = success;
    }

    pub fn fail(&mut self, stage: u16, error: &str) {
        self.complete(false);
        self.failed_stage = Some(stage);
        self.error = Some(error.into());
    }
}

// =============================================================================
// Recovery Manager
// =============================================================================

/// Boot recovery manager
pub struct RecoveryManager {
    /// Recovery configuration per stage
    configs: HashMap<u16, StageRecoveryConfig>,
    /// Checkpoints
    checkpoints: Vec<BootCheckpoint>,
    /// Boot attempts
    attempts: Vec<BootAttempt>,
    /// Current attempt
    current_attempt: Option<BootAttempt>,
    /// Maximum boot attempts before giving up
    max_boot_attempts: u32,
    /// Data directory for checkpoint storage
    data_dir: String,
    /// Recovery actions registry
    recovery_actions: HashMap<String, Box<dyn Fn() -> Result<(), String> + Send + Sync>>,
}

impl RecoveryManager {
    pub fn new(data_dir: &str) -> Self {
        let mut manager = Self {
            configs: HashMap::new(),
            checkpoints: vec![],
            attempts: vec![],
            current_attempt: None,
            max_boot_attempts: 3,
            data_dir: data_dir.into(),
            recovery_actions: HashMap::new(),
        };

        // Register default configurations
        manager.register_default_configs();

        manager
    }

    fn register_default_configs(&mut self) {
        // Stage 0: IDENTITY - Critical, retry
        self.configs.insert(0, StageRecoveryConfig::new(0)
            .critical()
            .with_strategy(RecoveryStrategy::Retry)
            .with_retries(3));

        // Stage 1: CONFIG - Critical, retry with recovery
        self.configs.insert(1, StageRecoveryConfig::new(1)
            .critical()
            .with_strategy(RecoveryStrategy::RecoverAndRetry)
            .with_recovery_action("reset_config"));

        // Stage 2: SECRETS - Critical, retry
        self.configs.insert(2, StageRecoveryConfig::new(2)
            .critical()
            .with_strategy(RecoveryStrategy::Retry)
            .with_retries(3));

        // Stage 3: STORAGE - Critical, rollback on failure
        self.configs.insert(3, StageRecoveryConfig::new(3)
            .critical()
            .with_strategy(RecoveryStrategy::Rollback)
            .with_rollback_action("restore_storage_backup"));

        // Stage 4: KERNEL - Critical, rollback
        self.configs.insert(4, StageRecoveryConfig::new(4)
            .critical()
            .with_strategy(RecoveryStrategy::Rollback)
            .with_rollback_action("restore_kernel_state"));

        // Stage 5: POLICIES - Optional, can skip
        self.configs.insert(5, StageRecoveryConfig::new(5)
            .optional()
            .with_strategy(RecoveryStrategy::Skip));

        // Stage 6: SCHEDULER - Optional, can skip
        self.configs.insert(6, StageRecoveryConfig::new(6)
            .optional()
            .with_strategy(RecoveryStrategy::Skip));

        // Stage 7: CAPABILITIES - Critical, retry
        self.configs.insert(7, StageRecoveryConfig::new(7)
            .critical()
            .with_strategy(RecoveryStrategy::Retry)
            .with_retries(2));

        // Stage 8: RESTORE - Deferrable, can skip
        self.configs.insert(8, StageRecoveryConfig::new(8)
            .deferrable()
            .with_strategy(RecoveryStrategy::Skip));

        // Stage 9: SERVICES - Optional, can skip
        self.configs.insert(9, StageRecoveryConfig::new(9)
            .optional()
            .with_strategy(RecoveryStrategy::Skip));

        // Stage 10: ACCESS - Critical, retry
        self.configs.insert(10, StageRecoveryConfig::new(10)
            .critical()
            .with_strategy(RecoveryStrategy::Retry)
            .with_retries(5)
            .with_timeout(60000));

        // Stage 11: READY - Always succeeds if we get here
        self.configs.insert(11, StageRecoveryConfig::new(11)
            .critical()
            .with_strategy(RecoveryStrategy::Retry));
    }

    /// Start a new boot attempt
    pub fn start_boot(&mut self) -> Result<u32, String> {
        let attempt_num = self.attempts.len() as u32 + 1;

        if attempt_num > self.max_boot_attempts {
            return Err(format!(
                "Maximum boot attempts ({}) exceeded",
                self.max_boot_attempts
            ));
        }

        let attempt = BootAttempt::new(attempt_num);
        self.current_attempt = Some(attempt);

        tracing::info!("Starting boot attempt {}/{}", attempt_num, self.max_boot_attempts);

        Ok(attempt_num)
    }

    /// Create a checkpoint before a stage
    pub fn checkpoint(&mut self, before_stage: u16) -> BootCheckpoint {
        let checkpoint = BootCheckpoint::new(before_stage);
        self.checkpoints.push(checkpoint.clone());

        tracing::debug!("Created checkpoint {} before stage {}", checkpoint.id, before_stage);

        checkpoint
    }

    /// Handle a stage failure
    pub fn handle_failure(&mut self, stage: u16, error: &str) -> RecoveryAction {
        let config = self.configs.get(&stage)
            .cloned()
            .unwrap_or_else(|| StageRecoveryConfig::new(stage));

        tracing::warn!(
            "Stage {} ({}) failed: {}. Strategy: {:?}",
            stage, config.name, error, config.strategy
        );

        // Record the failure (BF2-O06: per-stage attempt index within this boot attempt)
        if let Some(ref mut attempt) = self.current_attempt {
            let attempt_no = attempt
                .stages
                .iter()
                .filter(|s| s.stage == stage)
                .count() as u32
                + 1;
            attempt.record_stage(StageAttemptResult {
                stage,
                attempt: attempt_no,
                success: false,
                duration_ms: 0,
                error: Some(error.into()),
                recovery_action_taken: None,
            });
        }

        match config.criticality {
            StageCriticality::Optional | StageCriticality::Deferrable => {
                tracing::info!("Stage {} is {:?}, continuing boot", stage, config.criticality);
                return RecoveryAction::Continue;
            }
            StageCriticality::Critical => {
                // Apply recovery strategy
            }
        }

        match config.strategy {
            RecoveryStrategy::Retry => {
                RecoveryAction::Retry {
                    max_attempts: config.max_retries,
                    delay: Duration::from_millis(config.retry_delay_ms),
                }
            }
            RecoveryStrategy::Skip => {
                RecoveryAction::Continue
            }
            RecoveryStrategy::Rollback => {
                if let Some(checkpoint) = self.find_checkpoint_before(stage) {
                    RecoveryAction::Rollback {
                        checkpoint_id: checkpoint.id.clone(),
                        restart_from_stage: checkpoint.before_stage,
                    }
                } else {
                    RecoveryAction::Abort {
                        reason: format!("No checkpoint available for rollback from stage {}", stage),
                    }
                }
            }
            RecoveryStrategy::Abort => {
                RecoveryAction::Abort {
                    reason: format!("Stage {} failed: {}", stage, error),
                }
            }
            RecoveryStrategy::RecoverAndRetry => {
                if let Some(action) = &config.recovery_action {
                    RecoveryAction::RunRecoveryAction {
                        action: action.clone(),
                        then_retry: true,
                    }
                } else {
                    RecoveryAction::Retry {
                        max_attempts: config.max_retries,
                        delay: Duration::from_millis(config.retry_delay_ms),
                    }
                }
            }
        }
    }

    /// Find the most recent checkpoint before a stage
    fn find_checkpoint_before(&self, stage: u16) -> Option<&BootCheckpoint> {
        self.checkpoints.iter()
            .rev()
            .find(|c| c.before_stage < stage)
    }

    /// Execute a rollback to a checkpoint
    pub fn rollback(&mut self, checkpoint_id: &str) -> Result<u16, String> {
        let checkpoint = self.checkpoints.iter()
            .find(|c| c.id == checkpoint_id)
            .ok_or_else(|| format!("Checkpoint {} not found", checkpoint_id))?;

        tracing::info!("Rolling back to checkpoint {} (stage {})", checkpoint_id, checkpoint.before_stage);

        // Restore backed up files
        for file in &checkpoint.backed_up_files {
            let backup_path = format!("{}.bak", file);
            if Path::new(&backup_path).exists() {
                if let Err(e) = std::fs::copy(&backup_path, file) {
                    tracing::warn!("Failed to restore {}: {}", file, e);
                }
            }
        }

        // Clear checkpoints after this one
        let restart_stage = checkpoint.before_stage;
        self.checkpoints.retain(|c| c.before_stage <= restart_stage);

        Ok(restart_stage)
    }

    /// Register a recovery action
    pub fn register_action<F>(&mut self, name: &str, action: F)
    where
        F: Fn() -> Result<(), String> + Send + Sync + 'static,
    {
        self.recovery_actions.insert(name.into(), Box::new(action));
    }

    /// Execute a recovery action
    pub fn execute_action(&self, name: &str) -> Result<(), String> {
        if let Some(action) = self.recovery_actions.get(name) {
            tracing::info!("Executing recovery action: {}", name);
            action()
        } else {
            Err(format!("Recovery action '{}' not registered", name))
        }
    }

    /// Complete the current boot attempt
    pub fn complete_boot(&mut self, success: bool) {
        if let Some(mut attempt) = self.current_attempt.take() {
            attempt.complete(success);
            self.attempts.push(attempt);
        }

        if success {
            // Clear checkpoints on successful boot
            self.checkpoints.clear();
            tracing::info!("Boot completed successfully");
        }
    }

    /// Get boot attempt history
    pub fn attempts(&self) -> &[BootAttempt] {
        &self.attempts
    }

    /// Get configuration for a stage
    pub fn get_config(&self, stage: u16) -> Option<&StageRecoveryConfig> {
        self.configs.get(&stage)
    }

    /// Set configuration for a stage
    pub fn set_config(&mut self, config: StageRecoveryConfig) {
        self.configs.insert(config.stage, config);
    }

    /// Persist recovery state to disk
    pub fn persist(&self) -> Result<(), String> {
        let state = RecoveryState {
            attempts: self.attempts.clone(),
            checkpoints: self.checkpoints.clone(),
        };

        let path = format!("{}/boot_recovery.json", self.data_dir);
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| format!("Failed to serialize: {}", e))?;

        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to write {}: {}", path, e))?;

        Ok(())
    }

    /// Load recovery state from disk
    pub fn load(&mut self) -> Result<(), String> {
        let path = format!("{}/boot_recovery.json", self.data_dir);

        if !Path::new(&path).exists() {
            return Ok(());
        }

        let json = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read {}: {}", path, e))?;

        let state: RecoveryState = serde_json::from_str(&json)
            .map_err(|e| format!("Failed to parse: {}", e))?;

        self.attempts = state.attempts;
        self.checkpoints = state.checkpoints;

        Ok(())
    }
}

/// Recovery action to take
#[derive(Debug, Clone)]
pub enum RecoveryAction {
    /// Continue to next stage (skip failure)
    Continue,
    /// Retry the stage
    Retry {
        max_attempts: u32,
        delay: Duration,
    },
    /// Rollback to checkpoint
    Rollback {
        checkpoint_id: String,
        restart_from_stage: u16,
    },
    /// Run a recovery action then retry
    RunRecoveryAction {
        action: String,
        then_retry: bool,
    },
    /// Abort boot
    Abort {
        reason: String,
    },
}

/// Persisted recovery state
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryState {
    attempts: Vec<BootAttempt>,
    checkpoints: Vec<BootCheckpoint>,
}

// =============================================================================
// Stage Executor with Recovery
// =============================================================================

/// Execute a stage with recovery handling
pub struct StageExecutor<'a> {
    recovery: &'a mut RecoveryManager,
    stage: u16,
    attempts: u32,
    max_attempts: u32,
}

impl<'a> StageExecutor<'a> {
    pub fn new(recovery: &'a mut RecoveryManager, stage: u16) -> Self {
        let max_attempts = recovery.get_config(stage)
            .map(|c| c.max_retries)
            .unwrap_or(3);

        Self {
            recovery,
            stage,
            attempts: 0,
            max_attempts,
        }
    }

    /// Execute the stage with automatic retry
    pub fn execute<F, T>(&mut self, f: F) -> Result<T, String>
    where
        F: Fn() -> Result<T, String>,
    {
        // Create checkpoint before stage
        self.recovery.checkpoint(self.stage);

        loop {
            self.attempts += 1;

            match f() {
                Ok(result) => {
                    return Ok(result);
                }
                Err(error) => {
                    let action = self.recovery.handle_failure(self.stage, &error);

                    match action {
                        RecoveryAction::Continue => {
                            return Err(error); // Let caller handle skip
                        }
                        RecoveryAction::Retry { max_attempts, delay } => {
                            if self.attempts >= max_attempts {
                                return Err(format!(
                                    "Stage {} failed after {} attempts: {}",
                                    self.stage, self.attempts, error
                                ));
                            }
                            tracing::info!(
                                "Retrying stage {} (attempt {}/{})",
                                self.stage, self.attempts + 1, max_attempts
                            );
                            std::thread::sleep(delay);
                        }
                        RecoveryAction::Rollback { checkpoint_id, restart_from_stage } => {
                            self.recovery.rollback(&checkpoint_id)?;
                            return Err(format!(
                                "Rolled back to stage {}",
                                restart_from_stage
                            ));
                        }
                        RecoveryAction::RunRecoveryAction { action, then_retry } => {
                            if let Err(e) = self.recovery.execute_action(&action) {
                                tracing::warn!("Recovery action failed: {}", e);
                            }
                            if !then_retry || self.attempts >= self.max_attempts {
                                return Err(error);
                            }
                        }
                        RecoveryAction::Abort { reason } => {
                            return Err(reason);
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_config() {
        let config = StageRecoveryConfig::new(3)
            .critical()
            .with_strategy(RecoveryStrategy::Rollback)
            .with_retries(5);

        assert_eq!(config.stage, 3);
        assert_eq!(config.criticality, StageCriticality::Critical);
        assert_eq!(config.strategy, RecoveryStrategy::Rollback);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_checkpoint() {
        let mut checkpoint = BootCheckpoint::new(3);
        checkpoint.save_state("key", "value");
        checkpoint.add_backup_file("/path/to/file");

        assert_eq!(checkpoint.before_stage, 3);
        assert_eq!(checkpoint.get_state("key"), Some("value"));
        assert!(checkpoint.backed_up_files.contains(&"/path/to/file".to_string()));
    }

    #[test]
    fn test_boot_attempt() {
        let mut attempt = BootAttempt::new(1);

        attempt.record_stage(StageAttemptResult {
            stage: 0,
            attempt: 1,
            success: true,
            duration_ms: 100,
            error: None,
            recovery_action_taken: None,
        });

        attempt.complete(true);

        assert!(attempt.success);
        assert!(attempt.ended_at.is_some());
        assert_eq!(attempt.stages.len(), 1);
    }

    #[test]
    fn test_recovery_manager() {
        let mut manager = RecoveryManager::new("/tmp/test");

        // Start boot
        let attempt = manager.start_boot().unwrap();
        assert_eq!(attempt, 1);

        // Create checkpoint
        let checkpoint = manager.checkpoint(3);
        assert_eq!(checkpoint.before_stage, 3);

        // Handle optional stage failure
        let action = manager.handle_failure(5, "test error");
        assert!(matches!(action, RecoveryAction::Continue));

        // Handle critical stage failure
        let action = manager.handle_failure(0, "test error");
        assert!(matches!(action, RecoveryAction::Retry { .. }));
    }

    #[test]
    fn test_recovery_action_types() {
        let mut manager = RecoveryManager::new("/tmp/test");

        // Test rollback strategy
        manager.checkpoint(0);
        manager.checkpoint(2);

        let config = StageRecoveryConfig::new(3)
            .critical()
            .with_strategy(RecoveryStrategy::Rollback);
        manager.set_config(config);

        let action = manager.handle_failure(3, "storage error");
        assert!(
            matches!(
                action,
                RecoveryAction::Rollback { restart_from_stage, .. } if restart_from_stage == 2
            ),
            "expected Rollback to stage 2, got {:?}",
            action
        );
    }
}

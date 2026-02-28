//! Context Manager — higher-level LLM context lifecycle management.
//!
//! Wraps the kernel's low-level context syscalls (UpdateContext, TrimContextWindow,
//! GetContextPressure) with snapshot/restore/compress semantics.
//!
//! Provides:
//! - `snapshot()` — serialize ExecutionContext + context window to content-addressed store
//! - `restore()` — reconstruct agent context from a snapshot CID
//! - `compress()` — summarize/truncate context window to free tokens
//! - `evict()` / `resume()` — suspend agent context to cold storage and restore later
//!
//! Analogous to: Linux process hibernation (CRIU), memory-mapped file snapshots

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Context Snapshot
// ═══════════════════════════════════════════════════════════════

/// A content-addressed snapshot of an agent's execution context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextSnapshot {
    /// Content-addressed ID (SHA256 of canonical bytes)
    pub snapshot_cid: String,
    /// Agent PID this snapshot belongs to
    pub agent_pid: String,
    /// Context window CIDs at snapshot time
    pub context_window: Vec<String>,
    /// Token count at snapshot time
    pub context_tokens: u64,
    /// Max tokens at snapshot time
    pub context_max_tokens: u64,
    /// Reasoning chain CIDs
    pub reasoning_chain: Vec<String>,
    /// Step counter
    pub step_counter: u64,
    /// Session ID
    pub session_id: String,
    /// Pipeline ID
    pub pipeline_id: String,
    /// Snapshot timestamp (ms epoch)
    pub created_at_ms: u64,
    /// Optional summary of compressed/evicted content
    pub summary: Option<String>,
    /// Whether this snapshot was created by eviction
    pub evicted: bool,
}

impl ContextSnapshot {
    /// Compute the content-addressed CID for this snapshot.
    fn compute_cid(&self) -> String {
        let canonical = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.agent_pid,
            self.session_id,
            self.pipeline_id,
            self.step_counter,
            self.context_tokens,
            self.context_window.join(","),
            self.created_at_ms,
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        format!("snap:{}", hex::encode(&hasher.finalize()[..16]))
    }
}

// ═══════════════════════════════════════════════════════════════
// Compression Strategy
// ═══════════════════════════════════════════════════════════════

/// How to compress/truncate context when pressure is high.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionStrategy {
    /// Remove oldest entries first (FIFO eviction)
    TruncateOldest,
    /// Keep first and last N entries, remove middle
    KeepEnds,
    /// Summarize and replace with a single summary entry
    Summarize,
}

// ═══════════════════════════════════════════════════════════════
// Context Manager
// ═══════════════════════════════════════════════════════════════

/// Higher-level context management for agent LLM state.
///
/// Sits above the kernel's context syscalls and provides snapshot/restore
/// and compression lifecycle.
pub struct ContextManager {
    /// In-memory snapshot store (CID → snapshot)
    snapshots: HashMap<String, ContextSnapshot>,
    /// Active contexts per agent (agent_pid → live context state)
    contexts: HashMap<String, LiveContext>,
    /// Default compression strategy
    pub default_strategy: CompressionStrategy,
    /// Default max tokens for new contexts
    pub default_max_tokens: u64,
}

/// Live context state tracked by the manager.
#[derive(Debug, Clone)]
pub struct LiveContext {
    pub agent_pid: String,
    pub session_id: String,
    pub pipeline_id: String,
    pub step_counter: u64,
    pub context_window: Vec<String>,
    pub context_tokens: u64,
    pub context_max_tokens: u64,
    pub reasoning_chain: Vec<String>,
}

impl LiveContext {
    pub fn new(agent_pid: impl Into<String>, session_id: impl Into<String>, max_tokens: u64) -> Self {
        Self {
            agent_pid: agent_pid.into(),
            session_id: session_id.into(),
            pipeline_id: String::new(),
            step_counter: 0,
            context_window: Vec::new(),
            context_tokens: 0,
            context_max_tokens: max_tokens,
            reasoning_chain: Vec::new(),
        }
    }

    /// Context pressure as a percentage (0.0–1.0).
    pub fn pressure(&self) -> f64 {
        if self.context_max_tokens == 0 { return 0.0; }
        self.context_tokens as f64 / self.context_max_tokens as f64
    }
}

impl ContextManager {
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            contexts: HashMap::new(),
            default_strategy: CompressionStrategy::TruncateOldest,
            default_max_tokens: 128_000,
        }
    }

    /// Register a new live context for an agent.
    pub fn register(&mut self, agent_pid: impl Into<String>, session_id: impl Into<String>) {
        let pid = agent_pid.into();
        let ctx = LiveContext::new(pid.clone(), session_id, self.default_max_tokens);
        self.contexts.insert(pid, ctx);
    }

    /// Get a reference to a live context.
    pub fn get(&self, agent_pid: &str) -> Option<&LiveContext> {
        self.contexts.get(agent_pid)
    }

    /// Get a mutable reference to a live context.
    pub fn get_mut(&mut self, agent_pid: &str) -> Option<&mut LiveContext> {
        self.contexts.get_mut(agent_pid)
    }

    /// Add CIDs to an agent's context window and update token count.
    pub fn update(&mut self, agent_pid: &str, cids: Vec<String>, token_delta: i64) -> Result<(), String> {
        let ctx = self.contexts.get_mut(agent_pid)
            .ok_or_else(|| format!("No context for agent {}", agent_pid))?;
        for cid in cids {
            if !ctx.context_window.contains(&cid) {
                ctx.context_window.push(cid);
            }
        }
        if token_delta >= 0 {
            ctx.context_tokens = ctx.context_tokens.saturating_add(token_delta as u64);
        } else {
            ctx.context_tokens = ctx.context_tokens.saturating_sub((-token_delta) as u64);
        }
        ctx.step_counter += 1;
        Ok(())
    }

    /// Snapshot an agent's context — returns the snapshot CID.
    pub fn snapshot(&mut self, agent_pid: &str, now_ms: u64) -> Result<String, String> {
        let ctx = self.contexts.get(agent_pid)
            .ok_or_else(|| format!("No context for agent {}", agent_pid))?;

        let mut snap = ContextSnapshot {
            snapshot_cid: String::new(),
            agent_pid: ctx.agent_pid.clone(),
            context_window: ctx.context_window.clone(),
            context_tokens: ctx.context_tokens,
            context_max_tokens: ctx.context_max_tokens,
            reasoning_chain: ctx.reasoning_chain.clone(),
            step_counter: ctx.step_counter,
            session_id: ctx.session_id.clone(),
            pipeline_id: ctx.pipeline_id.clone(),
            created_at_ms: now_ms,
            summary: None,
            evicted: false,
        };
        snap.snapshot_cid = snap.compute_cid();
        let cid = snap.snapshot_cid.clone();
        self.snapshots.insert(cid.clone(), snap);
        Ok(cid)
    }

    /// Restore an agent's context from a snapshot CID.
    pub fn restore(&mut self, snapshot_cid: &str) -> Result<String, String> {
        let snap = self.snapshots.get(snapshot_cid)
            .ok_or_else(|| format!("Snapshot not found: {}", snapshot_cid))?
            .clone();

        let ctx = LiveContext {
            agent_pid: snap.agent_pid.clone(),
            session_id: snap.session_id.clone(),
            pipeline_id: snap.pipeline_id.clone(),
            step_counter: snap.step_counter,
            context_window: snap.context_window,
            context_tokens: snap.context_tokens,
            context_max_tokens: snap.context_max_tokens,
            reasoning_chain: snap.reasoning_chain,
        };
        let pid = ctx.agent_pid.clone();
        self.contexts.insert(pid.clone(), ctx);
        Ok(pid)
    }

    /// Compress an agent's context window to free tokens.
    pub fn compress(
        &mut self,
        agent_pid: &str,
        tokens_to_free: u64,
        strategy: Option<CompressionStrategy>,
    ) -> Result<CompressResult, String> {
        let ctx = self.contexts.get_mut(agent_pid)
            .ok_or_else(|| format!("No context for agent {}", agent_pid))?;

        let strategy = strategy.unwrap_or(self.default_strategy);
        let before_tokens = ctx.context_tokens;
        let before_window = ctx.context_window.len();

        if ctx.context_window.is_empty() || ctx.context_tokens == 0 {
            return Ok(CompressResult {
                evicted_cids: vec![],
                tokens_freed: 0,
                strategy,
            });
        }

        // Estimate tokens per CID
        let tokens_per_cid = if before_window > 0 {
            (ctx.context_tokens as f64 / before_window as f64).ceil() as u64
        } else {
            0
        };

        let mut evicted_cids = Vec::new();
        let mut freed = 0u64;

        match strategy {
            CompressionStrategy::TruncateOldest => {
                while freed < tokens_to_free && !ctx.context_window.is_empty() {
                    let removed = ctx.context_window.remove(0);
                    evicted_cids.push(removed);
                    freed += tokens_per_cid;
                }
            }
            CompressionStrategy::KeepEnds => {
                // Keep first 25% and last 25%, remove middle 50%
                let keep = (ctx.context_window.len() / 4).max(1);
                if ctx.context_window.len() > keep * 2 {
                    let middle: Vec<String> = ctx.context_window[keep..ctx.context_window.len() - keep].to_vec();
                    for cid in &middle {
                        freed += tokens_per_cid;
                        evicted_cids.push(cid.clone());
                    }
                    let head = ctx.context_window[..keep].to_vec();
                    let tail = ctx.context_window[ctx.context_window.len() - keep..].to_vec();
                    ctx.context_window = [head, tail].concat();
                }
            }
            CompressionStrategy::Summarize => {
                // Remove all but the last entry, replace freed tokens
                while ctx.context_window.len() > 1 {
                    let removed = ctx.context_window.remove(0);
                    evicted_cids.push(removed);
                    freed += tokens_per_cid;
                }
            }
        }

        ctx.context_tokens = ctx.context_tokens.saturating_sub(freed);
        let actual_freed = before_tokens.saturating_sub(ctx.context_tokens);

        Ok(CompressResult {
            evicted_cids,
            tokens_freed: actual_freed,
            strategy,
        })
    }

    /// Evict an agent's context to snapshot store (suspend).
    pub fn evict(&mut self, agent_pid: &str, now_ms: u64) -> Result<String, String> {
        let cid = self.snapshot(agent_pid, now_ms)?;
        // Mark the snapshot as evicted
        if let Some(snap) = self.snapshots.get_mut(&cid) {
            snap.evicted = true;
        }
        // Remove the live context
        self.contexts.remove(agent_pid);
        Ok(cid)
    }

    /// Resume an agent from an evicted snapshot.
    pub fn resume(&mut self, snapshot_cid: &str) -> Result<String, String> {
        let snap = self.snapshots.get(snapshot_cid)
            .ok_or_else(|| format!("Snapshot not found: {}", snapshot_cid))?;
        if !snap.evicted {
            return Err(format!("Snapshot {} was not evicted", snapshot_cid));
        }
        self.restore(snapshot_cid)
    }

    /// Get a stored snapshot.
    pub fn get_snapshot(&self, cid: &str) -> Option<&ContextSnapshot> {
        self.snapshots.get(cid)
    }

    /// Total snapshot count.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Active context count.
    pub fn context_count(&self) -> usize {
        self.contexts.len()
    }
}

/// Result of a compress operation.
#[derive(Debug, Clone)]
pub struct CompressResult {
    pub evicted_cids: Vec<String>,
    pub tokens_freed: u64,
    pub strategy: CompressionStrategy,
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_manager_with_agent(pid: &str) -> ContextManager {
        let mut mgr = ContextManager::new();
        mgr.register(pid, "session:001");
        mgr
    }

    #[test]
    fn test_register_and_get_context() {
        let mgr = setup_manager_with_agent("pid:a");
        let ctx = mgr.get("pid:a").unwrap();
        assert_eq!(ctx.agent_pid, "pid:a");
        assert_eq!(ctx.session_id, "session:001");
        assert_eq!(ctx.context_tokens, 0);
        assert_eq!(ctx.context_max_tokens, 128_000);
    }

    #[test]
    fn test_update_adds_cids_and_tokens() {
        let mut mgr = setup_manager_with_agent("pid:a");
        mgr.update("pid:a", vec!["cid:1".into(), "cid:2".into()], 500).unwrap();
        let ctx = mgr.get("pid:a").unwrap();
        assert_eq!(ctx.context_window.len(), 2);
        assert_eq!(ctx.context_tokens, 500);
        assert_eq!(ctx.step_counter, 1);

        // Duplicate CID not added
        mgr.update("pid:a", vec!["cid:1".into(), "cid:3".into()], 200).unwrap();
        let ctx = mgr.get("pid:a").unwrap();
        assert_eq!(ctx.context_window.len(), 3); // cid:1 not duplicated
        assert_eq!(ctx.context_tokens, 700);
    }

    #[test]
    fn test_snapshot_roundtrip() {
        let mut mgr = setup_manager_with_agent("pid:a");
        mgr.update("pid:a", vec!["cid:1".into(), "cid:2".into()], 1000).unwrap();

        let snap_cid = mgr.snapshot("pid:a", 5000).unwrap();
        assert!(snap_cid.starts_with("snap:"));

        let snap = mgr.get_snapshot(&snap_cid).unwrap();
        assert_eq!(snap.agent_pid, "pid:a");
        assert_eq!(snap.context_tokens, 1000);
        assert_eq!(snap.context_window.len(), 2);
        assert_eq!(snap.created_at_ms, 5000);
        assert!(!snap.evicted);
    }

    #[test]
    fn test_snapshot_cid_is_content_addressed() {
        let mut mgr = setup_manager_with_agent("pid:a");
        mgr.update("pid:a", vec!["cid:1".into()], 500).unwrap();

        let cid1 = mgr.snapshot("pid:a", 1000).unwrap();
        let cid2 = mgr.snapshot("pid:a", 1000).unwrap();
        // Same content + same timestamp → same CID
        assert_eq!(cid1, cid2);

        // Different timestamp → different CID
        let cid3 = mgr.snapshot("pid:a", 2000).unwrap();
        assert_ne!(cid1, cid3);
    }

    #[test]
    fn test_restore_from_snapshot() {
        let mut mgr = setup_manager_with_agent("pid:a");
        mgr.update("pid:a", vec!["cid:1".into(), "cid:2".into()], 800).unwrap();
        let snap_cid = mgr.snapshot("pid:a", 5000).unwrap();

        // Modify the live context
        mgr.update("pid:a", vec!["cid:3".into()], 500).unwrap();
        let ctx = mgr.get("pid:a").unwrap();
        assert_eq!(ctx.context_window.len(), 3);
        assert_eq!(ctx.context_tokens, 1300);

        // Restore from snapshot — reverts to snapshot state
        mgr.restore(&snap_cid).unwrap();
        let ctx = mgr.get("pid:a").unwrap();
        assert_eq!(ctx.context_window.len(), 2);
        assert_eq!(ctx.context_tokens, 800);
    }

    #[test]
    fn test_compress_truncate_oldest() {
        let mut mgr = setup_manager_with_agent("pid:a");
        mgr.update("pid:a", vec![
            "cid:1".into(), "cid:2".into(), "cid:3".into(), "cid:4".into(),
        ], 4000).unwrap();

        let result = mgr.compress("pid:a", 2000, Some(CompressionStrategy::TruncateOldest)).unwrap();
        assert_eq!(result.evicted_cids.len(), 2); // 2 × 1000 tokens each
        assert_eq!(result.evicted_cids[0], "cid:1");
        assert_eq!(result.evicted_cids[1], "cid:2");
        assert_eq!(result.tokens_freed, 2000);

        let ctx = mgr.get("pid:a").unwrap();
        assert_eq!(ctx.context_window, vec!["cid:3", "cid:4"]);
        assert_eq!(ctx.context_tokens, 2000);
    }

    #[test]
    fn test_compress_keep_ends() {
        let mut mgr = setup_manager_with_agent("pid:a");
        // 8 CIDs, 8000 tokens
        let cids: Vec<String> = (1..=8).map(|i| format!("cid:{}", i)).collect();
        mgr.update("pid:a", cids, 8000).unwrap();

        let result = mgr.compress("pid:a", 4000, Some(CompressionStrategy::KeepEnds)).unwrap();
        // Keep first 2 and last 2, evict middle 4
        assert_eq!(result.evicted_cids.len(), 4);
        let ctx = mgr.get("pid:a").unwrap();
        assert_eq!(ctx.context_window, vec!["cid:1", "cid:2", "cid:7", "cid:8"]);
    }

    #[test]
    fn test_evict_and_resume() {
        let mut mgr = setup_manager_with_agent("pid:a");
        mgr.update("pid:a", vec!["cid:1".into()], 1000).unwrap();

        // Evict — removes live context
        let snap_cid = mgr.evict("pid:a", 5000).unwrap();
        assert!(mgr.get("pid:a").is_none());
        assert_eq!(mgr.context_count(), 0);

        let snap = mgr.get_snapshot(&snap_cid).unwrap();
        assert!(snap.evicted);

        // Resume — restores live context
        let pid = mgr.resume(&snap_cid).unwrap();
        assert_eq!(pid, "pid:a");
        let ctx = mgr.get("pid:a").unwrap();
        assert_eq!(ctx.context_tokens, 1000);
        assert_eq!(ctx.context_window, vec!["cid:1"]);
    }

    #[test]
    fn test_multi_agent_isolation() {
        let mut mgr = ContextManager::new();
        mgr.register("pid:a", "sess:a");
        mgr.register("pid:b", "sess:b");

        mgr.update("pid:a", vec!["cid:a1".into()], 500).unwrap();
        mgr.update("pid:b", vec!["cid:b1".into(), "cid:b2".into()], 1200).unwrap();

        let ctx_a = mgr.get("pid:a").unwrap();
        let ctx_b = mgr.get("pid:b").unwrap();
        assert_eq!(ctx_a.context_window.len(), 1);
        assert_eq!(ctx_b.context_window.len(), 2);
        assert_eq!(ctx_a.context_tokens, 500);
        assert_eq!(ctx_b.context_tokens, 1200);

        // Snapshot A doesn't affect B
        let snap_a = mgr.snapshot("pid:a", 1000).unwrap();
        mgr.update("pid:a", vec!["cid:a2".into()], 300).unwrap();
        mgr.restore(&snap_a).unwrap();

        let ctx_a = mgr.get("pid:a").unwrap();
        let ctx_b = mgr.get("pid:b").unwrap();
        assert_eq!(ctx_a.context_tokens, 500); // Restored
        assert_eq!(ctx_b.context_tokens, 1200); // Unchanged
    }
}

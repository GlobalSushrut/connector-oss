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
//! - `budget_remaining()` — tokens available before hitting budget limit (B5)
//! - `check_pressure_and_evict()` — automatic LRU-K eviction at 90% pressure (B5)
//!
//! Analogous to: Linux process hibernation (CRIU), memory-mapped file snapshots

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, VecDeque};

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
// B5: Context Budget
// ═══════════════════════════════════════════════════════════════

/// Token budget tracking for a single agent context (B5).
///
/// Tracks how tokens are allocated across context categories and
/// exposes `budget_remaining()` so callers can check headroom
/// before inserting new content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBudget {
    /// Total token cap for this context window
    pub max_tokens: u64,
    /// Tokens reserved for the system prompt (cannot be evicted)
    pub system_tokens: u64,
    /// Tokens used by conversation history
    pub history_tokens: u64,
    /// Tokens used by retrieved documents / RAG context
    pub document_tokens: u64,
    /// Tokens used by tool definitions / schemas
    pub tool_tokens: u64,
    /// Pressure threshold at which LRU-K eviction fires (default 0.90)
    pub eviction_threshold: f64,
}

impl ContextBudget {
    pub fn new(max_tokens: u64) -> Self {
        Self {
            max_tokens,
            system_tokens: 0,
            history_tokens: 0,
            document_tokens: 0,
            tool_tokens: 0,
            eviction_threshold: 0.90,
        }
    }

    /// Total tokens currently consumed across all categories.
    pub fn used_tokens(&self) -> u64 {
        self.system_tokens
            .saturating_add(self.history_tokens)
            .saturating_add(self.document_tokens)
            .saturating_add(self.tool_tokens)
    }

    /// Tokens remaining before the cap is reached.
    ///
    /// Returns 0 if over budget (never wraps / panics).
    pub fn budget_remaining(&self) -> u64 {
        self.max_tokens.saturating_sub(self.used_tokens())
    }

    /// Pressure as a fraction 0.0–1.0.
    pub fn pressure(&self) -> f64 {
        if self.max_tokens == 0 { return 0.0; }
        (self.used_tokens() as f64 / self.max_tokens as f64).min(1.0)
    }

    /// Returns true when pressure ≥ `eviction_threshold` (default 90%).
    pub fn needs_eviction(&self) -> bool {
        self.pressure() >= self.eviction_threshold
    }
}

impl Default for ContextBudget {
    fn default() -> Self {
        Self::new(128_000)
    }
}

// ═══════════════════════════════════════════════════════════════
// B5: LRU-K Access Tracker
// ═══════════════════════════════════════════════════════════════

/// LRU-K eviction policy tracker for context window CIDs.
///
/// Each CID records its last K access timestamps. The CID with the
/// oldest K-th most recent access is the eviction candidate.
/// K=2 is the default (standard LRU-2 — good balance of recency
/// vs frequency, as per the original O'Neil et al. 1993 paper).
#[derive(Debug, Clone)]
pub struct LruKTracker {
    /// K — number of access timestamps to track per CID
    pub k: usize,
    /// access_history[cid] = VecDeque of last K access timestamps (ms)
    access_history: HashMap<String, VecDeque<u64>>,
}

impl LruKTracker {
    pub fn new(k: usize) -> Self {
        Self { k: k.max(1), access_history: HashMap::new() }
    }

    /// Record an access to `cid` at `now_ms`.
    pub fn record_access(&mut self, cid: &str, now_ms: u64) {
        let history = self.access_history
            .entry(cid.to_string())
            .or_insert_with(VecDeque::new);
        history.push_back(now_ms);
        // Keep only the last K entries
        while history.len() > self.k {
            history.pop_front();
        }
    }

    /// Remove tracking for a CID (called when CID is evicted).
    pub fn remove(&mut self, cid: &str) {
        self.access_history.remove(cid);
    }

    /// Correlated backward K-distance for a CID at `now_ms`.
    ///
    /// = `now_ms - timestamp_of_kth_most_recent_access`.
    /// If the CID has fewer than K accesses, returns `u64::MAX`
    /// (treated as "never accessed K times" — highest eviction priority).
    pub fn backward_k_distance(&self, cid: &str, now_ms: u64) -> u64 {
        match self.access_history.get(cid) {
            None => u64::MAX,
            Some(history) if history.len() < self.k => u64::MAX,
            Some(history) => {
                // history is sorted oldest→newest; [0] = K-th most recent
                now_ms.saturating_sub(history[0])
            }
        }
    }

    /// Choose the best eviction candidate from `candidates` at `now_ms`.
    ///
    /// Returns the CID with the highest backward-K-distance
    /// (i.e. least recently used K times).
    pub fn eviction_candidate<'a>(
        &self,
        candidates: &'a [String],
        now_ms: u64,
    ) -> Option<&'a str> {
        candidates.iter()
            .max_by_key(|cid| self.backward_k_distance(cid, now_ms))
            .map(String::as_str)
    }
}

// ═══════════════════════════════════════════════════════════════
// B5: Context Compressor
// ═══════════════════════════════════════════════════════════════

/// High-level compressor that combines budget tracking with LRU-K eviction.
///
/// Usage:
/// ```ignore
/// let mut compressor = ContextCompressor::new(128_000);
/// compressor.record_access("cid:a", now_ms);
/// if compressor.budget.needs_eviction() {
///     let evicted = compressor.evict_to_target(0.70, &window, now_ms);
/// }
/// println!("remaining: {}", compressor.budget.budget_remaining());
/// ```
#[derive(Debug, Clone)]
pub struct ContextCompressor {
    pub budget: ContextBudget,
    pub lru_k:  LruKTracker,
    /// Tokens per CID estimate (updated on each compress pass)
    tokens_per_cid: u64,
}

impl ContextCompressor {
    pub fn new(max_tokens: u64) -> Self {
        Self {
            budget: ContextBudget::new(max_tokens),
            lru_k:  LruKTracker::new(2),
            tokens_per_cid: 0,
        }
    }

    pub fn with_eviction_threshold(mut self, threshold: f64) -> Self {
        self.budget.eviction_threshold = threshold.clamp(0.5, 1.0);
        self
    }

    /// Record that `cid` was accessed at `now_ms`.
    pub fn record_access(&mut self, cid: &str, now_ms: u64) {
        self.lru_k.record_access(cid, now_ms);
    }

    /// Tokens remaining before budget cap.
    pub fn budget_remaining(&self) -> u64 {
        self.budget.budget_remaining()
    }

    /// True when pressure ≥ eviction_threshold.
    pub fn needs_eviction(&self) -> bool {
        self.budget.needs_eviction()
    }

    /// Evict CIDs from `window` using LRU-K until pressure drops to `target_pressure`.
    ///
    /// Returns the list of evicted CIDs (in eviction order).
    /// `tokens_per_cid` is used to estimate how much each eviction saves.
    pub fn evict_to_target(
        &mut self,
        target_pressure: f64,
        window: &[String],
        now_ms: u64,
    ) -> Vec<String> {
        let target_tokens = (self.budget.max_tokens as f64 * target_pressure) as u64;
        let mut remaining: Vec<String> = window.to_vec();
        let mut evicted = Vec::new();

        while self.budget.used_tokens() > target_tokens && !remaining.is_empty() {
            let candidate = self.lru_k
                .eviction_candidate(&remaining, now_ms)
                .map(String::from);

            if let Some(cid) = candidate {
                remaining.retain(|c| c != &cid);
                self.lru_k.remove(&cid);
                self.budget.history_tokens =
                    self.budget.history_tokens.saturating_sub(self.tokens_per_cid);
                evicted.push(cid);
            } else {
                break;
            }
        }

        evicted
    }

    /// Update the tokens-per-CID estimate given total tokens and window size.
    pub fn calibrate(&mut self, total_tokens: u64, window_size: usize) {
        if window_size > 0 {
            self.tokens_per_cid = (total_tokens as f64 / window_size as f64).ceil() as u64;
        }
        // Sync budget used tokens to what LiveContext reports
        self.budget.history_tokens = total_tokens;
    }
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
    /// B5: Per-agent ContextCompressor (budget + LRU-K tracker)
    compressors: HashMap<String, ContextCompressor>,
    /// B5: Auto-evict when pressure ≥ this threshold (default 0.90)
    pub eviction_threshold: f64,
    /// B5: Target pressure after LRU-K eviction pass (default 0.70)
    pub eviction_target_pressure: f64,
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
            compressors: HashMap::new(),
            eviction_threshold: 0.90,
            eviction_target_pressure: 0.70,
        }
    }

    /// Register a new live context for an agent.
    pub fn register(&mut self, agent_pid: impl Into<String>, session_id: impl Into<String>) {
        let pid = agent_pid.into();
        let max_tokens = self.default_max_tokens;
        let threshold = self.eviction_threshold;
        let ctx = LiveContext::new(pid.clone(), session_id, max_tokens);
        self.contexts.insert(pid.clone(), ctx);
        // B5: create a compressor for this agent
        self.compressors.insert(
            pid,
            ContextCompressor::new(max_tokens).with_eviction_threshold(threshold),
        );
    }

    // ── B5: Budget + LRU-K methods ────────────────────────────

    /// Tokens remaining in the agent's context budget.
    ///
    /// Returns `None` if no context is registered for `agent_pid`.
    pub fn budget_remaining(&self, agent_pid: &str) -> Option<u64> {
        self.compressors.get(agent_pid).map(|c| c.budget_remaining())
    }

    /// Returns the full `ContextBudget` for an agent.
    pub fn get_budget(&self, agent_pid: &str) -> Option<&ContextBudget> {
        self.compressors.get(agent_pid).map(|c| &c.budget)
    }

    /// Record that `cid` was accessed by `agent_pid` at `now_ms`.
    ///
    /// Used by LRU-K to decide eviction order.
    pub fn record_access(&mut self, agent_pid: &str, cid: &str, now_ms: u64) {
        if let Some(comp) = self.compressors.get_mut(agent_pid) {
            comp.record_access(cid, now_ms);
        }
    }

    /// Check if agent pressure ≥ eviction_threshold; if so, run LRU-K eviction.
    ///
    /// Returns the list of CIDs evicted (empty if no eviction needed).
    /// Eviction targets `eviction_target_pressure` (default 70%).
    ///
    /// Side effects:
    /// - Updates the compressor's budget to reflect freed tokens
    /// - Removes evicted CIDs from the live context window
    /// - Emits a `ContextPressureEviction` metric (increments eviction_count)
    pub fn check_pressure_and_evict(&mut self, agent_pid: &str, now_ms: u64) -> Vec<String> {
        let needs = self.compressors.get(agent_pid)
            .map(|c| c.needs_eviction())
            .unwrap_or(false);
        if !needs {
            return Vec::new();
        }

        let target = self.eviction_target_pressure;
        let window = self.contexts.get(agent_pid)
            .map(|c| c.context_window.clone())
            .unwrap_or_default();

        let comp = match self.compressors.get_mut(agent_pid) {
            Some(c) => c,
            None => return Vec::new(),
        };
        let evicted = comp.evict_to_target(target, &window, now_ms);

        // Remove evicted CIDs from live context window
        if let Some(ctx) = self.contexts.get_mut(agent_pid) {
            ctx.context_window.retain(|cid| !evicted.contains(cid));
            // Recalculate token count proportionally
            let original_len = window.len();
            let remaining_len = ctx.context_window.len();
            if original_len > 0 {
                let ratio = remaining_len as f64 / original_len as f64;
                ctx.context_tokens = (ctx.context_tokens as f64 * ratio) as u64;
            }
            // Re-calibrate compressor with updated state
            comp.calibrate(ctx.context_tokens, ctx.context_window.len());
        }

        evicted
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
        for cid in &cids {
            if !ctx.context_window.contains(cid) {
                ctx.context_window.push(cid.clone());
            }
        }
        if token_delta >= 0 {
            ctx.context_tokens = ctx.context_tokens.saturating_add(token_delta as u64);
        } else {
            ctx.context_tokens = ctx.context_tokens.saturating_sub((-token_delta) as u64);
        }
        ctx.step_counter += 1;
        // B5: keep compressor budget in sync after every update
        let total = ctx.context_tokens;
        let win_len = ctx.context_window.len();
        if let Some(comp) = self.compressors.get_mut(agent_pid) {
            comp.calibrate(total, win_len);
        }
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

    /// Sliding window summarization — when context pressure ≥ `threshold` (default 0.80),
    /// remove the oldest `n_turns` CIDs from the window, generate a stub summary string,
    /// and return a `SlidingSummary` describing what was compressed.
    ///
    /// The actual LLM summarization call is performed by the caller using
    /// `summary.source_cids` as the input. This method handles the window mutation only
    /// so it stays sync and allocation-free.
    ///
    /// Returns `None` if pressure is below threshold or window has < 2 entries.
    pub fn sliding_window_summarize(
        &mut self,
        agent_pid: &str,
        threshold: f64,
        n_turns: usize,
    ) -> Option<SlidingSummary> {
        // Read pressure + check threshold before any mutation
        let pressure_before = self.compressors.get(agent_pid)?.budget.pressure();
        if pressure_before < threshold {
            return None;
        }
        let ctx = self.contexts.get_mut(agent_pid)?;
        if ctx.context_window.len() < 2 {
            return None;
        }
        let take = n_turns.min(ctx.context_window.len() - 1).max(1);
        let source_cids: Vec<String> = ctx.context_window.drain(..take).collect();
        let total_len = ctx.context_window.len() + take;
        let tokens_per_cid = if total_len > 0 {
            ctx.context_tokens / total_len as u64
        } else { 0 };
        let freed_tokens = tokens_per_cid * take as u64;
        ctx.context_tokens = ctx.context_tokens.saturating_sub(freed_tokens);
        let remaining = ctx.context_window.len();
        let remaining_tokens = ctx.context_tokens;
        // Re-calibrate compressor
        if let Some(comp) = self.compressors.get_mut(agent_pid) {
            comp.calibrate(remaining_tokens, remaining);
        }
        Some(SlidingSummary {
            agent_pid: agent_pid.to_string(),
            source_cids,
            freed_tokens,
            remaining_window: remaining,
            pressure_before,
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

    /// Every live context, for fleet-wide rollups.
    pub fn live_contexts(&self) -> impl Iterator<Item = &LiveContext> {
        self.contexts.values()
    }
}

/// Result of a compress operation.
#[derive(Debug, Clone)]
pub struct CompressResult {
    pub evicted_cids: Vec<String>,
    pub tokens_freed: u64,
    pub strategy: CompressionStrategy,
}

/// Result of a sliding-window summarization pass.
///
/// `source_cids` are the CIDs removed from the front of the context window.
/// The caller should LLM-summarize those CIDs and write the summary back
/// as a new `MemPacket` in the agent's semantic namespace, then call
/// `context_manager.update(pid, vec![summary_cid], estimated_tokens)`.
#[derive(Debug, Clone)]
pub struct SlidingSummary {
    /// Agent PID whose context was compressed
    pub agent_pid: String,
    /// CIDs that were evicted from the front of the window
    pub source_cids: Vec<String>,
    /// Token budget freed by removing source_cids
    pub freed_tokens: u64,
    /// Window size after the compression
    pub remaining_window: usize,
    /// Context pressure (0.0–1.0) measured before eviction
    pub pressure_before: f64,
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

    // ── B5 tests ──────────────────────────────────────────────

    #[test]
    fn test_context_budget_remaining() {
        let mut b = ContextBudget::new(10_000);
        assert_eq!(b.budget_remaining(), 10_000);
        b.history_tokens = 6_000;
        b.document_tokens = 1_000;
        assert_eq!(b.used_tokens(), 7_000);
        assert_eq!(b.budget_remaining(), 3_000);
        assert!((b.pressure() - 0.70).abs() < 0.001);
    }

    #[test]
    fn test_context_budget_needs_eviction() {
        let mut b = ContextBudget::new(10_000);
        b.history_tokens = 8_999;
        assert!(!b.needs_eviction()); // 89.99% < 90%
        b.history_tokens = 9_000;
        assert!(b.needs_eviction()); // 90% == threshold
        b.history_tokens = 9_500;
        assert!(b.needs_eviction()); // 95% > 90%
    }

    #[test]
    fn test_budget_remaining_no_underflow() {
        let mut b = ContextBudget::new(1_000);
        b.history_tokens = 2_000; // over budget
        assert_eq!(b.budget_remaining(), 0); // saturating_sub — never panics
    }

    #[test]
    fn test_lru_k_backward_distance_under_k_accesses() {
        let tracker = LruKTracker::new(2);
        // No accesses yet → u64::MAX
        assert_eq!(tracker.backward_k_distance("cid:a", 5000), u64::MAX);
    }

    #[test]
    fn test_lru_k_backward_distance_k_accesses() {
        let mut tracker = LruKTracker::new(2);
        tracker.record_access("cid:a", 1000);
        tracker.record_access("cid:a", 3000);
        // 2nd access at 3000; history[0]=1000 (oldest of last K=2)
        // backward_k_distance at now=5000 = 5000-1000 = 4000
        assert_eq!(tracker.backward_k_distance("cid:a", 5000), 4000);
    }

    #[test]
    fn test_lru_k_eviction_candidate_prefers_least_recently_k_used() {
        let mut tracker = LruKTracker::new(2);
        // cid:a accessed twice — most recently K used
        tracker.record_access("cid:a", 100);
        tracker.record_access("cid:a", 900);
        // cid:b accessed twice — but older
        tracker.record_access("cid:b", 50);
        tracker.record_access("cid:b", 200);
        // At now=1000: distance(a) = 1000-100=900, distance(b)=1000-50=950
        // cid:b has larger backward distance → eviction candidate
        let candidates = vec!["cid:a".to_string(), "cid:b".to_string()];
        assert_eq!(tracker.eviction_candidate(&candidates, 1000), Some("cid:b"));
    }

    #[test]
    fn test_lru_k_cid_never_accessed_highest_priority() {
        let mut tracker = LruKTracker::new(2);
        tracker.record_access("cid:a", 100);
        tracker.record_access("cid:a", 900);
        // cid:b never accessed → u64::MAX distance → highest eviction priority
        let candidates = vec!["cid:a".to_string(), "cid:b".to_string()];
        assert_eq!(tracker.eviction_candidate(&candidates, 1000), Some("cid:b"));
    }

    #[test]
    fn test_context_compressor_evict_to_target() {
        let mut comp = ContextCompressor::new(10_000);
        // Start at 95% pressure (9500 tokens, 10 CIDs at 950 each)
        let window: Vec<String> = (1..=10).map(|i| format!("cid:{}", i)).collect();
        comp.calibrate(9_500, 10);
        // Access cid:1 and cid:2 twice — they should be kept (most recently used)
        comp.record_access("cid:1", 100);  comp.record_access("cid:1", 900);
        comp.record_access("cid:2", 200);  comp.record_access("cid:2", 800);
        // cid:3..10 accessed only once (or not at all) — higher eviction priority
        for i in 3..=10 {
            comp.record_access(&format!("cid:{}", i), i as u64 * 10);
        }
        assert!(comp.needs_eviction()); // 95% > 90%
        let evicted = comp.evict_to_target(0.70, &window, 1000);
        assert!(!evicted.is_empty(), "should evict some CIDs");
        // Verify cid:1 and cid:2 were NOT evicted (they had 2 accesses each)
        assert!(!evicted.contains(&"cid:1".to_string()));
        assert!(!evicted.contains(&"cid:2".to_string()));
        // Budget should be at or below 70%
        assert!(comp.budget.pressure() <= 0.70 + 0.01);
    }

    #[test]
    fn test_context_manager_budget_remaining() {
        let mut mgr = ContextManager::new();
        mgr.default_max_tokens = 10_000;
        mgr.register("pid:a", "sess:001");
        // Initially all tokens free
        assert_eq!(mgr.budget_remaining("pid:a"), Some(10_000));
        // Add 5000 tokens
        mgr.update("pid:a", vec!["cid:1".into()], 5_000).unwrap();
        assert_eq!(mgr.budget_remaining("pid:a"), Some(5_000));
    }

    #[test]
    fn test_context_manager_check_pressure_no_eviction_below_threshold() {
        let mut mgr = ContextManager::new();
        mgr.default_max_tokens = 10_000;
        mgr.register("pid:a", "sess:001");
        mgr.update("pid:a", vec!["cid:1".into(), "cid:2".into()], 8_000).unwrap();
        // 80% pressure < 90% threshold → no eviction
        let evicted = mgr.check_pressure_and_evict("pid:a", 1000);
        assert!(evicted.is_empty());
        assert_eq!(mgr.budget_remaining("pid:a"), Some(2_000));
    }

    #[test]
    fn test_context_manager_check_pressure_evicts_at_90_percent() {
        let mut mgr = ContextManager::new();
        mgr.default_max_tokens = 10_000;
        mgr.register("pid:a", "sess:001");
        // Load 10 CIDs at 9100 tokens total (91%)
        let cids: Vec<String> = (1..=10).map(|i| format!("cid:{}", i)).collect();
        mgr.update("pid:a", cids.clone(), 9_100).unwrap();
        // Access cid:1 and cid:2 twice — they should survive eviction
        mgr.record_access("pid:a", "cid:1", 100);
        mgr.record_access("pid:a", "cid:1", 500);
        mgr.record_access("pid:a", "cid:2", 200);
        mgr.record_access("pid:a", "cid:2", 600);
        // Evict — should bring pressure to ≤ 70%
        let evicted = mgr.check_pressure_and_evict("pid:a", 1000);
        assert!(!evicted.is_empty(), "should evict CIDs at 91% pressure");
        // Context window should not contain evicted CIDs
        let ctx = mgr.get("pid:a").unwrap();
        for cid in &evicted {
            assert!(!ctx.context_window.contains(cid),
                "evicted CID {} still in window", cid);
        }
        // Pressure should be ≤ 70% after eviction
        assert!(ctx.pressure() <= 0.71,
            "pressure {} still above target after eviction", ctx.pressure());
    }

    #[test]
    fn test_context_manager_budget_remaining_unknown_agent() {
        let mgr = ContextManager::new();
        assert_eq!(mgr.budget_remaining("pid:unknown"), None);
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

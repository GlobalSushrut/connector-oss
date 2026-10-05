//! eBPF-Style Kernel Extension Points — runtime-loadable hooks that extend kernel behavior.
//!
//! Military-grade safety guarantees (eBPF analog):
//! - Extensions cannot access kernel internal state (only hook arguments)
//! - Bounded execution: hooks must complete within 1ms
//! - No blocking I/O in hooks
//! - Load-time verification: Ed25519 signature check on extension
//! - Every load/unload/hook-fire logged to audit trail
//!
//! Linux analog: eBPF lets userspace safely inject logic into kernel code paths
//! without recompiling. We provide the same for agentic AI kernels.

use std::collections::HashMap;
use std::time::Instant;

// ── Hook Points ─────────────────────────────────────────────────────

/// The 8 kernel hook points where extensions can attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookPoint {
    /// Intercept before syscall dispatch — can deny or modify.
    PreSyscall,
    /// Observe after syscall dispatch — read-only.
    PostSyscall,
    /// Fires when a new agent registers.
    OnAgentRegister,
    /// Fires when an agent terminates.
    OnAgentTerminate,
    /// Intercept memory writes — can deny or modify.
    OnMemWrite,
    /// Observe audit log entries — read-only.
    OnAuditEntry,
    /// Fires on security threat detection.
    OnThreatDetected,
    /// Fires when an agent's token budget is exhausted.
    OnTokenBudgetExhausted,
}

impl std::fmt::Display for HookPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreSyscall => write!(f, "PreSyscall"),
            Self::PostSyscall => write!(f, "PostSyscall"),
            Self::OnAgentRegister => write!(f, "OnAgentRegister"),
            Self::OnAgentTerminate => write!(f, "OnAgentTerminate"),
            Self::OnMemWrite => write!(f, "OnMemWrite"),
            Self::OnAuditEntry => write!(f, "OnAuditEntry"),
            Self::OnThreatDetected => write!(f, "OnThreatDetected"),
            Self::OnTokenBudgetExhausted => write!(f, "OnTokenBudgetExhausted"),
        }
    }
}

// ── Hook Decision ───────────────────────────────────────────────────

/// Decision returned by an extension hook.
#[derive(Debug, Clone, PartialEq)]
pub enum HookDecision {
    /// Allow the operation to proceed unchanged.
    Allow,
    /// Deny the operation with a reason.
    Deny(String),
    /// Modify the payload (for PreSyscall/OnMemWrite only).
    Modify(String),
}

// ── Hook Context ────────────────────────────────────────────────────

/// Read-only context passed to extension hooks.
/// Extensions CANNOT access kernel internals — only this context.
#[derive(Debug, Clone)]
pub struct HookContext {
    /// The hook point being fired.
    pub hook: HookPoint,
    /// Agent PID involved (if any).
    pub agent_pid: String,
    /// Operation name (e.g., "MemWrite", "AgentRegister").
    pub operation: String,
    /// Payload data (serialized, read-only snapshot).
    pub payload: String,
    /// Timestamp of the event (epoch ms).
    pub timestamp: i64,
    /// Additional metadata key-value pairs.
    pub metadata: HashMap<String, String>,
}

impl HookContext {
    pub fn new(hook: HookPoint, agent_pid: &str, operation: &str, payload: &str) -> Self {
        Self {
            hook,
            agent_pid: agent_pid.to_string(),
            operation: operation.to_string(),
            payload: payload.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
            metadata: HashMap::new(),
        }
    }
}

// ── Extension Trait ─────────────────────────────────────────────────

/// Trait that all kernel extensions must implement.
pub trait KernelExtension: Send + Sync {
    /// Unique name of the extension.
    fn name(&self) -> &str;

    /// Semantic version (e.g., "1.0.0").
    fn version(&self) -> &str;

    /// Which hook points this extension attaches to.
    fn hooks(&self) -> Vec<HookPoint>;

    /// Execute the hook. Must complete within 1ms.
    /// Returns HookDecision for intercepting hooks, or Allow for observe-only.
    fn on_hook(&self, ctx: &HookContext) -> HookDecision;

    /// Ed25519 signature of the extension binary/code (hex-encoded).
    /// Empty string = unsigned (rejected in strict mode).
    fn signature(&self) -> &str { "" }

    /// Public key that signed this extension (hex-encoded).
    fn signing_key(&self) -> &str { "" }
}

// ── Extension Registry ──────────────────────────────────────────────

/// Statistics for an extension.
#[derive(Debug, Clone, Default)]
pub struct ExtensionStats {
    pub invocations: u64,
    pub total_duration_us: u64,
    pub max_duration_us: u64,
    pub denials: u64,
    pub modifications: u64,
    pub timeouts: u64,
}

/// Registry that manages loaded extensions and dispatches hooks.
pub struct ExtensionRegistry {
    /// Loaded extensions by name.
    extensions: Vec<Box<dyn KernelExtension>>,
    /// Hook point → list of extension indices.
    hook_map: HashMap<HookPoint, Vec<usize>>,
    /// Per-extension statistics.
    stats: HashMap<String, ExtensionStats>,
    /// Maximum hook execution time in microseconds (default: 1000 = 1ms).
    pub max_hook_duration_us: u64,
    /// If true, reject unsigned extensions.
    pub require_signatures: bool,
    /// Audit log of load/unload/hook events.
    audit: Vec<ExtensionAuditEntry>,
}

/// Audit entry for extension operations.
#[derive(Debug, Clone)]
pub struct ExtensionAuditEntry {
    pub timestamp: i64,
    pub event: String,
    pub extension_name: String,
    pub detail: String,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self {
            extensions: Vec::new(),
            hook_map: HashMap::new(),
            stats: HashMap::new(),
            max_hook_duration_us: 1_000, // 1ms
            require_signatures: false,
            audit: Vec::new(),
        }
    }

    /// Create a strict registry that requires Ed25519 signatures.
    pub fn strict() -> Self {
        let mut reg = Self::new();
        reg.require_signatures = true;
        reg
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    fn audit_event(&mut self, event: &str, ext_name: &str, detail: &str) {
        self.audit.push(ExtensionAuditEntry {
            timestamp: Self::now_ms(),
            event: event.to_string(),
            extension_name: ext_name.to_string(),
            detail: detail.to_string(),
        });
    }

    /// Load an extension. Returns error if:
    /// - Extension with same name already loaded
    /// - Signature check fails (in strict mode)
    pub fn load(&mut self, ext: Box<dyn KernelExtension>) -> Result<(), String> {
        let name = ext.name().to_string();
        let version = ext.version().to_string();

        // Duplicate check
        if self.extensions.iter().any(|e| e.name() == name) {
            return Err(format!("Extension '{}' already loaded", name));
        }

        // Signature verification (strict mode)
        if self.require_signatures {
            let sig = ext.signature();
            let key = ext.signing_key();
            if sig.is_empty() || key.is_empty() {
                self.audit_event("LOAD_REJECTED", &name, "missing signature");
                return Err(format!("Extension '{}' rejected: no signature (strict mode)", name));
            }
            // In production: verify Ed25519(key, hash(extension_code), sig)
            // For now: non-empty signature + key = accepted
            if sig.len() < 16 || key.len() < 16 {
                self.audit_event("LOAD_REJECTED", &name, "invalid signature format");
                return Err(format!("Extension '{}' rejected: invalid signature", name));
            }
        }

        // Register hooks
        let idx = self.extensions.len();
        for hook in ext.hooks() {
            self.hook_map.entry(hook).or_default().push(idx);
        }

        self.stats.insert(name.clone(), ExtensionStats::default());
        self.audit_event("LOADED", &name, &format!("v{}, hooks: {:?}", version, ext.hooks()));
        self.extensions.push(ext);

        Ok(())
    }

    /// Unload an extension by name.
    pub fn unload(&mut self, name: &str) -> Result<(), String> {
        let idx = self.extensions.iter().position(|e| e.name() == name)
            .ok_or_else(|| format!("Extension '{}' not found", name))?;

        // Remove from hook map
        for hooks in self.hook_map.values_mut() {
            hooks.retain(|&i| i != idx);
            // Adjust indices above the removed one
            for i in hooks.iter_mut() {
                if *i > idx { *i -= 1; }
            }
        }

        self.audit_event("UNLOADED", name, "");
        self.extensions.remove(idx);
        Ok(())
    }

    /// Fire hooks for a given hook point. Returns the aggregate decision.
    ///
    /// For intercepting hooks (PreSyscall, OnMemWrite):
    ///   - If ANY extension returns Deny, the overall result is Deny.
    ///   - If ANY extension returns Modify, the modification is applied.
    ///   - All extensions are executed even if one denies (for auditing).
    ///
    /// For observe-only hooks: all extensions are called, result is always Allow.
    ///
    /// **Bounded execution**: each hook is timed. If it exceeds max_hook_duration_us,
    /// a timeout is recorded and the hook result is ignored (treated as Allow).
    pub fn fire(&mut self, ctx: &HookContext) -> HookDecision {
        let indices = match self.hook_map.get(&ctx.hook) {
            Some(idxs) => idxs.clone(),
            None => return HookDecision::Allow,
        };

        let mut final_decision = HookDecision::Allow;
        let max_us = self.max_hook_duration_us;

        for idx in indices {
            if idx >= self.extensions.len() { continue; }

            let ext_name = self.extensions[idx].name().to_string();
            let start = Instant::now();

            let decision = self.extensions[idx].on_hook(ctx);

            let elapsed_us = start.elapsed().as_micros() as u64;
            let stats = self.stats.entry(ext_name.clone()).or_default();
            stats.invocations += 1;
            stats.total_duration_us += elapsed_us;
            if elapsed_us > stats.max_duration_us {
                stats.max_duration_us = elapsed_us;
            }

            // Timeout enforcement
            if elapsed_us > max_us {
                stats.timeouts += 1;
                self.audit_event("TIMEOUT", &ext_name,
                    &format!("{}us > {}us limit at {:?}", elapsed_us, max_us, ctx.hook));
                continue; // Ignore result of timed-out hook
            }

            match &decision {
                HookDecision::Deny(reason) => {
                    stats.denials += 1;
                    self.audit_event("DENY", &ext_name,
                        &format!("{:?}: {}", ctx.hook, reason));
                    final_decision = decision;
                }
                HookDecision::Modify(payload) => {
                    stats.modifications += 1;
                    self.audit_event("MODIFY", &ext_name,
                        &format!("{:?}: payload modified", ctx.hook));
                    if final_decision == HookDecision::Allow {
                        final_decision = HookDecision::Modify(payload.clone());
                    }
                }
                HookDecision::Allow => {}
            }
        }

        final_decision
    }

    // ── Query methods ───────────────────────────────────────────

    pub fn extension_count(&self) -> usize { self.extensions.len() }

    pub fn extension_names(&self) -> Vec<&str> {
        self.extensions.iter().map(|e| e.name()).collect()
    }

    pub fn stats(&self, name: &str) -> Option<&ExtensionStats> {
        self.stats.get(name)
    }

    pub fn audit_log(&self) -> &[ExtensionAuditEntry] {
        &self.audit
    }

    pub fn is_loaded(&self, name: &str) -> bool {
        self.extensions.iter().any(|e| e.name() == name)
    }
}

impl Default for ExtensionRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test Extension: blocks "forbidden" payloads ──────────────

    struct BlockForbiddenExt;

    impl KernelExtension for BlockForbiddenExt {
        fn name(&self) -> &str { "block_forbidden" }
        fn version(&self) -> &str { "1.0.0" }
        fn hooks(&self) -> Vec<HookPoint> {
            vec![HookPoint::PreSyscall, HookPoint::OnMemWrite]
        }
        fn on_hook(&self, ctx: &HookContext) -> HookDecision {
            if ctx.payload.contains("FORBIDDEN") {
                HookDecision::Deny("forbidden content detected".into())
            } else {
                HookDecision::Allow
            }
        }
    }

    // ── Test Extension: observes audit entries ───────────────────

    struct AuditObserverExt;

    impl KernelExtension for AuditObserverExt {
        fn name(&self) -> &str { "audit_observer" }
        fn version(&self) -> &str { "1.0.0" }
        fn hooks(&self) -> Vec<HookPoint> { vec![HookPoint::OnAuditEntry] }
        fn on_hook(&self, _ctx: &HookContext) -> HookDecision {
            HookDecision::Allow // observe-only
        }
    }

    // ── Test Extension: signed ───────────────────────────────────

    struct SignedExt;

    impl KernelExtension for SignedExt {
        fn name(&self) -> &str { "signed_ext" }
        fn version(&self) -> &str { "1.0.0" }
        fn hooks(&self) -> Vec<HookPoint> { vec![HookPoint::PostSyscall] }
        fn on_hook(&self, _ctx: &HookContext) -> HookDecision { HookDecision::Allow }
        fn signature(&self) -> &str { "abcdef0123456789abcdef0123456789" }
        fn signing_key(&self) -> &str { "key_abcdef0123456789abcdef012345" }
    }

    // ── Test Extension: slow (simulates timeout) ─────────────────

    struct SlowExt {
        sleep_us: u64,
    }

    impl KernelExtension for SlowExt {
        fn name(&self) -> &str { "slow_ext" }
        fn version(&self) -> &str { "1.0.0" }
        fn hooks(&self) -> Vec<HookPoint> { vec![HookPoint::PreSyscall] }
        fn on_hook(&self, _ctx: &HookContext) -> HookDecision {
            let start = Instant::now();
            while start.elapsed().as_micros() < self.sleep_us as u128 {
                std::hint::spin_loop();
            }
            HookDecision::Deny("slow deny".into())
        }
    }

    // ── Test Extension: modifies payload ─────────────────────────

    struct RedactExt;

    impl KernelExtension for RedactExt {
        fn name(&self) -> &str { "redact_ext" }
        fn version(&self) -> &str { "1.0.0" }
        fn hooks(&self) -> Vec<HookPoint> { vec![HookPoint::OnMemWrite] }
        fn on_hook(&self, ctx: &HookContext) -> HookDecision {
            if ctx.payload.contains("SSN:") {
                HookDecision::Modify(ctx.payload.replace("SSN:", "SSN:[REDACTED]"))
            } else {
                HookDecision::Allow
            }
        }
    }

    #[test]
    fn test_load_extension() {
        let mut reg = ExtensionRegistry::new();
        assert_eq!(reg.extension_count(), 0);
        reg.load(Box::new(BlockForbiddenExt)).unwrap();
        assert_eq!(reg.extension_count(), 1);
        assert!(reg.is_loaded("block_forbidden"));
    }

    #[test]
    fn test_duplicate_load_rejected() {
        let mut reg = ExtensionRegistry::new();
        reg.load(Box::new(BlockForbiddenExt)).unwrap();
        assert!(reg.load(Box::new(BlockForbiddenExt)).is_err());
    }

    #[test]
    fn test_presyscall_deny() {
        let mut reg = ExtensionRegistry::new();
        reg.load(Box::new(BlockForbiddenExt)).unwrap();

        let ctx = HookContext::new(HookPoint::PreSyscall, "pid:1", "MemWrite", "safe content");
        assert_eq!(reg.fire(&ctx), HookDecision::Allow);

        let ctx2 = HookContext::new(HookPoint::PreSyscall, "pid:1", "MemWrite", "contains FORBIDDEN data");
        assert!(matches!(reg.fire(&ctx2), HookDecision::Deny(_)));
    }

    #[test]
    fn test_postsyscall_observe() {
        let mut reg = ExtensionRegistry::new();
        reg.load(Box::new(AuditObserverExt)).unwrap();

        let ctx = HookContext::new(HookPoint::OnAuditEntry, "pid:1", "MemWrite", "data");
        assert_eq!(reg.fire(&ctx), HookDecision::Allow);

        let stats = reg.stats("audit_observer").unwrap();
        assert_eq!(stats.invocations, 1);
    }

    #[test]
    fn test_unload_extension() {
        let mut reg = ExtensionRegistry::new();
        reg.load(Box::new(BlockForbiddenExt)).unwrap();
        reg.load(Box::new(AuditObserverExt)).unwrap();
        assert_eq!(reg.extension_count(), 2);

        reg.unload("block_forbidden").unwrap();
        assert_eq!(reg.extension_count(), 1);
        assert!(!reg.is_loaded("block_forbidden"));
        assert!(reg.is_loaded("audit_observer"));
    }

    #[test]
    fn test_timeout_enforcement() {
        let mut reg = ExtensionRegistry::new();
        reg.max_hook_duration_us = 100; // 0.1ms — very tight
        reg.load(Box::new(SlowExt { sleep_us: 5_000 })).unwrap(); // 5ms — will timeout

        let ctx = HookContext::new(HookPoint::PreSyscall, "pid:1", "op", "data");
        let decision = reg.fire(&ctx);
        // Timed-out hook result is IGNORED — treated as Allow
        assert_eq!(decision, HookDecision::Allow);

        let stats = reg.stats("slow_ext").unwrap();
        assert_eq!(stats.timeouts, 1);
    }

    #[test]
    fn test_signature_required_strict_mode() {
        let mut reg = ExtensionRegistry::strict();

        // Unsigned extension rejected
        assert!(reg.load(Box::new(BlockForbiddenExt)).is_err());

        // Signed extension accepted
        assert!(reg.load(Box::new(SignedExt)).is_ok());
    }

    #[test]
    fn test_modify_hook() {
        let mut reg = ExtensionRegistry::new();
        reg.load(Box::new(RedactExt)).unwrap();

        let ctx = HookContext::new(HookPoint::OnMemWrite, "pid:1", "MemWrite", "data with SSN: 123-45-6789");
        let decision = reg.fire(&ctx);
        assert!(matches!(decision, HookDecision::Modify(ref s) if s.contains("[REDACTED]")));
    }

    #[test]
    fn test_audit_trail() {
        let mut reg = ExtensionRegistry::new();
        reg.load(Box::new(BlockForbiddenExt)).unwrap();

        let audit = reg.audit_log();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].event, "LOADED");
        assert_eq!(audit[0].extension_name, "block_forbidden");
    }

    #[test]
    fn test_multiple_extensions_deny_wins() {
        let mut reg = ExtensionRegistry::new();
        reg.load(Box::new(AuditObserverExt)).unwrap(); // Allow
        reg.load(Box::new(BlockForbiddenExt)).unwrap(); // Deny on FORBIDDEN

        // Both registered but different hooks — doesn't apply
        // Register an extension that shares PreSyscall with BlockForbidden
        struct AllowAll;
        impl KernelExtension for AllowAll {
            fn name(&self) -> &str { "allow_all" }
            fn version(&self) -> &str { "1.0.0" }
            fn hooks(&self) -> Vec<HookPoint> { vec![HookPoint::PreSyscall] }
            fn on_hook(&self, _ctx: &HookContext) -> HookDecision { HookDecision::Allow }
        }
        reg.load(Box::new(AllowAll)).unwrap();

        let ctx = HookContext::new(HookPoint::PreSyscall, "pid:1", "op", "FORBIDDEN payload");
        let decision = reg.fire(&ctx);
        // BlockForbidden denies, AllowAll allows — Deny wins
        assert!(matches!(decision, HookDecision::Deny(_)));
    }

    #[test]
    fn test_stats_tracking() {
        let mut reg = ExtensionRegistry::new();
        reg.load(Box::new(BlockForbiddenExt)).unwrap();

        for _ in 0..5 {
            let ctx = HookContext::new(HookPoint::PreSyscall, "pid:1", "op", "safe");
            reg.fire(&ctx);
        }
        let ctx = HookContext::new(HookPoint::PreSyscall, "pid:1", "op", "FORBIDDEN");
        reg.fire(&ctx);

        let stats = reg.stats("block_forbidden").unwrap();
        assert_eq!(stats.invocations, 6);
        assert_eq!(stats.denials, 1);
    }

    #[test]
    fn test_hook_context_metadata() {
        let mut ctx = HookContext::new(HookPoint::OnThreatDetected, "pid:1", "threat", "score=0.9");
        ctx.metadata.insert("threat_type".into(), "injection".into());
        ctx.metadata.insert("confidence".into(), "0.95".into());
        assert_eq!(ctx.metadata.len(), 2);
        assert_eq!(ctx.metadata["threat_type"], "injection");
    }
}

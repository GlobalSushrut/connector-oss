//! Debugging and Core Dumps — Agent execution debugging and crash recovery
//!
//! This module implements debugging infrastructure:
//! - Debug symbols and source mapping for agent execution
//! - Stack traces with symbolic names
//! - Core dumps for agent state on crash
//! - Execution snapshots for post-mortem analysis
//!
//! Design sources: GDB, DWARF debug info, Linux core dumps

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::process::Pid;

// =============================================================================
// Debug Symbols
// =============================================================================

/// Debug symbol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolType {
    /// Function/procedure
    Function,
    /// Variable
    Variable,
    /// Constant
    Constant,
    /// Type definition
    Type,
    /// Label/jump target
    Label,
    /// Module/namespace
    Module,
}

/// Source location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Source file path
    pub file: String,
    /// Line number (1-indexed)
    pub line: u32,
    /// Column number (1-indexed)
    pub column: u32,
    /// End line (for ranges)
    pub end_line: Option<u32>,
    /// End column
    pub end_column: Option<u32>,
}

impl SourceLocation {
    pub fn new(file: &str, line: u32, column: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column,
            end_line: None,
            end_column: None,
        }
    }

    pub fn with_range(mut self, end_line: u32, end_column: u32) -> Self {
        self.end_line = Some(end_line);
        self.end_column = Some(end_column);
        self
    }
}

/// Debug symbol entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSymbol {
    /// Symbol name
    pub name: String,
    /// Fully qualified name
    pub qualified_name: String,
    /// Symbol type
    pub symbol_type: SymbolType,
    /// Source location
    pub location: Option<SourceLocation>,
    /// Address/offset in execution
    pub address: u64,
    /// Size in bytes (for data)
    pub size: Option<u64>,
    /// Type signature
    pub type_sig: Option<String>,
    /// Documentation
    pub doc: Option<String>,
}

impl DebugSymbol {
    pub fn function(name: &str, address: u64) -> Self {
        Self {
            name: name.into(),
            qualified_name: name.into(),
            symbol_type: SymbolType::Function,
            location: None,
            address,
            size: None,
            type_sig: None,
            doc: None,
        }
    }

    pub fn variable(name: &str, address: u64, type_sig: &str) -> Self {
        Self {
            name: name.into(),
            qualified_name: name.into(),
            symbol_type: SymbolType::Variable,
            location: None,
            address,
            size: None,
            type_sig: Some(type_sig.into()),
            doc: None,
        }
    }

    pub fn with_location(mut self, loc: SourceLocation) -> Self {
        self.location = Some(loc);
        self
    }

    pub fn with_qualified_name(mut self, qname: &str) -> Self {
        self.qualified_name = qname.into();
        self
    }
}

/// Debug symbol table
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolTable {
    /// Symbols by address
    by_address: HashMap<u64, DebugSymbol>,
    /// Symbols by name
    by_name: HashMap<String, u64>,
    /// Source file index
    source_files: Vec<String>,
    /// Line number table (file_idx, line -> address)
    line_table: HashMap<(usize, u32), u64>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a symbol
    pub fn add(&mut self, symbol: DebugSymbol) {
        let addr = symbol.address;
        self.by_name.insert(symbol.name.clone(), addr);
        self.by_address.insert(addr, symbol);
    }

    /// Add source file
    pub fn add_source_file(&mut self, path: &str) -> usize {
        if let Some(idx) = self.source_files.iter().position(|f| f == path) {
            return idx;
        }
        self.source_files.push(path.into());
        self.source_files.len() - 1
    }

    /// Add line mapping
    pub fn add_line(&mut self, file_idx: usize, line: u32, address: u64) {
        self.line_table.insert((file_idx, line), address);
    }

    /// Lookup by address
    pub fn lookup_address(&self, address: u64) -> Option<&DebugSymbol> {
        // Exact match
        if let Some(sym) = self.by_address.get(&address) {
            return Some(sym);
        }
        // Find nearest symbol before address
        self.by_address.iter()
            .filter(|(&addr, _)| addr <= address)
            .max_by_key(|(&addr, _)| addr)
            .map(|(_, sym)| sym)
    }

    /// Lookup by name
    pub fn lookup_name(&self, name: &str) -> Option<&DebugSymbol> {
        self.by_name.get(name)
            .and_then(|addr| self.by_address.get(addr))
    }

    /// Get source location for address
    pub fn address_to_source(&self, address: u64) -> Option<SourceLocation> {
        self.lookup_address(address)
            .and_then(|sym| sym.location.clone())
    }

    /// Get address for source location
    pub fn source_to_address(&self, file: &str, line: u32) -> Option<u64> {
        let file_idx = self.source_files.iter().position(|f| f == file)?;
        self.line_table.get(&(file_idx, line)).copied()
    }

    /// List all symbols
    pub fn symbols(&self) -> Vec<&DebugSymbol> {
        self.by_address.values().collect()
    }

    /// List all source files
    pub fn source_files(&self) -> &[String] {
        &self.source_files
    }
}

// =============================================================================
// Stack Frames
// =============================================================================

/// Stack frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    /// Frame index (0 = top)
    pub index: u32,
    /// Instruction pointer/address
    pub ip: u64,
    /// Stack pointer
    pub sp: u64,
    /// Function name (if known)
    pub function: Option<String>,
    /// Source location (if known)
    pub location: Option<SourceLocation>,
    /// Local variables
    pub locals: HashMap<String, DebugValue>,
    /// Arguments
    pub arguments: HashMap<String, DebugValue>,
}

impl StackFrame {
    pub fn new(index: u32, ip: u64, sp: u64) -> Self {
        Self {
            index,
            ip,
            sp,
            function: None,
            location: None,
            locals: HashMap::new(),
            arguments: HashMap::new(),
        }
    }

    pub fn with_function(mut self, name: &str) -> Self {
        self.function = Some(name.into());
        self
    }

    pub fn with_location(mut self, loc: SourceLocation) -> Self {
        self.location = Some(loc);
        self
    }

    pub fn add_local(&mut self, name: &str, value: DebugValue) {
        self.locals.insert(name.into(), value);
    }

    pub fn add_argument(&mut self, name: &str, value: DebugValue) {
        self.arguments.insert(name.into(), value);
    }
}

/// Debug value (variable content)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum DebugValue {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<DebugValue>),
    Object(HashMap<String, DebugValue>),
    Reference(u64),
    Unavailable,
}

impl DebugValue {
    pub fn from_json(json: &serde_json::Value) -> Self {
        match json {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(b) => Self::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::Int(i)
                } else if let Some(u) = n.as_u64() {
                    Self::Uint(u)
                } else if let Some(f) = n.as_f64() {
                    Self::Float(f)
                } else {
                    Self::Unavailable
                }
            }
            serde_json::Value::String(s) => Self::String(s.clone()),
            serde_json::Value::Array(arr) => {
                Self::Array(arr.iter().map(Self::from_json).collect())
            }
            serde_json::Value::Object(obj) => {
                Self::Object(obj.iter().map(|(k, v)| (k.clone(), Self::from_json(v))).collect())
            }
        }
    }
}

/// Stack trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackTrace {
    /// Agent PID
    pub agent_pid: Pid,
    /// Timestamp
    pub timestamp: i64,
    /// Frames (0 = top of stack)
    pub frames: Vec<StackFrame>,
    /// Truncated flag
    pub truncated: bool,
}

impl StackTrace {
    pub fn new(agent_pid: Pid) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            agent_pid,
            timestamp: now,
            frames: vec![],
            truncated: false,
        }
    }

    pub fn push_frame(&mut self, frame: StackFrame) {
        self.frames.push(frame);
    }

    pub fn top(&self) -> Option<&StackFrame> {
        self.frames.first()
    }

    pub fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Format as string
    pub fn format(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Stack trace for {}:\n", self.agent_pid));
        
        for frame in &self.frames {
            let func = frame.function.as_deref().unwrap_or("<unknown>");
            let loc = frame.location.as_ref()
                .map(|l| format!("{}:{}:{}", l.file, l.line, l.column))
                .unwrap_or_else(|| format!("0x{:x}", frame.ip));
            
            out.push_str(&format!("  #{} {} at {}\n", frame.index, func, loc));
        }
        
        if self.truncated {
            out.push_str("  ... (truncated)\n");
        }
        
        out
    }
}

// =============================================================================
// Core Dump
// =============================================================================

/// Core dump ID counter
static CORE_DUMP_ID: AtomicU64 = AtomicU64::new(1);

/// Core dump reason
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreDumpReason {
    /// Explicit crash/panic
    Panic { message: String },
    /// Unhandled error
    UnhandledError { error: String },
    /// Signal received
    Signal { signal: i32, name: String },
    /// Out of memory
    OutOfMemory { requested: u64, available: u64 },
    /// Timeout
    Timeout { limit_ms: u64, elapsed_ms: u64 },
    /// Budget exhausted
    BudgetExhausted { resource: String },
    /// Assertion failure
    AssertionFailed { condition: String, location: Option<SourceLocation> },
    /// Manual dump request
    Manual { requester: String },
}

/// Memory region in core dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Start address
    pub start: u64,
    /// Size in bytes
    pub size: u64,
    /// Region name
    pub name: String,
    /// Permissions (rwx)
    pub permissions: String,
    /// Content (may be truncated)
    pub content: Option<Vec<u8>>,
    /// Content hash (if content truncated)
    pub content_hash: Option<String>,
}

/// Register state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterState {
    /// General purpose registers
    pub general: HashMap<String, u64>,
    /// Floating point registers
    pub floating: HashMap<String, f64>,
    /// Special registers (flags, etc.)
    pub special: HashMap<String, u64>,
}

/// Agent state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    /// Agent PID
    pub pid: Pid,
    /// Agent name
    pub name: String,
    /// Current state
    pub state: String,
    /// Session ID
    pub session_id: Option<String>,
    /// Memory usage
    pub memory_bytes: u64,
    /// Token budget remaining
    pub tokens_remaining: Option<u64>,
    /// Current operation
    pub current_op: Option<String>,
    /// Pending operations
    pub pending_ops: Vec<String>,
    /// Environment variables
    pub env: HashMap<String, String>,
    /// Open file descriptors
    pub open_fds: Vec<String>,
    /// Custom state (JSON)
    pub custom: HashMap<String, serde_json::Value>,
}

/// Core dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreDump {
    /// Dump ID
    pub id: u64,
    /// Agent PID
    pub agent_pid: Pid,
    /// Timestamp
    pub timestamp: i64,
    /// Reason for dump
    pub reason: CoreDumpReason,
    /// Stack trace
    pub stack_trace: StackTrace,
    /// Register state
    pub registers: RegisterState,
    /// Memory regions
    pub memory: Vec<MemoryRegion>,
    /// Agent state
    pub agent_state: AgentState,
    /// Symbol table (if available)
    pub symbols: Option<SymbolTable>,
    /// Node ID
    pub node_id: String,
    /// Platform version
    pub version: String,
}

impl CoreDump {
    pub fn new(agent_pid: Pid, reason: CoreDumpReason) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            id: CORE_DUMP_ID.fetch_add(1, Ordering::SeqCst),
            agent_pid: agent_pid.clone(),
            timestamp: now,
            reason,
            stack_trace: StackTrace::new(agent_pid.clone()),
            registers: RegisterState::default(),
            memory: vec![],
            agent_state: AgentState {
                pid: agent_pid,
                name: String::new(),
                state: "crashed".into(),
                session_id: None,
                memory_bytes: 0,
                tokens_remaining: None,
                current_op: None,
                pending_ops: vec![],
                env: HashMap::new(),
                open_fds: vec![],
                custom: HashMap::new(),
            },
            symbols: None,
            node_id: String::new(),
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    pub fn with_stack_trace(mut self, trace: StackTrace) -> Self {
        self.stack_trace = trace;
        self
    }

    pub fn with_agent_state(mut self, state: AgentState) -> Self {
        self.agent_state = state;
        self
    }

    pub fn add_memory_region(&mut self, region: MemoryRegion) {
        self.memory.push(region);
    }

    pub fn set_register(&mut self, name: &str, value: u64) {
        self.registers.general.insert(name.into(), value);
    }

    /// Save to file
    pub fn save(&self, path: &str) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write: {}", e))?;
        Ok(())
    }

    /// Load from file
    pub fn load(path: &str) -> Result<Self, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read: {}", e))?;
        serde_json::from_str(&json)
            .map_err(|e| format!("Failed to parse: {}", e))
    }

    /// Generate filename
    pub fn filename(&self) -> String {
        format!(
            "core.{}.{}.{}.json",
            self.agent_pid.replace(":", "_"),
            self.id,
            self.timestamp
        )
    }
}

// =============================================================================
// Core Dump Manager
// =============================================================================

/// Core dump manager
#[derive(Debug, Default)]
pub struct CoreDumpManager {
    /// Storage directory
    dump_dir: String,
    /// Maximum dumps to keep
    max_dumps: usize,
    /// Dumps by agent
    by_agent: HashMap<Pid, Vec<u64>>,
    /// All dump IDs
    dump_ids: Vec<u64>,
    /// Symbol tables by agent
    symbols: HashMap<Pid, SymbolTable>,
}

impl CoreDumpManager {
    pub fn new(dump_dir: &str) -> Self {
        Self {
            dump_dir: dump_dir.into(),
            max_dumps: 100,
            by_agent: HashMap::new(),
            dump_ids: vec![],
            symbols: HashMap::new(),
        }
    }

    pub fn with_max_dumps(mut self, max: usize) -> Self {
        self.max_dumps = max;
        self
    }

    /// Register symbol table for an agent
    pub fn register_symbols(&mut self, agent_pid: Pid, symbols: SymbolTable) {
        self.symbols.insert(agent_pid, symbols);
    }

    /// Create a core dump
    pub fn dump(&mut self, mut core: CoreDump) -> Result<String, String> {
        // Attach symbols if available
        if let Some(symbols) = self.symbols.get(&core.agent_pid) {
            core.symbols = Some(symbols.clone());
        }

        // Generate path
        let filename = core.filename();
        let path = format!("{}/{}", self.dump_dir, filename);

        // Ensure directory exists
        std::fs::create_dir_all(&self.dump_dir)
            .map_err(|e| format!("Failed to create dump dir: {}", e))?;

        // Save dump
        core.save(&path)?;

        // Track dump
        self.dump_ids.push(core.id);
        self.by_agent.entry(core.agent_pid.clone())
            .or_default()
            .push(core.id);

        // Cleanup old dumps
        self.cleanup()?;

        tracing::info!("Core dump saved: {}", path);

        Ok(path)
    }

    /// Cleanup old dumps
    fn cleanup(&mut self) -> Result<(), String> {
        while self.dump_ids.len() > self.max_dumps {
            let oldest_id = self.dump_ids.remove(0);
            
            // Find and remove file
            if let Ok(entries) = std::fs::read_dir(&self.dump_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.contains(&format!(".{}.json", oldest_id)) {
                        let _ = std::fs::remove_file(entry.path());
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// List dumps for an agent
    pub fn list_agent_dumps(&self, agent_pid: &Pid) -> Vec<u64> {
        self.by_agent.get(agent_pid).cloned().unwrap_or_default()
    }

    /// List all dumps
    pub fn list_all(&self) -> &[u64] {
        &self.dump_ids
    }

    /// Load a dump
    pub fn load(&self, dump_id: u64) -> Result<CoreDump, String> {
        // Find file
        let entries = std::fs::read_dir(&self.dump_dir)
            .map_err(|e| format!("Failed to read dump dir: {}", e))?;

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains(&format!(".{}.json", dump_id)) {
                return CoreDump::load(&entry.path().to_string_lossy());
            }
        }

        Err(format!("Dump {} not found", dump_id))
    }
}

// =============================================================================
// Debug Session
// =============================================================================

/// Debug session for interactive debugging
#[derive(Debug)]
pub struct DebugSession {
    /// Session ID
    pub id: String,
    /// Target agent PID
    pub agent_pid: Pid,
    /// Symbol table
    pub symbols: SymbolTable,
    /// Breakpoints (address -> enabled)
    breakpoints: HashMap<u64, bool>,
    /// Watchpoints (address -> condition)
    watchpoints: HashMap<u64, String>,
    /// Current stack trace
    pub stack_trace: Option<StackTrace>,
    /// Paused flag
    pub paused: bool,
}

impl DebugSession {
    pub fn new(agent_pid: Pid) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        Self {
            id: format!("dbg-{:x}", now),
            agent_pid,
            symbols: SymbolTable::new(),
            breakpoints: HashMap::new(),
            watchpoints: HashMap::new(),
            stack_trace: None,
            paused: false,
        }
    }

    /// Set breakpoint at address
    pub fn set_breakpoint(&mut self, address: u64) {
        self.breakpoints.insert(address, true);
    }

    /// Set breakpoint at function
    pub fn set_breakpoint_function(&mut self, name: &str) -> Result<u64, String> {
        let sym = self.symbols.lookup_name(name)
            .ok_or_else(|| format!("Function '{}' not found", name))?;
        self.breakpoints.insert(sym.address, true);
        Ok(sym.address)
    }

    /// Set breakpoint at source location
    pub fn set_breakpoint_source(&mut self, file: &str, line: u32) -> Result<u64, String> {
        let addr = self.symbols.source_to_address(file, line)
            .ok_or_else(|| format!("No code at {}:{}", file, line))?;
        self.breakpoints.insert(addr, true);
        Ok(addr)
    }

    /// Remove breakpoint
    pub fn remove_breakpoint(&mut self, address: u64) {
        self.breakpoints.remove(&address);
    }

    /// Enable/disable breakpoint
    pub fn toggle_breakpoint(&mut self, address: u64, enabled: bool) {
        if let Some(bp) = self.breakpoints.get_mut(&address) {
            *bp = enabled;
        }
    }

    /// Set watchpoint
    pub fn set_watchpoint(&mut self, address: u64, condition: &str) {
        self.watchpoints.insert(address, condition.into());
    }

    /// Remove watchpoint
    pub fn remove_watchpoint(&mut self, address: u64) {
        self.watchpoints.remove(&address);
    }

    /// Check if address has active breakpoint
    pub fn has_breakpoint(&self, address: u64) -> bool {
        self.breakpoints.get(&address).copied().unwrap_or(false)
    }

    /// List breakpoints
    pub fn breakpoints(&self) -> Vec<(u64, bool)> {
        self.breakpoints.iter().map(|(&a, &e)| (a, e)).collect()
    }

    /// List watchpoints
    pub fn watchpoints(&self) -> Vec<(u64, &str)> {
        self.watchpoints.iter().map(|(&a, c)| (a, c.as_str())).collect()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_table() {
        let mut table = SymbolTable::new();

        let sym = DebugSymbol::function("main", 0x1000)
            .with_location(SourceLocation::new("main.rs", 10, 1));
        table.add(sym);

        let sym = DebugSymbol::function("helper", 0x2000);
        table.add(sym);

        assert!(table.lookup_name("main").is_some());
        assert!(table.lookup_address(0x1000).is_some());
        assert_eq!(table.lookup_address(0x1500).unwrap().name, "main"); // Nearest
    }

    #[test]
    fn test_stack_trace() {
        let mut trace = StackTrace::new("pid:001".into());

        trace.push_frame(
            StackFrame::new(0, 0x1000, 0x7fff0000)
                .with_function("inner")
                .with_location(SourceLocation::new("lib.rs", 50, 5))
        );
        trace.push_frame(
            StackFrame::new(1, 0x2000, 0x7fff1000)
                .with_function("outer")
        );

        assert_eq!(trace.depth(), 2);
        assert_eq!(trace.top().unwrap().function.as_deref(), Some("inner"));

        let formatted = trace.format();
        assert!(formatted.contains("inner"));
        assert!(formatted.contains("lib.rs:50:5"));
    }

    #[test]
    fn test_core_dump() {
        let dump = CoreDump::new(
            "pid:001".into(),
            CoreDumpReason::Panic { message: "test panic".into() },
        );

        assert!(dump.id > 0);
        assert_eq!(dump.agent_pid, "pid:001");

        let filename = dump.filename();
        assert!(filename.starts_with("core.pid_001"));
        assert!(filename.ends_with(".json"));
    }

    #[test]
    fn test_debug_session() {
        let mut session = DebugSession::new("pid:001".into());

        // Add symbols
        session.symbols.add(DebugSymbol::function("main", 0x1000));
        session.symbols.add(DebugSymbol::function("helper", 0x2000));

        // Set breakpoints
        session.set_breakpoint(0x1000);
        session.set_breakpoint_function("helper").unwrap();

        assert!(session.has_breakpoint(0x1000));
        assert!(session.has_breakpoint(0x2000));
        assert!(!session.has_breakpoint(0x3000));

        // Toggle
        session.toggle_breakpoint(0x1000, false);
        assert!(!session.has_breakpoint(0x1000));
    }

    #[test]
    fn test_debug_value() {
        let json = serde_json::json!({
            "name": "test",
            "count": 42,
            "items": [1, 2, 3]
        });

        let value = DebugValue::from_json(&json);
        match value {
            DebugValue::Object(obj) => {
                assert!(obj.contains_key("name"));
                assert!(obj.contains_key("count"));
            }
            _ => panic!("Expected Object"),
        }
    }
}

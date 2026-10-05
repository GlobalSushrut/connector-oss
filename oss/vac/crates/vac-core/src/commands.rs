//! Investigation Commands — Unix-like CLI commands for Connector
//!
//! This module implements standard investigation commands:
//! - ls: List resources (agents, memory, sessions, tools)
//! - ps: Process status with hierarchy
//! - top: Live resource monitor
//! - cat: Display content
//! - grep: Search/filter
//! - find: Locate by criteria
//! - trace: Execution tracing
//! - stat: Detailed statistics
//! - tree: Hierarchical views
//! - tail: Follow logs
//! - diff: Compare states
//!
//! All commands produce standard output format (JSON, table, or plain text).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Standard Output Format
// =============================================================================

/// Exit codes (POSIX-compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Success
    Success,
    /// General error
    Error,
    /// Misuse of command
    Misuse,
    /// Cannot execute
    CannotExecute,
    /// Command not found
    NotFound,
    /// Invalid argument
    InvalidArg,
    /// Terminated by signal (128 + signal)
    Signal(i32),
}

impl ExitCode {
    pub fn code(&self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Error => 1,
            Self::Misuse => 2,
            Self::CannotExecute => 126,
            Self::NotFound => 127,
            Self::InvalidArg => 128,
            Self::Signal(sig) => 128 + sig,
        }
    }
}

/// Output format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// JSON output
    Json,
    /// Human-readable table
    Table,
    /// Plain text (one item per line)
    Plain,
    /// CSV format
    Csv,
    /// YAML format
    Yaml,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Table
    }
}

/// Command result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    /// Exit code
    pub exit_code: i32,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Structured data (for JSON output)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Execution time in microseconds
    pub duration_us: u64,
}

impl CommandResult {
    pub fn success(stdout: String) -> Self {
        Self {
            exit_code: 0,
            stdout,
            stderr: String::new(),
            data: None,
            duration_us: 0,
        }
    }

    pub fn success_json(data: serde_json::Value) -> Self {
        Self {
            exit_code: 0,
            stdout: serde_json::to_string_pretty(&data).unwrap_or_default(),
            stderr: String::new(),
            data: Some(data),
            duration_us: 0,
        }
    }

    pub fn error(code: i32, stderr: String) -> Self {
        Self {
            exit_code: code,
            stdout: String::new(),
            stderr,
            data: None,
            duration_us: 0,
        }
    }

    pub fn with_duration(mut self, us: u64) -> Self {
        self.duration_us = us;
        self
    }
}

// =============================================================================
// ls — List Resources
// =============================================================================

/// ls command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LsOptions {
    /// Long format (detailed)
    pub long: bool,
    /// Show all (including hidden)
    pub all: bool,
    /// Human-readable sizes
    pub human: bool,
    /// Recursive listing
    pub recursive: bool,
    /// Sort by (name, size, time, type)
    pub sort: Option<String>,
    /// Reverse sort
    pub reverse: bool,
    /// Output format
    pub format: OutputFormat,
    /// Filter by type (agent, memory, session, tool, port)
    pub type_filter: Option<String>,
}

/// ls entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsEntry {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub size: u64,
    pub size_human: String,
    pub mode: String,
    pub owner: String,
    pub group: String,
    pub modified: String,
    pub cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, serde_json::Value>>,
}

impl LsEntry {
    pub fn format_table_row(&self) -> String {
        format!(
            "{} {:>8} {:>8} {:>8} {} {}",
            self.mode,
            self.owner,
            self.group,
            self.size_human,
            self.modified,
            self.name
        )
    }
}

/// ls result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsResult {
    pub path: String,
    pub entries: Vec<LsEntry>,
    pub total: usize,
}

impl LsResult {
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table => {
                let mut out = format!("total {}\n", self.total);
                for entry in &self.entries {
                    out.push_str(&entry.format_table_row());
                    out.push('\n');
                }
                out
            }
            OutputFormat::Plain => {
                self.entries.iter()
                    .map(|e| e.name.clone())
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            OutputFormat::Csv => {
                let mut out = "name,type,size,mode,owner,modified\n".to_string();
                for e in &self.entries {
                    out.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        e.name, e.entry_type, e.size, e.mode, e.owner, e.modified
                    ));
                }
                out
            }
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// ps — Process Status
// =============================================================================

/// ps command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PsOptions {
    /// Show all processes
    pub all: bool,
    /// Full format
    pub full: bool,
    /// Show process tree
    pub tree: bool,
    /// Show threads (sub-agents)
    pub threads: bool,
    /// Filter by user/owner
    pub user: Option<String>,
    /// Filter by state
    pub state: Option<String>,
    /// Output format
    pub format: OutputFormat,
    /// Custom output columns
    pub columns: Option<Vec<String>>,
}

/// ps entry (process info)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsEntry {
    pub pid: String,
    pub ppid: Option<String>,
    pub pgid: String,
    pub sid: String,
    pub user: String,
    pub state: String,
    pub cpu_percent: f32,
    pub mem_percent: f32,
    pub vsz: u64,
    pub rss: u64,
    pub tty: String,
    pub start_time: String,
    pub time: String,
    pub command: String,
    /// Tree depth (for --tree)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    /// Extra fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, serde_json::Value>>,
}

impl PsEntry {
    pub fn format_table_row(&self, tree: bool) -> String {
        let indent = if tree {
            "  ".repeat(self.depth.unwrap_or(0))
        } else {
            String::new()
        };
        format!(
            "{:>8} {:>8} {} {:>5.1} {:>5.1} {:>8} {:>8} {} {}{}",
            self.pid,
            self.ppid.as_deref().unwrap_or("-"),
            self.state,
            self.cpu_percent,
            self.mem_percent,
            self.vsz,
            self.rss,
            self.time,
            indent,
            self.command
        )
    }
}

/// ps result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsResult {
    pub processes: Vec<PsEntry>,
    pub total: usize,
    pub running: usize,
    pub sleeping: usize,
    pub stopped: usize,
    pub zombie: usize,
}

impl PsResult {
    pub fn format(&self, format: OutputFormat, tree: bool) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table => {
                let mut out = format!(
                    "PID      PPID     S   CPU%  MEM%      VSZ      RSS TIME     COMMAND\n"
                );
                for p in &self.processes {
                    out.push_str(&p.format_table_row(tree));
                    out.push('\n');
                }
                out.push_str(&format!(
                    "\nTotal: {} | Running: {} | Sleeping: {} | Stopped: {} | Zombie: {}\n",
                    self.total, self.running, self.sleeping, self.stopped, self.zombie
                ));
                out
            }
            OutputFormat::Plain => {
                self.processes.iter()
                    .map(|p| format!("{} {}", p.pid, p.command))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            OutputFormat::Csv => {
                let mut out = "pid,ppid,state,cpu,mem,vsz,rss,time,command\n".to_string();
                for p in &self.processes {
                    out.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        p.pid,
                        p.ppid.as_deref().unwrap_or(""),
                        p.state,
                        p.cpu_percent,
                        p.mem_percent,
                        p.vsz,
                        p.rss,
                        p.time,
                        p.command
                    ));
                }
                out
            }
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// top — Live Resource Monitor
// =============================================================================

/// top command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TopOptions {
    /// Update interval in seconds
    pub interval: f32,
    /// Number of iterations (0 = infinite)
    pub iterations: u32,
    /// Sort by field
    pub sort: Option<String>,
    /// Filter by user
    pub user: Option<String>,
    /// Show only N processes
    pub limit: Option<usize>,
    /// Output format
    pub format: OutputFormat,
}

/// System summary for top
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopSummary {
    pub uptime: String,
    pub load_avg: [f32; 3],
    pub tasks_total: usize,
    pub tasks_running: usize,
    pub tasks_sleeping: usize,
    pub tasks_stopped: usize,
    pub tasks_zombie: usize,
    pub cpu_user: f32,
    pub cpu_system: f32,
    pub cpu_idle: f32,
    pub mem_total: u64,
    pub mem_used: u64,
    pub mem_free: u64,
    pub mem_cached: u64,
    pub tokens_used: u64,
    pub tokens_limit: u64,
}

/// top result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopResult {
    pub summary: TopSummary,
    pub processes: Vec<PsEntry>,
    pub timestamp: String,
}

impl TopResult {
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table => {
                let s = &self.summary;
                let mut out = format!(
                    "top - {} up {}, load average: {:.2}, {:.2}, {:.2}\n",
                    self.timestamp, s.uptime, s.load_avg[0], s.load_avg[1], s.load_avg[2]
                );
                out.push_str(&format!(
                    "Tasks: {} total, {} running, {} sleeping, {} stopped, {} zombie\n",
                    s.tasks_total, s.tasks_running, s.tasks_sleeping, s.tasks_stopped, s.tasks_zombie
                ));
                out.push_str(&format!(
                    "%Cpu(s): {:.1} us, {:.1} sy, {:.1} id\n",
                    s.cpu_user, s.cpu_system, s.cpu_idle
                ));
                out.push_str(&format!(
                    "MiB Mem: {} total, {} used, {} free, {} cached\n",
                    format_bytes(s.mem_total),
                    format_bytes(s.mem_used),
                    format_bytes(s.mem_free),
                    format_bytes(s.mem_cached)
                ));
                out.push_str(&format!(
                    "Tokens: {} / {} ({:.1}%)\n\n",
                    s.tokens_used,
                    s.tokens_limit,
                    if s.tokens_limit > 0 { s.tokens_used as f32 / s.tokens_limit as f32 * 100.0 } else { 0.0 }
                ));
                out.push_str("PID      USER     S   CPU%  MEM%      VSZ      RSS COMMAND\n");
                for p in &self.processes {
                    out.push_str(&format!(
                        "{:>8} {:>8} {} {:>5.1} {:>5.1} {:>8} {:>8} {}\n",
                        p.pid, p.user, p.state, p.cpu_percent, p.mem_percent,
                        p.vsz, p.rss, p.command
                    ));
                }
                out
            }
            _ => serde_json::to_string_pretty(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// grep — Search/Filter
// =============================================================================

/// grep command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrepOptions {
    /// Pattern to search
    pub pattern: String,
    /// Case insensitive
    pub ignore_case: bool,
    /// Invert match
    pub invert: bool,
    /// Count only
    pub count: bool,
    /// Show line numbers
    pub line_numbers: bool,
    /// Show context lines before
    pub before: usize,
    /// Show context lines after
    pub after: usize,
    /// Recursive search
    pub recursive: bool,
    /// Include files matching pattern
    pub include: Option<String>,
    /// Exclude files matching pattern
    pub exclude: Option<String>,
    /// Output format
    pub format: OutputFormat,
    /// Search in (memory, audit, sessions, all)
    pub scope: Option<String>,
}

/// grep match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepMatch {
    pub path: String,
    pub line_number: Option<usize>,
    pub content: String,
    pub match_start: usize,
    pub match_end: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_before: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_after: Option<Vec<String>>,
}

/// grep result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepResult {
    pub pattern: String,
    pub matches: Vec<GrepMatch>,
    pub total_matches: usize,
    pub files_searched: usize,
    pub files_matched: usize,
}

impl GrepResult {
    pub fn format(&self, format: OutputFormat, show_line_numbers: bool) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table | OutputFormat::Plain => {
                let mut out = String::new();
                for m in &self.matches {
                    if show_line_numbers {
                        if let Some(ln) = m.line_number {
                            out.push_str(&format!("{}:{}: {}\n", m.path, ln, m.content));
                        } else {
                            out.push_str(&format!("{}: {}\n", m.path, m.content));
                        }
                    } else {
                        out.push_str(&format!("{}: {}\n", m.path, m.content));
                    }
                }
                out.push_str(&format!(
                    "\n{} matches in {} files ({} files searched)\n",
                    self.total_matches, self.files_matched, self.files_searched
                ));
                out
            }
            OutputFormat::Csv => {
                let mut out = "path,line,content\n".to_string();
                for m in &self.matches {
                    out.push_str(&format!(
                        "{},{},{}\n",
                        m.path,
                        m.line_number.unwrap_or(0),
                        m.content.replace(',', "\\,")
                    ));
                }
                out
            }
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// find — Locate by Criteria
// =============================================================================

/// find command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindOptions {
    /// Starting path
    pub path: String,
    /// Name pattern (glob)
    pub name: Option<String>,
    /// Type filter (f=file, d=dir, a=agent, s=session, p=port, t=tool)
    pub type_filter: Option<String>,
    /// Size filter (e.g., "+1M", "-100K")
    pub size: Option<String>,
    /// Modified time filter (e.g., "-1d", "+7d")
    pub mtime: Option<String>,
    /// Owner filter
    pub user: Option<String>,
    /// Max depth
    pub maxdepth: Option<usize>,
    /// Min depth
    pub mindepth: Option<usize>,
    /// Execute command on results
    pub exec: Option<String>,
    /// Output format
    pub format: OutputFormat,
    /// Custom predicate (JSON expression)
    pub predicate: Option<String>,
}

/// find result entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub size: u64,
    pub modified: String,
    pub owner: String,
    pub depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, serde_json::Value>>,
}

/// find result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindResult {
    pub root: String,
    pub entries: Vec<FindEntry>,
    pub total: usize,
}

impl FindResult {
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table | OutputFormat::Plain => {
                self.entries.iter()
                    .map(|e| e.path.clone())
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            OutputFormat::Csv => {
                let mut out = "path,type,size,modified,owner\n".to_string();
                for e in &self.entries {
                    out.push_str(&format!(
                        "{},{},{},{},{}\n",
                        e.path, e.entry_type, e.size, e.modified, e.owner
                    ));
                }
                out
            }
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// trace — Execution Tracing
// =============================================================================

/// trace command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceOptions {
    /// Target PID to trace
    pub pid: Option<String>,
    /// Trace syscalls
    pub syscalls: bool,
    /// Trace signals
    pub signals: bool,
    /// Trace tool calls
    pub tools: bool,
    /// Trace memory operations
    pub memory: bool,
    /// Trace port operations
    pub ports: bool,
    /// Follow child processes
    pub follow_forks: bool,
    /// Output format
    pub format: OutputFormat,
    /// Max events to capture
    pub limit: Option<usize>,
    /// Filter by operation type
    pub filter: Option<String>,
}

/// Trace event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub timestamp: String,
    pub pid: String,
    pub event_type: String,
    pub operation: String,
    pub args: Vec<String>,
    pub result: Option<String>,
    pub duration_us: u64,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
}

impl TraceEvent {
    pub fn format_line(&self) -> String {
        let args = self.args.join(", ");
        let result = self.result.as_deref().unwrap_or("?");
        format!(
            "[{}] {} {}({}) = {} <{}us>",
            self.timestamp, self.pid, self.operation, args, result, self.duration_us
        )
    }
}

/// trace result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    pub pid: String,
    pub events: Vec<TraceEvent>,
    pub total_events: usize,
    pub start_time: String,
    pub end_time: String,
}

impl TraceResult {
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table | OutputFormat::Plain => {
                let mut out = format!("Tracing PID {} ({} events)\n", self.pid, self.total_events);
                out.push_str(&format!("Start: {} | End: {}\n\n", self.start_time, self.end_time));
                for e in &self.events {
                    out.push_str(&e.format_line());
                    out.push('\n');
                }
                out
            }
            OutputFormat::Csv => {
                let mut out = "timestamp,pid,type,operation,result,duration_us\n".to_string();
                for e in &self.events {
                    out.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        e.timestamp, e.pid, e.event_type, e.operation,
                        e.result.as_deref().unwrap_or(""), e.duration_us
                    ));
                }
                out
            }
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// stat — Detailed Statistics
// =============================================================================

/// stat command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatOptions {
    /// Target path or PID
    pub target: String,
    /// Output format
    pub format: OutputFormat,
    /// Show filesystem info
    pub filesystem: bool,
}

/// stat result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatResult {
    pub path: String,
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub size: u64,
    pub blocks: u64,
    pub block_size: u32,
    pub inode: u64,
    pub links: u32,
    pub mode: String,
    pub mode_octal: String,
    pub uid: String,
    pub gid: String,
    pub access_time: String,
    pub modify_time: String,
    pub change_time: String,
    pub birth_time: String,
    pub cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<HashMap<String, serde_json::Value>>,
}

impl StatResult {
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table | OutputFormat::Plain => {
                format!(
                    "  File: {}\n  Size: {}  Blocks: {}  IO Block: {}  {}\n\
                     Inode: {}  Links: {}\n\
                     Access: ({})  Uid: {}  Gid: {}\n\
                     Access: {}\nModify: {}\nChange: {}\n Birth: {}\n",
                    self.path, self.size, self.blocks, self.block_size, self.entry_type,
                    self.inode, self.links,
                    self.mode_octal, self.uid, self.gid,
                    self.access_time, self.modify_time, self.change_time, self.birth_time
                )
            }
            OutputFormat::Csv => {
                format!(
                    "path,type,size,inode,mode,uid,gid,mtime\n{},{},{},{},{},{},{},{}\n",
                    self.path, self.entry_type, self.size, self.inode,
                    self.mode_octal, self.uid, self.gid, self.modify_time
                )
            }
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// tree — Hierarchical View
// =============================================================================

/// tree command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TreeOptions {
    /// Root path
    pub path: String,
    /// Max depth
    pub max_depth: Option<usize>,
    /// Show hidden files
    pub all: bool,
    /// Show only directories
    pub dirs_only: bool,
    /// Show file sizes
    pub size: bool,
    /// Pattern to match
    pub pattern: Option<String>,
    /// Output format
    pub format: OutputFormat,
}

/// tree node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub size: Option<u64>,
    pub children: Vec<TreeNode>,
}

impl TreeNode {
    pub fn format_ascii(&self, prefix: &str, is_last: bool) -> String {
        let connector = if is_last { "└── " } else { "├── " };
        let mut out = format!("{}{}{}", prefix, connector, self.name);
        if let Some(size) = self.size {
            out.push_str(&format!(" [{}]", format_bytes(size)));
        }
        out.push('\n');

        let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
        for (i, child) in self.children.iter().enumerate() {
            let is_last_child = i == self.children.len() - 1;
            out.push_str(&child.format_ascii(&child_prefix, is_last_child));
        }
        out
    }
}

/// tree result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeResult {
    pub root: TreeNode,
    pub directories: usize,
    pub files: usize,
}

impl TreeResult {
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table | OutputFormat::Plain => {
                let mut out = format!("{}\n", self.root.name);
                for (i, child) in self.root.children.iter().enumerate() {
                    let is_last = i == self.root.children.len() - 1;
                    out.push_str(&child.format_ascii("", is_last));
                }
                out.push_str(&format!(
                    "\n{} directories, {} files\n",
                    self.directories, self.files
                ));
                out
            }
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
            OutputFormat::Csv => serde_json::to_string_pretty(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// tail — Follow Logs
// =============================================================================

/// tail command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TailOptions {
    /// Target path or stream
    pub target: String,
    /// Number of lines
    pub lines: usize,
    /// Follow mode (like tail -f)
    pub follow: bool,
    /// Output format
    pub format: OutputFormat,
    /// Filter pattern
    pub filter: Option<String>,
}

/// tail result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailResult {
    pub target: String,
    pub lines: Vec<String>,
    pub total_lines: usize,
    pub following: bool,
}

impl TailResult {
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table | OutputFormat::Plain => {
                self.lines.join("\n")
            }
            OutputFormat::Csv => {
                let mut out = "line_number,content\n".to_string();
                let start = self.total_lines.saturating_sub(self.lines.len());
                for (i, line) in self.lines.iter().enumerate() {
                    out.push_str(&format!("{},{}\n", start + i + 1, line.replace(',', "\\,")));
                }
                out
            }
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// diff — Compare States
// =============================================================================

/// diff command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiffOptions {
    /// First target
    pub left: String,
    /// Second target
    pub right: String,
    /// Context lines
    pub context: usize,
    /// Unified format
    pub unified: bool,
    /// Side-by-side
    pub side_by_side: bool,
    /// Output format
    pub format: OutputFormat,
}

/// diff hunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffHunk {
    pub left_start: usize,
    pub left_count: usize,
    pub right_start: usize,
    pub right_count: usize,
    pub lines: Vec<DiffLine>,
}

/// diff line
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffLine {
    pub kind: String, // "context", "add", "remove"
    pub content: String,
    pub left_line: Option<usize>,
    pub right_line: Option<usize>,
}

/// diff result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    pub left: String,
    pub right: String,
    pub hunks: Vec<DiffHunk>,
    pub additions: usize,
    pub deletions: usize,
    pub changes: usize,
}

impl DiffResult {
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table | OutputFormat::Plain => {
                let mut out = format!("--- {}\n+++ {}\n", self.left, self.right);
                for hunk in &self.hunks {
                    out.push_str(&format!(
                        "@@ -{},{} +{},{} @@\n",
                        hunk.left_start, hunk.left_count,
                        hunk.right_start, hunk.right_count
                    ));
                    for line in &hunk.lines {
                        let prefix = match line.kind.as_str() {
                            "add" => "+",
                            "remove" => "-",
                            _ => " ",
                        };
                        out.push_str(&format!("{}{}\n", prefix, line.content));
                    }
                }
                out.push_str(&format!(
                    "\n{} additions, {} deletions, {} changes\n",
                    self.additions, self.deletions, self.changes
                ));
                out
            }
            OutputFormat::Csv => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// cat — Display Content
// =============================================================================

/// cat command options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CatOptions {
    /// Target path(s)
    pub paths: Vec<String>,
    /// Show line numbers
    pub number: bool,
    /// Show non-printing characters
    pub show_all: bool,
    /// Squeeze blank lines
    pub squeeze: bool,
    /// Output format
    pub format: OutputFormat,
}

/// cat result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatResult {
    pub path: String,
    pub content: String,
    pub size: u64,
    pub content_type: String,
}

impl CatResult {
    pub fn format(&self, format: OutputFormat, show_numbers: bool) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Table | OutputFormat::Plain => {
                if show_numbers {
                    self.content
                        .lines()
                        .enumerate()
                        .map(|(i, line)| format!("{:>6}  {}", i + 1, line))
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    self.content.clone()
                }
            }
            OutputFormat::Csv => serde_json::to_string_pretty(self).unwrap_or_default(),
            OutputFormat::Yaml => serde_yaml::to_string(self).unwrap_or_default(),
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Format bytes as human-readable
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T", "P"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    
    if unit_idx == 0 {
        format!("{}", bytes)
    } else {
        format!("{:.1}{}", size, UNITS[unit_idx])
    }
}

/// Format duration as human-readable
pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m{}s", seconds / 60, seconds % 60)
    } else if seconds < 86400 {
        format!("{}h{}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d{}h", seconds / 86400, (seconds % 86400) / 3600)
    }
}

/// Format timestamp as ISO 8601
pub fn format_timestamp(epoch_ms: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let d = UNIX_EPOCH + Duration::from_millis(epoch_ms as u64);
    format!("{:?}", d)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0");
        assert_eq!(format_bytes(512), "512");
        assert_eq!(format_bytes(1024), "1.0K");
        assert_eq!(format_bytes(1536), "1.5K");
        assert_eq!(format_bytes(1048576), "1.0M");
        assert_eq!(format_bytes(1073741824), "1.0G");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m30s");
        assert_eq!(format_duration(3661), "1h1m");
        assert_eq!(format_duration(90061), "1d1h");
    }

    #[test]
    fn test_ls_result_format() {
        let result = LsResult {
            path: "/m".to_string(),
            entries: vec![
                LsEntry {
                    name: "agent1".to_string(),
                    path: "/m/agent1".to_string(),
                    entry_type: "directory".to_string(),
                    size: 4096,
                    size_human: "4.0K".to_string(),
                    mode: "drwxr-xr-x".to_string(),
                    owner: "root".to_string(),
                    group: "root".to_string(),
                    modified: "2024-01-01 12:00".to_string(),
                    cid: None,
                    extra: None,
                },
            ],
            total: 1,
        };

        let json = result.format(OutputFormat::Json);
        assert!(json.contains("agent1"));

        let table = result.format(OutputFormat::Table);
        assert!(table.contains("drwxr-xr-x"));
    }

    #[test]
    fn test_tree_format() {
        let result = TreeResult {
            root: TreeNode {
                name: "/m".to_string(),
                path: "/m".to_string(),
                node_type: "directory".to_string(),
                size: None,
                children: vec![
                    TreeNode {
                        name: "agent1".to_string(),
                        path: "/m/agent1".to_string(),
                        node_type: "directory".to_string(),
                        size: None,
                        children: vec![],
                    },
                ],
            },
            directories: 2,
            files: 0,
        };

        let output = result.format(OutputFormat::Plain);
        assert!(output.contains("agent1"));
        assert!(output.contains("2 directories"));
    }

    #[test]
    fn test_command_result() {
        let result = CommandResult::success("Hello".to_string());
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "Hello");

        let error = CommandResult::error(1, "Failed".to_string());
        assert_eq!(error.exit_code, 1);
        assert_eq!(error.stderr, "Failed");
    }
}

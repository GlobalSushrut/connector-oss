use std::sync::{Arc, RwLock};

use lazy_static::lazy_static;

use crate::state::SharedState;

#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub agent_pid: String,
    pub role: String,
}

type SessionResolver = dyn Fn(&SharedState, &str) -> Option<SessionContext> + Send + Sync + 'static;
type MessageGuard = dyn Fn(&SharedState, &str, &str) -> (String, usize) + Send + Sync + 'static;
type CommandGuard = dyn Fn(&SharedState, &str, &str) -> CommandGuardResult + Send + Sync + 'static;
type FileGuard = dyn Fn(&SharedState, &str, &str, &str) -> FileGuardResult + Send + Sync + 'static;
type LlmCallRecorder = dyn Fn(&SharedState, &str, &str, u32, u32) + Send + Sync + 'static;

lazy_static! {
    static ref SESSION_RESOLVERS: RwLock<Vec<Arc<SessionResolver>>> = RwLock::new(Vec::new());
    static ref MESSAGE_GUARDS: RwLock<Vec<Arc<MessageGuard>>> = RwLock::new(Vec::new());
    static ref COMMAND_GUARDS: RwLock<Vec<Arc<CommandGuard>>> = RwLock::new(Vec::new());
    static ref FILE_GUARDS: RwLock<Vec<Arc<FileGuard>>> = RwLock::new(Vec::new());
    static ref LLM_CALL_RECORDERS: RwLock<Vec<Arc<LlmCallRecorder>>> = RwLock::new(Vec::new());
}

pub fn register_session_resolver(resolver: Arc<SessionResolver>) {
    if let Ok(mut resolvers) = SESSION_RESOLVERS.write() {
        resolvers.push(resolver);
    }
}

pub fn ensure_default_hooks() {
    // Plugin-owned hooks are registered externally via MCP/plugin bootstrapping.
}

pub fn resolve_session(state: &SharedState, api_key: &str) -> Option<SessionContext> {
    let resolvers = SESSION_RESOLVERS.read().ok()?;
    for resolver in resolvers.iter() {
        if let Some(ctx) = resolver(state, api_key) {
            return Some(ctx);
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct CommandGuardResult {
    pub allowed: bool,
    pub verdict: String,
    pub reason: String,
    pub dangerous: bool,
    pub network_egress: bool,
    pub requires_approval: bool,
}

#[derive(Debug, Clone)]
pub struct FileGuardResult {
    pub allowed: bool,
    pub verdict: String,
    pub reason: String,
    pub requires_approval: bool,
}

pub fn register_message_guard(guard: Arc<MessageGuard>) {
    if let Ok(mut guards) = MESSAGE_GUARDS.write() {
        guards.push(guard);
    }
}

pub fn guard_message_content(
    state: &SharedState,
    agent_pid: &str,
    content: &str,
) -> (String, usize) {
    let guards = match MESSAGE_GUARDS.read() {
        Ok(g) => g,
        Err(_) => return (content.to_string(), 0),
    };
    for guard in guards.iter() {
        let (sanitized, redacted) = guard(state, agent_pid, content);
        if redacted > 0 || sanitized != content {
            return (sanitized, redacted);
        }
    }
    (content.to_string(), 0)
}

pub fn register_command_guard(guard: Arc<CommandGuard>) {
    if let Ok(mut guards) = COMMAND_GUARDS.write() {
        guards.push(guard);
    }
}

pub fn guard_command(
    state: &SharedState,
    agent_pid: &str,
    command: &str,
) -> Option<CommandGuardResult> {
    let guards = COMMAND_GUARDS.read().ok()?;
    guards.first().map(|guard| guard(state, agent_pid, command))
}

pub fn register_file_guard(guard: Arc<FileGuard>) {
    if let Ok(mut guards) = FILE_GUARDS.write() {
        guards.push(guard);
    }
}

pub fn guard_file_op(
    state: &SharedState,
    agent_pid: &str,
    operation: &str,
    path: &str,
) -> Option<FileGuardResult> {
    let guards = FILE_GUARDS.read().ok()?;
    guards
        .first()
        .map(|guard| guard(state, agent_pid, operation, path))
}

pub fn register_llm_call_recorder(recorder: Arc<LlmCallRecorder>) {
    if let Ok(mut recorders) = LLM_CALL_RECORDERS.write() {
        recorders.push(recorder);
    }
}

pub fn record_llm_call(
    state: &SharedState,
    session_id: &str,
    agent_pid: &str,
    input_tokens: u32,
    output_tokens: u32,
) {
    if let Ok(recorders) = LLM_CALL_RECORDERS.read() {
        for recorder in recorders.iter() {
            recorder(state, session_id, agent_pid, input_tokens, output_tokens);
        }
    }
}

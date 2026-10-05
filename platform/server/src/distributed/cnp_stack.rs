//! CNP Stack — Connector Native Protocol Stack
//!
//! FIX BUG-021: Protocol infrastructure

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Intent type for CNP messages
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Intent {
    Query,
    Execute,
    Instruct,
    Notify,
    Heartbeat,
}

/// A CNP protocol message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpMessage {
    pub message_id: String,
    pub session_id: String,
    pub intent: Intent,
    pub payload: Vec<u8>,
    pub timestamp: i64,
}

/// CNP session with typed intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CnpSession {
    pub session_id: String,
    pub intent: Intent,
    pub created_at: i64,
}

/// CNP Stack manages the protocol layers
pub struct CnpStack {
    layers: HashMap<u8, Layer>,
    session_counter: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    pub layer_id: u8,
    pub name: String,
    pub enabled: bool,
}

impl CnpStack {
    pub fn new() -> Self {
        Self {
            layers: HashMap::new(),
            session_counter: 0,
        }
    }

    pub fn create_session(&mut self, intent: Intent) -> CnpSession {
        self.session_counter += 1;
        CnpSession {
            session_id: format!("session-{}", self.session_counter),
            intent,
            created_at: chrono::Utc::now().timestamp_millis(),
        }
    }
}

impl Default for CnpStack {
    fn default() -> Self {
        Self::new()
    }
}

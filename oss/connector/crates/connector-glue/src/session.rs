//! GlueSession - Scoped execution context

use crate::{Glue, GlueResult, GlueError};
use std::sync::Arc;

/// A scoped session with inherited policy and namespace
#[derive(Clone)]
pub struct GlueSession {
    glue: Glue,
    policy: Option<String>,
    namespace: Option<String>,
    timeout_ms: Option<u64>,
    session_id: String,
}

impl GlueSession {
    pub fn new(
        glue: Glue,
        policy: Option<String>,
        namespace: Option<String>,
        timeout_ms: Option<u64>,
    ) -> Self {
        let session_id = generate_session_id();
        Self { glue, policy, namespace, timeout_ms, session_id }
    }

    pub fn id(&self) -> &str { &self.session_id }
    pub fn policy(&self) -> Option<&str> { self.policy.as_deref() }
    pub fn namespace(&self) -> Option<&str> { self.namespace.as_deref() }

    /// Run a contract within this session
    pub fn run<T: Into<String>>(&self, target: T) -> SessionRunBuilder {
        SessionRunBuilder::new(self.clone(), target.into())
    }

    /// Remember within this session's namespace
    pub fn remember<K: Into<String>>(&self, key: K) -> SessionRememberBuilder {
        SessionRememberBuilder::new(self.clone(), key.into())
    }

    /// Recall within this session's namespace
    pub fn recall<Q: Into<String>>(&self, query: Q) -> SessionRecallBuilder {
        SessionRecallBuilder::new(self.clone(), query.into())
    }
}

fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("sess_{:x}", ts & 0xFFFFFFFFFFFF)
}

pub struct SessionRunBuilder {
    session: GlueSession,
    target: String,
    inputs: std::collections::HashMap<String, serde_json::Value>,
}

impl SessionRunBuilder {
    fn new(session: GlueSession, target: String) -> Self {
        Self { session, target, inputs: std::collections::HashMap::new() }
    }

    pub fn with_input<K: Into<String>, V: serde::Serialize>(mut self, key: K, value: V) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.inputs.insert(key.into(), v);
        }
        self
    }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        let mut builder = self.session.glue.run(&self.target);
        for (k, v) in self.inputs {
            builder = builder.with_input(k, v);
        }
        if let Some(p) = &self.session.policy {
            builder = builder.with_policy(p.clone());
        }
        builder.execute()
    }
}

pub struct SessionRememberBuilder {
    session: GlueSession,
    key: String,
    content: Option<String>,
}

impl SessionRememberBuilder {
    fn new(session: GlueSession, key: String) -> Self {
        Self { session, key, content: None }
    }

    pub fn content<C: Into<String>>(mut self, c: C) -> Self {
        self.content = Some(c.into());
        self
    }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        let mut builder = self.session.glue.remember(&self.key);
        if let Some(c) = self.content {
            builder = builder.content(c);
        }
        if let Some(ns) = &self.session.namespace {
            builder = builder.namespace(ns.clone());
        }
        builder.execute()
    }
}

pub struct SessionRecallBuilder {
    session: GlueSession,
    query: String,
    limit: Option<usize>,
}

impl SessionRecallBuilder {
    fn new(session: GlueSession, query: String) -> Self {
        Self { session, query, limit: None }
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    pub fn execute(self) -> Result<GlueResult, GlueError> {
        let mut builder = self.session.glue.recall(&self.query);
        if let Some(ns) = &self.session.namespace {
            builder = builder.namespace(ns.clone());
        }
        if let Some(l) = self.limit {
            builder = builder.limit(l);
        }
        builder.execute()
    }
}

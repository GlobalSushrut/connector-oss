//! Shared request store — pulse, health, notifications, agents, workflows, watch.

#![allow(dead_code)]

use leptos::prelude::*;
use serde_json::Value;

use crate::api::{self, ApiError};
use crate::auth::AuthState;

#[derive(Debug, Clone, Copy)]
pub struct ReloadPulse(pub RwSignal<u64>);

impl ReloadPulse {
    fn new() -> Self {
        Self(RwSignal::new(0))
    }
    pub fn get(&self) -> u64 {
        self.0.get()
    }
    pub fn bump(&self) {
        self.0.update(|n| *n = n.wrapping_add(1));
    }
}

#[derive(Clone, Copy)]
pub struct SharedRequests {
    pub health: LocalResource<Result<Value, ApiError>>,
    pub notifications: LocalResource<Result<Value, ApiError>>,
    pub agents: LocalResource<Result<Value, ApiError>>,
    pub pulse: LocalResource<Result<Value, ApiError>>,
    pub workflows: LocalResource<Result<Value, ApiError>>,
    pub fix_queue: LocalResource<Result<Value, ApiError>>,
    pub watch_events: LocalResource<Result<Value, ApiError>>,
}

fn unauth() -> ApiError {
    ApiError {
        status: 0,
        code: None,
        message: "not authenticated".into(),
        detail: None,
        hints: vec![],
        docs: None,
    }
}

pub fn provide_shared_requests(auth: ReadSignal<AuthState>) {
    let pulse_sig = ReloadPulse::new();

    let health = LocalResource::new(move || {
        let _ = pulse_sig.get();
        let is_auth = auth.get().is_authenticated;
        async move {
            if !is_auth {
                return Err(unauth());
            }
            api::get_value("/monitor/health").await
        }
    });
    let notifications = LocalResource::new(move || {
        let _ = pulse_sig.get();
        let is_auth = auth.get().is_authenticated;
        async move {
            if !is_auth {
                return Err(unauth());
            }
            api::get_value("/notifications").await
        }
    });
    let agents = LocalResource::new(move || {
        let _ = pulse_sig.get();
        let is_auth = auth.get().is_authenticated;
        async move {
            if !is_auth {
                return Err(unauth());
            }
            api::get_value("/agents").await
        }
    });
    let pulse = LocalResource::new(move || {
        let _ = pulse_sig.get();
        let is_auth = auth.get().is_authenticated;
        async move {
            if !is_auth {
                return Err(unauth());
            }
            api::get_value("/operator/pulse").await
        }
    });
    let workflows = LocalResource::new(move || {
        let _ = pulse_sig.get();
        let is_auth = auth.get().is_authenticated;
        async move {
            if !is_auth {
                return Err(unauth());
            }
            api::get_value("/workflows").await
        }
    });
    let fix_queue = LocalResource::new(move || {
        let _ = pulse_sig.get();
        let is_auth = auth.get().is_authenticated;
        async move {
            if !is_auth {
                return Err(unauth());
            }
            api::get_value("/operator/fix/queue").await
        }
    });
    let watch_events = LocalResource::new(move || {
        let _ = pulse_sig.get();
        let is_auth = auth.get().is_authenticated;
        async move {
            if !is_auth {
                return Err(unauth());
            }
            api::get_value_q("/operator/watch/events", &[("limit", "100")]).await
        }
    });

    provide_context(pulse_sig);
    provide_context(SharedRequests {
        health,
        notifications,
        agents,
        pulse,
        workflows,
        fix_queue,
        watch_events,
    });
}

pub fn use_shared_requests() -> SharedRequests {
    expect_context::<SharedRequests>()
}

pub fn use_reload_pulse() -> ReloadPulse {
    expect_context::<ReloadPulse>()
}

pub fn bump_reload() {
    use_reload_pulse().bump();
}

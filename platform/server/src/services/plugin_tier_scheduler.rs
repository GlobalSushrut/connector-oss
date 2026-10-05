//! Phase 5.4 — cold / warm / hot tier state + cold-start **budget** gate with waiter coalescing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::Notify;

use crate::state::SharedState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalTier {
    Cold,
    Warming,
    Warm,
    Hot,
}

struct Slot {
    tier: ThermalTier,
    cold_gate: Arc<Notify>,
    last_touch_unix_ms: i64,
    admits: u64,
    /// Times this slot was demoted Warm/Hot → Cold due to idle (Phase 5.4.3).
    idle_demotions: u64,
    /// Warm/Hot → Cold when cgroup CPU growth stayed below threshold (Phase 5.4.3 remainder).
    cgroup_accelerated_idle_demotions: u64,
    cgroup_last_usage_usec: u64,
    cgroup_last_sample_unix_ms: i64,
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            tier: ThermalTier::Cold,
            cold_gate: Arc::new(Notify::new()),
            last_touch_unix_ms: 0,
            admits: 0,
            idle_demotions: 0,
            cgroup_accelerated_idle_demotions: 0,
            cgroup_last_usage_usec: 0,
            cgroup_last_sample_unix_ms: 0,
        }
    }
}

pub struct PluginTierScheduler {
    slots: DashMap<String, Arc<Mutex<Slot>>>,
    /// 0 = idle suspend disabled. Otherwise Warm/Hot slots older than this since last touch → Cold.
    idle_suspend_after_ms: u64,
    /// When true + cgroup parent resolvable + tier idle policy on, demote Warm/Hot early if CPU rate is very low.
    tier_cgroup_idle_demote: bool,
    /// Max CPU **`usage_usec`** growth per wall-clock second averaged over a sample window; below → “idle enough” for cgroup demotion.
    tier_cgroup_demote_max_usec_per_wall_s: u64,
    /// Minimum time since last tier touch before cgroup demotion may apply (ms).
    tier_cgroup_demote_min_idle_ms: u64,
    /// Minimum gap between cgroup samples (ms).
    tier_cgroup_demote_sample_gap_ms: u64,
}

fn plugin_has_ready_signal(plugin_id: &str) -> bool {
    connector_plugin_runtime::linux_cgroup::tier_cgroup_runner_usage_usec_for_plugin(plugin_id)
        .is_some()
}

async fn wait_plugin_ready_signal(plugin_id: &str, deadline: tokio::time::Instant) -> bool {
    if plugin_has_ready_signal(plugin_id) {
        return true;
    }
    let mut interval = tokio::time::interval(Duration::from_millis(50));
    loop {
        interval.tick().await;
        if plugin_has_ready_signal(plugin_id) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
    }
}

impl Default for PluginTierScheduler {
    fn default() -> Self {
        Self::from_env()
    }
}

impl PluginTierScheduler {
    #[inline]
    pub fn idle_suspend_policy_after_ms(&self) -> u64 {
        self.idle_suspend_after_ms
    }

    /// When idle policy > 0, returns the same **`ms`** and **`connector.plugin_idle_suspend_after_ms=…`**
    /// fragment **`connector-plugin-runtime`** adds to the microVM guest kernel cmdline (Phase **5.4.3**).
    pub fn tier_idle_suspend_guest_hint(&self) -> (Option<u64>, Option<String>) {
        let ms = self.idle_suspend_after_ms;
        if ms == 0 {
            (None, None)
        } else {
            (
                Some(ms),
                Some(format!("connector.plugin_idle_suspend_after_ms={ms}")),
            )
        }
    }

    /// Reads **`CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS`** (unset → `0` = feature off). Capped at 24h.
    pub fn from_env() -> Self {
        let idle_suspend_after_ms = std::env::var("CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
            .min(86_400_000);
        let tier_cgroup_idle_demote = tier_cgroup_idle_demote_from_env();
        let tier_cgroup_demote_max_usec_per_wall_s =
            std::env::var("CONNECTOR_PLUGIN_TIER_CGROUP_DEMOTE_MAX_USEC_PER_WALL_SEC")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(20_000)
                .max(100);
        let tier_cgroup_demote_min_idle_ms =
            std::env::var("CONNECTOR_PLUGIN_TIER_CGROUP_DEMOTE_MIN_IDLE_MS")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(30_000)
                .max(1_000);
        let tier_cgroup_demote_sample_gap_ms =
            std::env::var("CONNECTOR_PLUGIN_TIER_CGROUP_DEMOTE_SAMPLE_GAP_MS")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(10_000)
                .max(2_000);
        Self {
            slots: DashMap::new(),
            idle_suspend_after_ms,
            tier_cgroup_idle_demote,
            tier_cgroup_demote_max_usec_per_wall_s,
            tier_cgroup_demote_min_idle_ms,
            tier_cgroup_demote_sample_gap_ms,
        }
    }

    fn reap_idle_locked(&self, plugin_id: &str, g: &mut Slot) {
        let policy = self.idle_suspend_after_ms;
        if policy == 0 {
            return;
        }
        if !matches!(g.tier, ThermalTier::Warm | ThermalTier::Hot) {
            return;
        }
        if g.last_touch_unix_ms <= 0 {
            return;
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        let idle = now_ms.saturating_sub(g.last_touch_unix_ms);
        if idle >= policy as i64 {
            g.tier = ThermalTier::Cold;
            g.idle_demotions = g.idle_demotions.saturating_add(1);
            g.cgroup_last_usage_usec = 0;
            g.cgroup_last_sample_unix_ms = 0;
            return;
        }

        if self.tier_cgroup_idle_demote && idle >= self.tier_cgroup_demote_min_idle_ms as i64 {
            if let Some(cur_usec) =
                connector_plugin_runtime::linux_cgroup::tier_cgroup_runner_usage_usec_for_plugin(
                    plugin_id,
                )
            {
                if g.cgroup_last_sample_unix_ms > 0 {
                    let wall_ms = now_ms.saturating_sub(g.cgroup_last_sample_unix_ms) as u64;
                    if wall_ms >= self.tier_cgroup_demote_sample_gap_ms {
                        let delta_usec = cur_usec.saturating_sub(g.cgroup_last_usage_usec);
                        let rate_usec_per_s = if wall_ms > 0 {
                            delta_usec.saturating_mul(1000).saturating_div(wall_ms)
                        } else {
                            u64::MAX
                        };
                        if rate_usec_per_s < self.tier_cgroup_demote_max_usec_per_wall_s {
                            g.tier = ThermalTier::Cold;
                            g.idle_demotions = g.idle_demotions.saturating_add(1);
                            g.cgroup_accelerated_idle_demotions =
                                g.cgroup_accelerated_idle_demotions.saturating_add(1);
                            g.cgroup_last_usage_usec = 0;
                            g.cgroup_last_sample_unix_ms = 0;
                            return;
                        }
                    }
                }
                g.cgroup_last_usage_usec = cur_usec;
                g.cgroup_last_sample_unix_ms = now_ms;
            }
        }
    }

    fn idle_suspend_json(&self, g: &Slot) -> Value {
        let policy = self.idle_suspend_after_ms;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let idle_ms = if g.last_touch_unix_ms > 0 {
            (now_ms.saturating_sub(g.last_touch_unix_ms).max(0)) as u64
        } else {
            0
        };
        if policy == 0 {
            return json!({
                "policy_after_ms": 0,
                "state": "off",
            });
        }
        let state = match g.tier {
            ThermalTier::Cold => "cold",
            ThermalTier::Warming => "warming",
            ThermalTier::Warm => "warm",
            ThermalTier::Hot => "hot",
        };
        json!({
            "policy_after_ms": policy,
            "idle_ms_since_touch": idle_ms,
            "idle_demotions": g.idle_demotions,
            "cgroup_accelerated_idle_demotions": g.cgroup_accelerated_idle_demotions,
            "state": state,
        })
    }

    pub fn touch(&self, plugin_id: &str) {
        let key = plugin_id.to_string();
        let cell: Arc<Mutex<Slot>> = {
            let rm = self
                .slots
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(Slot::default())));
            rm.value().clone()
        };
        let mut g = cell.lock().unwrap();
        g.last_touch_unix_ms = chrono::Utc::now().timestamp_millis();
        g.cgroup_last_usage_usec = 0;
        g.cgroup_last_sample_unix_ms = 0;
        if matches!(g.tier, ThermalTier::Warm | ThermalTier::Hot) {
            g.tier = ThermalTier::Hot;
        }
    }

    /// Wait for a real ready signal (cgroup runner usage) up to `cold_start_budget_ms`.
    /// Does **not** sleep-and-claim Warm. No signal → remains Cold.
    pub async fn admit_cold_start(&self, plugin_id: &str, cold_start_budget_ms: u32) -> bool {
        let cap_ms = cold_start_budget_ms.clamp(1, 60_000) as u64;
        let key = plugin_id.to_string();
        let cell: Arc<Mutex<Slot>> = {
            let rm = self
                .slots
                .entry(key)
                .or_insert_with(|| Arc::new(Mutex::new(Slot::default())));
            rm.value().clone()
        };

        loop {
            enum Step {
                ReturnReady,
                ColdWait { gate: Arc<Notify> },
                WarmingWait { gate: Arc<Notify>, cap_ms: u64 },
            }
            let step = {
                let mut g = cell.lock().unwrap();
                self.reap_idle_locked(plugin_id, &mut g);
                match g.tier {
                    ThermalTier::Warm | ThermalTier::Hot => Step::ReturnReady,
                    ThermalTier::Cold => {
                        g.tier = ThermalTier::Warming;
                        Step::ColdWait {
                            gate: g.cold_gate.clone(),
                        }
                    }
                    ThermalTier::Warming => Step::WarmingWait {
                        gate: g.cold_gate.clone(),
                        cap_ms,
                    },
                }
            };
            match step {
                Step::ReturnReady => return true,
                Step::ColdWait { gate } => {
                    let deadline = tokio::time::Instant::now() + Duration::from_millis(cap_ms);
                    let ready = wait_plugin_ready_signal(plugin_id, deadline).await;
                    let mut g2 = cell.lock().unwrap();
                    if ready {
                        g2.tier = ThermalTier::Warm;
                        g2.admits = g2.admits.saturating_add(1);
                        g2.last_touch_unix_ms = chrono::Utc::now().timestamp_millis();
                        gate.notify_waiters();
                        return true;
                    }
                    g2.tier = ThermalTier::Cold;
                    gate.notify_waiters();
                    return false;
                }
                Step::WarmingWait { gate, cap_ms } => {
                    let _ =
                        tokio::time::timeout(Duration::from_millis(cap_ms), gate.notified()).await;
                    let g2 = cell.lock().unwrap();
                    return matches!(g2.tier, ThermalTier::Warm | ThermalTier::Hot);
                }
            }
        }
    }

    pub fn snapshot_json(&self) -> Value {
        let mut rows = Vec::new();
        for r in self.slots.iter() {
            if let Ok(mut g) = r.value().try_lock() {
                self.reap_idle_locked(r.key(), &mut g);
                let idle_suspend = self.idle_suspend_json(&g);
                rows.push(json!({
                    "plugin_id": r.key(),
                    "tier": g.tier,
                    "admits": g.admits,
                    "last_touch_unix_ms": g.last_touch_unix_ms,
                    "idle_suspend": idle_suspend,
                }));
            }
        }
        json!({ "plugins": rows })
    }

    /// JSON object **`vendor/slug` → `"cold"` \| `"warm"`** for host microVM vsock tier replies
    /// (**`CONNECTOR_MICROVM_TIER_STATE_FILE`**, Phase **5.4.3** — `connector-plugin-runtime` **`read_tier_for_plugin`**).
    pub fn microvm_tier_signal_state_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        for r in self.slots.iter() {
            if let Ok(mut g) = r.value().try_lock() {
                self.reap_idle_locked(r.key(), &mut g);
                let v = match g.tier {
                    ThermalTier::Cold => "cold",
                    ThermalTier::Warming | ThermalTier::Warm | ThermalTier::Hot => "warm",
                };
                m.insert(r.key().clone(), json!(v));
            }
        }
        m
    }

    /// Aggregate thermal mix + counters across tracked plugins (Phase **5.4.3** — in-memory thermal mix;
    /// optional cgroup-accelerated idle demotion when **`CONNECTOR_PLUGIN_TIER_CGROUP_IDLE_DEMOTE=1`**).
    pub fn utilization_summary_json(&self) -> Value {
        let mut cold: u64 = 0;
        let mut warming: u64 = 0;
        let mut warm: u64 = 0;
        let mut hot: u64 = 0;
        let mut idle_demotions_total: u64 = 0;
        let mut cgroup_accelerated_idle_demotions_total: u64 = 0;
        let mut admits_total: u64 = 0;
        for r in self.slots.iter() {
            if let Ok(mut g) = r.value().try_lock() {
                self.reap_idle_locked(r.key(), &mut g);
                match g.tier {
                    ThermalTier::Cold => cold += 1,
                    ThermalTier::Warming => warming += 1,
                    ThermalTier::Warm => warm += 1,
                    ThermalTier::Hot => hot += 1,
                }
                idle_demotions_total = idle_demotions_total.saturating_add(g.idle_demotions);
                cgroup_accelerated_idle_demotions_total = cgroup_accelerated_idle_demotions_total
                    .saturating_add(g.cgroup_accelerated_idle_demotions);
                admits_total = admits_total.saturating_add(g.admits);
            }
        }
        let tracked = cold + warming + warm + hot;
        let mut out = json!({
            "tracked_plugins": tracked,
            "by_tier": {
                "cold": cold,
                "warming": warming,
                "warm": warm,
                "hot": hot,
            },
            "idle_demotions_total": idle_demotions_total,
            "cgroup_accelerated_idle_demotions_total": cgroup_accelerated_idle_demotions_total,
            "cold_start_admits_total": admits_total,
            "scope": "in_memory_scheduler",
        });
        if self.tier_cgroup_idle_demote && self.idle_suspend_after_ms > 0 {
            if let Some(m) = out.as_object_mut() {
                m.insert(
                    "scope".into(),
                    json!("in_memory_scheduler+cgroup_idle_demote"),
                );
            }
        }
        out
    }

    /// Single-plugin slice for dashboards (`plugins/status`, Service Map).
    pub fn hint_json(&self, plugin_id: &str) -> Value {
        let (guest_idle_ms, guest_idle_cmdline) = self.tier_idle_suspend_guest_hint();
        let Some(cell) = self.slots.get(plugin_id) else {
            return Value::Null;
        };
        let Ok(mut g) = cell.value().try_lock() else {
            return Value::Null;
        };
        self.reap_idle_locked(plugin_id, &mut g);
        let idle_suspend = self.idle_suspend_json(&g);
        json!({
            "tier": g.tier,
            "admits": g.admits,
            "last_touch_unix_ms": g.last_touch_unix_ms,
            "idle_suspend": idle_suspend,
            "tier_idle_suspend_policy_ms_for_guest": guest_idle_ms,
            "tier_idle_suspend_guest_cmdline_fragment": guest_idle_cmdline,
        })
    }
}

/// Writes atomic JSON (**`microvm_tier_signal_state_map`**) for **`CONNECTOR_MICROVM_VSOCK_TIER_SIGNAL`**
/// host listeners in **`connector-plugin-runtime`**.
pub fn write_microvm_tier_state_snapshot_to_path(
    scheduler: &PluginTierScheduler,
    path: &str,
) -> std::io::Result<()> {
    let map = scheduler.microvm_tier_signal_state_map();
    let body = serde_json::to_string(&Value::Object(map)).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("tier state json: {e}"),
        )
    })?;
    let path_pb = std::path::Path::new(path);
    if let Some(dir) = path_pb.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let tmp = format!("{}.tmp", path.trim());
    std::fs::write(&tmp, format!("{body}\n"))?;
    std::fs::rename(&tmp, path_pb)?;
    Ok(())
}

/// Non-empty **`CONNECTOR_MICROVM_TIER_STATE_FILE`** on the connector-platform host.
pub fn microvm_tier_state_file_path_from_env() -> Option<String> {
    std::env::var("CONNECTOR_MICROVM_TIER_STATE_FILE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// **`CONNECTOR_MICROVM_TIER_STATE_SYNC_MS`** (clamped **500..=120_000**), default **2000**.
pub fn microvm_tier_state_sync_interval_ms_from_env() -> u64 {
    std::env::var("CONNECTOR_MICROVM_TIER_STATE_SYNC_MS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(2_000)
        .clamp(500, 120_000)
}

/// Fire-and-forget refresh after **`POST …/plugin-tier-touch`** / **`…/plugin-tier-admit`** so vsock
/// **`tier_signal`** is not stuck until the periodic sync tick.
pub fn schedule_microvm_tier_state_file_write(scheduler: Arc<PluginTierScheduler>) {
    let Some(path) = microvm_tier_state_file_path_from_env() else {
        return;
    };
    tokio::spawn(async move {
        let sched = scheduler;
        let p = path.clone();
        match tokio::task::spawn_blocking(move || {
            write_microvm_tier_state_snapshot_to_path(&*sched, &p)
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::debug!(
                error = %e,
                path = %path,
                "microVM tier state immediate write failed"
            ),
            Err(e) => tracing::debug!(
                error = %e,
                "microVM tier state immediate write join failed"
            ),
        }
    });
}

fn tier_cgroup_idle_demote_from_env() -> bool {
    let raw = std::env::var("CONNECTOR_PLUGIN_TIER_CGROUP_IDLE_DEMOTE").unwrap_or_default();
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub async fn get_plugin_tier_scheduler(State(state): State<SharedState>) -> Json<Value> {
    let policy_ms = state.plugin_tier_scheduler.idle_suspend_policy_after_ms();
    let (guest_idle_ms, guest_idle_cmdline) =
        state.plugin_tier_scheduler.tier_idle_suspend_guest_hint();
    let mut utilization = state.plugin_tier_scheduler.utilization_summary_json();
    if let Some(cg) = connector_plugin_runtime::linux_cgroup::tier_cgroup_scan_from_env() {
        if let Some(m) = utilization.as_object_mut() {
            m.insert("cgroup_v2".into(), cg);
            if let Some(scope) = m.get("scope").and_then(|v| v.as_str()) {
                if scope.starts_with("in_memory_scheduler") && !scope.contains("cgroup_v2_scan") {
                    m.insert("scope".into(), json!(format!("{scope}+cgroup_v2_scan")));
                }
            }
        }
    }
    let tier_sync = match microvm_tier_state_file_path_from_env() {
        Some(_) => json!({
            "enabled": true,
            "interval_ms": microvm_tier_state_sync_interval_ms_from_env(),
            "immediate_refresh_on_tier_touch": true,
        }),
        None => json!({
            "enabled": false,
            "interval_ms": serde_json::Value::Null,
            "immediate_refresh_on_tier_touch": false,
        }),
    };
    Json(json!({
        "ok": true,
        "data": state.plugin_tier_scheduler.snapshot_json(),
        "utilization": utilization,
        "idle_suspend_policy_after_ms": policy_ms,
        "tier_idle_suspend_policy_ms_for_guest": guest_idle_ms,
        "tier_idle_suspend_guest_cmdline_fragment": guest_idle_cmdline,
        "microvm_tier_state_sync": tier_sync,
        "hint": "POST …/plugin-tier-admit before spawn; POST …/plugin-tier-touch after successful run (connectorctl plugin run --dev). Idle suspend: CONNECTOR_PLUGIN_IDLE_SUSPEND_AFTER_MS → Warm/Hot → Cold after idle; when >0, microVM boot args include tier_idle_suspend_guest_cmdline_fragment (connector-vm-agent logs; Phase 5.4.3 guest visibility). Optional cgroup-accelerated demotion: CONNECTOR_PLUGIN_TIER_CGROUP_IDLE_DEMOTE=1 + CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT + runner-<plugin>-* cgroups → Warm/Hot may demote early when CPU usage growth stays below CONNECTOR_PLUGIN_TIER_CGROUP_DEMOTE_MAX_USEC_PER_WALL_SEC (see env). utilization.by_tier is in-memory thermal mix; optional utilization.cgroup_v2 samples runner-* children when CONNECTOR_PLUGIN_TIER_CGROUP_SCAN=1 and CONNECTOR_PLUGIN_SUBPROCESS_CGROUP_PARENT is set (Phase 5.4.3 + 5.8). When CONNECTOR_MICROVM_TIER_STATE_FILE is set on connector-platform, the kernel periodically writes vendor/slug→cold|warm JSON for CONNECTOR_MICROVM_VSOCK_TIER_SIGNAL host replies (CONNECTOR_MICROVM_TIER_STATE_SYNC_MS, default 2000); admit/touch also trigger an immediate best-effort write.",
    }))
}

fn require_admin_or_dev(headers: &HeaderMap) -> Result<(), Value> {
    if crate::services::runtime_control::dev_auth_bypass_allowed() {
        return Ok(());
    }
    let Some(claims) = crate::auth::extract_claims(headers) else {
        return Err(json!({"ok": false, "error": "Unauthorized"}));
    };
    let role = crate::auth::PlatformRole::from_str(&claims.role);
    if role.rank() < crate::auth::PlatformRole::Admin.rank() {
        return Err(json!({"ok": false, "error": "Admin privileges required"}));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct PluginTierAdmitBody {
    pub plugin_id: String,
    #[serde(default)]
    pub cold_start_budget_ms: Option<u32>,
}

/// Runs [`PluginTierScheduler::admit_cold_start`] for a remote caller (e.g. `connectorctl plugin run --dev`).
pub async fn post_plugin_tier_admit(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<PluginTierAdmitBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let plugin_id = body.plugin_id.trim().to_string();
    if plugin_id.is_empty() || plugin_id.split('/').count() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "plugin_id must be vendor/slug"})),
        ));
    }
    let budget = body.cold_start_budget_ms.unwrap_or(500).clamp(1, 60_000);
    // C9 / residual T0: under harden, plugin cold-start cannot imply ambient shell/unrestricted net.
    if crate::kernel::agent_principal::intelligence_hardening_on() {
        let ambient = std::env::var("CONNECTOR_PLUGIN_AMBIENT_SHELL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let unrestricted = std::env::var("CONNECTOR_PLUGIN_UNRESTRICTED_NET")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if ambient || unrestricted {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "error": "plugin_ambient_forbidden_under_harden",
                    "denial_reason": "plugin_side_door",
                    "honesty": "Unset CONNECTOR_PLUGIN_AMBIENT_SHELL / CONNECTOR_PLUGIN_UNRESTRICTED_NET under harden",
                })),
            ));
        }
    }
    let ready = state
        .plugin_tier_scheduler
        .admit_cold_start(&plugin_id, budget)
        .await;
    schedule_microvm_tier_state_file_write(state.plugin_tier_scheduler.clone());
    Ok(Json(json!({
        "ok": true,
        "plugin_id": plugin_id,
        "cold_start_budget_ms": budget,
        "ready": ready,
        "honesty": if ready {
            "Warm — cgroup runner usage observed"
        } else {
            "Cold — no live cgroup/process signal within budget (install is not a boot)"
        },
    })))
}

#[derive(Debug, Deserialize)]
pub struct PluginTierTouchBody {
    pub plugin_id: String,
}

/// Marks a plugin as recently active ([`PluginTierScheduler::touch`]) — e.g. after a successful dev run.
pub async fn post_plugin_tier_touch(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<PluginTierTouchBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Err((StatusCode::FORBIDDEN, Json(e)));
    }
    let plugin_id = body.plugin_id.trim().to_string();
    if plugin_id.is_empty() || plugin_id.split('/').count() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "plugin_id must be vendor/slug"})),
        ));
    }
    state.plugin_tier_scheduler.touch(&plugin_id);
    schedule_microvm_tier_state_file_write(state.plugin_tier_scheduler.clone());
    Ok(Json(json!({ "ok": true, "plugin_id": plugin_id })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utilization_summary_empty_scheduler() {
        let s = PluginTierScheduler::from_env();
        let v = s.utilization_summary_json();
        assert_eq!(v["tracked_plugins"], json!(0));
        assert_eq!(v["idle_demotions_total"], json!(0));
        assert_eq!(v["cgroup_accelerated_idle_demotions_total"], json!(0));
        assert_eq!(v["cold_start_admits_total"], json!(0));
    }

    #[test]
    fn microvm_tier_signal_state_map_cold_vs_warm() {
        let s = PluginTierScheduler {
            slots: DashMap::new(),
            idle_suspend_after_ms: 0,
            tier_cgroup_idle_demote: false,
            tier_cgroup_demote_max_usec_per_wall_s: 20_000,
            tier_cgroup_demote_min_idle_ms: 30_000,
            tier_cgroup_demote_sample_gap_ms: 10_000,
        };
        let pid = "acme/demo".to_string();
        let cell = Arc::new(Mutex::new(Slot {
            tier: ThermalTier::Cold,
            ..Default::default()
        }));
        s.slots.insert(pid.clone(), cell);
        let m = s.microvm_tier_signal_state_map();
        assert_eq!(m.get(&pid).and_then(|x| x.as_str()), Some("cold"));

        if let Some(c) = s.slots.get(&pid) {
            let mut g = c.lock().unwrap();
            g.tier = ThermalTier::Warm;
        }
        let m2 = s.microvm_tier_signal_state_map();
        assert_eq!(m2.get(&pid).and_then(|x| x.as_str()), Some("warm"));
    }
}

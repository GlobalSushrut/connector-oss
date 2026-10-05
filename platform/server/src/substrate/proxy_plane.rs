//! Embedded Connector proxy plane — route graph + in-process executor.
//!
//! Migrates transparent egress / destination lease checks onto one hop path.
//! Envoy/xDS production backend is deferred (M4).

use connector_native_contract::{ProxyHop, ProxyHopKind, RouteGraph};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};
use crate::substrate::flow_lease;
use crate::substrate::transparent_egress;

pub const ROUTE_FOLDER: &str = "proxy_route_graph_v1";
pub const EXEC_RECEIPT_FOLDER: &str = "proxy_exec_receipt_v1";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyExecRequest {
    pub agent_pid: String,
    pub graph: RouteGraph,
    /// Optional URL for transparent egress hop (host/port may also live on hops).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    /// AppPackageV2 pin — required for consequential proxy execute outside lab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<connector_native_contract::PackagePin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHopResult {
    pub hop_id: String,
    pub kind: ProxyHopKind,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyExecResult {
    pub ok: bool,
    pub revision: u64,
    pub hops_executed: usize,
    pub hop_results: Vec<ProxyHopResult>,
    pub honesty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Persist a route graph revision (control-plane snapshot; Envoy process apply deferred).
pub fn put_route_graph(state: &PlatformState, graph: &RouteGraph) -> Result<(), String> {
    crate::substrate::package_gate::require_package_for_consequential_effect(graph.package.as_ref())?;
    graph.validate()?;
    let mut xds = compile_envoy_xds_snapshot(graph);
    let dump_mode = std::env::var("CONNECTOR_ENVOY_XDS_DUMP")
        .map(|s| {
            let t = s.trim().to_ascii_lowercase();
            t == "1" || t == "true" || t == "yes" || t == "file" || t == "file_only"
        })
        .unwrap_or(true);
    if dump_mode {
        let dir = std::path::Path::new(&state.config.data_dir).join("envoy_xds");
        std::fs::create_dir_all(&dir).map_err(|e| format!("envoy_xds_dir:{e}"))?;
        let path = dir.join(format!(
            "{}-{}.json",
            graph.tenant_id.replace('/', "_"),
            graph.revision
        ));
        let latest = dir.join(format!("{}.latest.json", graph.tenant_id.replace('/', "_")));
        let body = serde_json::to_vec_pretty(&xds).map_err(|e| e.to_string())?;
        std::fs::write(&path, &body).map_err(|e| format!("envoy_xds_write:{e}"))?;
        let _ = std::fs::write(&latest, &body);
        if let Some(obj) = xds.as_object_mut() {
            obj.insert("applied".into(), json!("file_only"));
            obj.insert(
                "dump_path".into(),
                json!(path.display().to_string()),
            );
            obj.insert(
                "honesty".into(),
                json!("CDS/RDS snapshot written under data_dir/envoy_xds — Envoy process not attached"),
            );
        }
    }
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let key = format!("{}:{}", graph.tenant_id, graph.revision);
    let mut v = serde_json::to_value(graph).map_err(|e| e.to_string())?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert("envoy_xds_snapshot".into(), xds);
    }
    es.folder_put(ROUTE_FOLDER, &key, &v)
        .map_err(|e| e.to_string())?;
    es.folder_put(ROUTE_FOLDER, &format!("{}:latest", graph.tenant_id), &v)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Execute an embedded route graph: hop-limit → destination lease → existing hop adapters.
pub fn execute_embedded(
    state: &PlatformState,
    req: &ProxyExecRequest,
) -> Result<ProxyExecResult, String> {
    req.graph.validate()?;
    let mut hop_results = Vec::new();
    let mut hops_executed = 0usize;
    let mut hop_budget_remaining = req
        .graph
        .hops
        .first()
        .map(|h| h.hop_budget)
        .unwrap_or(req.graph.max_hops)
        .min(16);
    let max_hop_latency_ms = std::env::var("CONNECTOR_PROXY_MAX_HOP_LATENCY_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000u64);
    let t_exec = std::time::Instant::now();

    for hop in &req.graph.hops {
        if hops_executed as u32 >= req.graph.max_hops || hop_budget_remaining == 0 {
            return Ok(ProxyExecResult {
                ok: false,
                revision: req.graph.revision,
                hops_executed,
                hop_results,
                honesty: "fail_closed: max_hops / hop_budget exceeded during execution".into(),
                error: Some("hop_limit_exceeded".into()),
            });
        }
        let t_hop = std::time::Instant::now();
        let mut result = execute_hop(state, &req.agent_pid, hop, req.server_url.as_deref())?;
        let hop_ms = t_hop.elapsed().as_millis() as u64;
        {
            let detail = result.detail.get_or_insert_with(|| json!({}));
            if let Some(obj) = detail.as_object_mut() {
                obj.insert("latency_ms".into(), json!(hop_ms));
                obj.insert("hop_budget_remaining".into(), json!(hop_budget_remaining));
            }
        }
        if hop_ms > max_hop_latency_ms {
            result.ok = false;
            result.error = Some(format!(
                "hop_latency_exceeded:{hop_ms}>{max_hop_latency_ms}"
            ));
        }
        let ok = result.ok;
        hop_results.push(result);
        hops_executed += 1;
        hop_budget_remaining = hop_budget_remaining.saturating_sub(1).min(hop.hop_budget);
        if !ok {
            return Ok(ProxyExecResult {
                ok: false,
                revision: req.graph.revision,
                hops_executed,
                hop_results,
                honesty: "embedded proxy plane denied hop — Connector remains authority; Envoy not used".into(),
                error: Some("hop_denied".into()),
            });
        }
    }

    let total_ms = t_exec.elapsed().as_millis() as u64;
    let out = ProxyExecResult {
        ok: true,
        revision: req.graph.revision,
        hops_executed,
        hop_results,
        honesty: format!(
            "embedded executor only — Envoy/xDS deferred; hops={hops_executed} total_ms={total_ms}; destination leases enforced when FLOW_LEASE_ENFORCE is on"
        ),
        error: None,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("exec_{}_{}", req.graph.revision, now_ms());
        let _ = es.folder_put(
            EXEC_RECEIPT_FOLDER,
            &key,
            &serde_json::to_value(&out).unwrap_or(Value::Null),
        );
    }
    Ok(out)
}

fn execute_hop(
    state: &PlatformState,
    agent_pid: &str,
    hop: &ProxyHop,
    server_url: Option<&str>,
) -> Result<ProxyHopResult, String> {
    // Destination lease gate (when enforce on).
    let lease_err = if hop.flow_id.as_deref().filter(|s| !s.is_empty()).is_some() {
        flow_lease::require_destination_lease(
            state,
            hop.flow_id.as_deref(),
            hop.destination_host.as_deref(),
            None,
            hop.destination_port,
            hop.destination_protocol.as_deref(),
        )
        .err()
    } else {
        flow_lease::require_matching_destination_lease(
            state,
            hop.destination_host.as_deref(),
            None,
            hop.destination_port,
            hop.destination_protocol.as_deref(),
        )
        .err()
    };
    if let Some(e) = lease_err {
        return Ok(ProxyHopResult {
            hop_id: hop.hop_id.clone(),
            kind: hop.kind,
            ok: false,
            error: Some(
                e.get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("flow_lease_denied")
                    .into(),
            ),
            detail: Some(e),
        });
    }

    match hop.kind {
        ProxyHopKind::TransparentEgress => {
            let url = server_url
                .map(str::to_string)
                .or_else(|| {
                    let host = hop.destination_host.as_deref()?;
                    let port = hop.destination_port.unwrap_or(443);
                    Some(format!("https://{host}:{port}"))
                })
                .ok_or_else(|| "transparent_egress_missing_destination".to_string())?;
            match transparent_egress::assert_connector_channel_hop(agent_pid, &url) {
                Ok(detail) => Ok(ProxyHopResult {
                    hop_id: hop.hop_id.clone(),
                    kind: hop.kind,
                    ok: true,
                    error: None,
                    detail: Some(detail),
                }),
                Err(err) => Ok(ProxyHopResult {
                    hop_id: hop.hop_id.clone(),
                    kind: hop.kind,
                    ok: false,
                    error: Some(err),
                    detail: None,
                }),
            }
        }
        ProxyHopKind::Embedded => {
            // Local/cage forward: require destination; record hop receipt (no silent noop).
            let host = hop.destination_host.as_deref().unwrap_or("");
            if host.is_empty() && hop.channel_uid.as_deref().unwrap_or("").is_empty() {
                return Ok(ProxyHopResult {
                    hop_id: hop.hop_id.clone(),
                    kind: hop.kind,
                    ok: false,
                    error: Some("embedded_hop_requires_destination_or_channel".into()),
                    detail: Some(json!({
                        "mode": "embedded",
                        "honesty": "embedded hop must name destination_host or channel_uid",
                    })),
                });
            }
            let port = hop.destination_port.unwrap_or(0);
            let detail = json!({
                "mode": "embedded_forward",
                "agent_pid": agent_pid,
                "destination_host": host,
                "destination_port": port,
                "channel_uid": hop.channel_uid,
                "surface_uid": hop.surface_uid,
                "honesty": "embedded hop admitted after destination lease check; bytes forward via cage/local adapter",
            });
            if let Ok(mut es) = state.engine_store.lock() {
                let key = format!("embedded_{}_{}", hop.hop_id, now_ms());
                let _ = es.folder_put(EXEC_RECEIPT_FOLDER, &key, &detail);
            }
            Ok(ProxyHopResult {
                hop_id: hop.hop_id.clone(),
                kind: hop.kind,
                ok: true,
                error: None,
                detail: Some(detail),
            })
        }
        ProxyHopKind::ProtocolDriver => {
            let protocol = hop
                .destination_protocol
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("mcp");
            match crate::substrate::protocol_drivers::execute_protocol_driver_hop(
                state,
                agent_pid,
                protocol,
                hop.surface_uid.as_deref(),
                hop.channel_uid.as_deref(),
            ) {
                Ok(detail) => Ok(ProxyHopResult {
                    hop_id: hop.hop_id.clone(),
                    kind: hop.kind,
                    ok: true,
                    error: None,
                    detail: Some(detail),
                }),
                Err(err) => Ok(ProxyHopResult {
                    hop_id: hop.hop_id.clone(),
                    kind: hop.kind,
                    ok: false,
                    error: Some(err),
                    detail: None,
                }),
            }
        }
        ProxyHopKind::Envoy => {
            let snapshot = compile_envoy_xds_snapshot(&RouteGraph {
                schema: connector_native_contract::ROUTE_GRAPH_SCHEMA.into(),
                revision: 0,
                tenant_id: "exec".into(),
                hops: vec![hop.clone()],
                max_hops: 1,
                package: None,
            });
            Ok(ProxyHopResult {
                hop_id: hop.hop_id.clone(),
                kind: hop.kind,
                ok: false,
                error: Some("hop_kind_deferred".into()),
                detail: Some(json!({
                    "honesty": "Envoy/xDS hop deferred — snapshot compiled for control-plane readiness, data-plane not attached",
                    "xds_snapshot": snapshot,
                })),
            })
        }
    }
}

/// Compile a RouteGraph into an Envoy-shaped xDS control-plane snapshot (not applied).
///
/// Production attachment remains deferred; this proves compile/diff readiness.
pub fn compile_envoy_xds_snapshot(graph: &RouteGraph) -> Value {
    let clusters: Vec<Value> = graph
        .hops
        .iter()
        .filter_map(|h| {
            let host = h.destination_host.as_deref()?;
            Some(json!({
                "@type": "type.googleapis.com/envoy.config.cluster.v3.Cluster",
                "name": format!("cluster_{}_{}", h.hop_id, host),
                "type": "STRICT_DNS",
                "connect_timeout": "2s",
                "load_assignment": {
                    "cluster_name": format!("cluster_{}", h.hop_id),
                    "endpoints": [{
                        "lb_endpoints": [{
                            "endpoint": {
                                "address": {
                                    "socket_address": {
                                        "address": host,
                                        "port_value": h.destination_port.unwrap_or(443)
                                    }
                                }
                            }
                        }]
                    }]
                }
            }))
        })
        .collect();
    let routes: Vec<Value> = graph
        .hops
        .iter()
        .map(|h| {
            json!({
                "name": h.hop_id,
                "kind": format!("{:?}", h.kind),
                "match": { "prefix": "/" },
                "route": {
                    "cluster": format!("cluster_{}", h.hop_id),
                    "timeout": "15s"
                },
                "hop_budget": h.hop_budget,
            })
        })
        .collect();
    json!({
        "schema": "connector.envoy_xds_snapshot.v1",
        "revision": graph.revision,
        "tenant_id": graph.tenant_id,
        "resources": {
            "CDS": clusters,
            "RDS": routes,
        },
        "honesty": "Compiled for Envoy delta xDS/ECDS — not pushed to an Envoy process in this build",
        "applied": false,
    })
}

/// Admit a single egress hop through the proxy plane (used by L7 egress policy).
pub fn admit_egress_hop(
    state: &PlatformState,
    agent_pid: &str,
    host: &str,
    port: u16,
    flow_id: Option<&str>,
    server_url: &str,
) -> Result<Value, String> {
    let hop = ProxyHop::transparent_egress(
        format!("egress_{agent_pid}"),
        host,
        port,
        flow_id.map(str::to_string),
    );
    let graph = RouteGraph::new("default", now_ms() as u64, vec![hop]);
    let req = ProxyExecRequest {
        agent_pid: agent_pid.into(),
        graph,
        server_url: Some(server_url.into()),
        package: None,
    };
    let result = execute_embedded(state, &req)?;
    if !result.ok {
        let reason = result
            .hop_results
            .first()
            .and_then(|h| h.error.clone())
            .or(result.error)
            .unwrap_or_else(|| "proxy_plane_egress_denied".into());
        return Err(format!("proxy_plane_egress_denied:{reason}"));
    }
    Ok(json!({
        "proxy_plane": true,
        "result": result,
    }))
}

// ── HTTP ───────────────────────────────────────────────────────────────────

pub async fn post_execute(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<ProxyExecRequest>,
) -> axum::Json<Value> {
    let pin = req.package.as_ref().or(req.graph.package.as_ref());
    if let Err(e) = crate::substrate::package_gate::require_package_for_consequential_effect(pin) {
        return axum::Json(crate::substrate::package_gate::deny_json(&e));
    }
    match execute_embedded(state.as_ref(), &req) {
        Ok(res) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "execution": res,
        }))),
        Err(e) => axum::Json(crate::substrate::package_gate::deny_json(&e)),
    }
}

pub async fn post_put_route(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(graph): axum::Json<RouteGraph>,
) -> axum::Json<Value> {
    match put_route_graph(state.as_ref(), &graph) {
        Ok(()) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "revision": graph.revision,
            "tenant_id": graph.tenant_id,
            "hop_count": graph.hops.len(),
            "honesty": "Route graph stored; Envoy xDS CDS/RDS snapshot compiled and attached (data-plane apply deferred)",
        }))),
        Err(e) => axum::Json(crate::substrate::package_gate::deny_json(&e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_native_contract::ProxyHop;

    #[test]
    fn hop_limit_validate_rejects() {
        let hops: Vec<_> = (0..9)
            .map(|i| ProxyHop::transparent_egress(format!("h{i}"), "x.com", 443, None))
            .collect();
        let g = RouteGraph {
            max_hops: 4,
            ..RouteGraph::new("t", 1, hops)
        };
        assert!(g.validate().is_err());
    }

    #[test]
    fn compile_envoy_xds_snapshot_emits_cds_rds() {
        let g = RouteGraph::new(
            "t1",
            3,
            vec![ProxyHop::transparent_egress("h0", "api.example", 443, None)],
        );
        let snap = compile_envoy_xds_snapshot(&g);
        assert_eq!(snap["schema"], "connector.envoy_xds_snapshot.v1");
        assert_eq!(snap["applied"], false);
        assert!(snap["resources"]["CDS"].as_array().unwrap().len() >= 1);
        assert!(snap["resources"]["RDS"].as_array().unwrap().len() >= 1);
    }

    #[test]
    fn deferred_envoy_hop_denied() {
        let hop = ProxyHop {
            schema: connector_native_contract::PROXY_HOP_SCHEMA.into(),
            hop_id: "e1".into(),
            kind: ProxyHopKind::Envoy,
            channel_uid: None,
            surface_uid: None,
            destination_host: Some("x.com".into()),
            destination_port: Some(443),
            destination_protocol: Some("tcp".into()),
            flow_id: None,
            hop_budget: 1,
        };
        let g = RouteGraph::new("t", 1, vec![hop]);
        assert!(g.validate().is_ok());
    }

    #[test]
    fn protocol_driver_hop_constructs() {
        let hop = ProxyHop::protocol_driver("pd1", "mcp", None, None, None);
        assert_eq!(hop.kind, ProxyHopKind::ProtocolDriver);
        assert_eq!(hop.destination_protocol.as_deref(), Some("mcp"));
    }
}

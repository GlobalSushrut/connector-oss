//! Live kernel + billing ledger injection for Monitor/overview SOE JSON.
use chrono::Datelike;
use serde_json::{json, Value};

use crate::state::SharedState;

pub struct KernelFleetSnapshot {
    pub agents: usize,
    pub sessions: usize,
    pub packets: usize,
    pub audit_entries: usize,
    pub fleet_cost_usd: f64,
}

pub fn kernel_fleet_snapshot(state: &SharedState) -> KernelFleetSnapshot {
    let k = state.kernel.lock().unwrap();
    let agents = k.agents().len();
    let sessions = k.sessions().len();
    let packets = k.packet_count();
    let audit_entries = k.audit_log().len();
    let fleet_cost_usd: f64 = k.agents().values().map(|a| a.total_cost_usd).sum();
    KernelFleetSnapshot {
        agents,
        sessions,
        packets,
        audit_entries,
        fleet_cost_usd,
    }
}

fn fmt_usd(x: f64) -> String {
    format!("${:.2}", (x * 100.0).round() / 100.0)
}

fn fmt_tok(n: u64) -> String {
    let s = n.to_string();
    let mut r = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            r.push(',');
        }
        r.push(c);
    }
    r.chars().rev().collect()
}

/// Replace demo Monitor numbers with kernel + `billing_usage_events` data for this account.
pub fn apply_monitor_surface_live_overlay(root: &mut Value, state: &SharedState, account_id: &str) {
    let totals = crate::services::books::billing_ledger_totals(state, Some(account_id));
    let fleet = kernel_fleet_snapshot(state);
    let recent = crate::services::books::recent_billing_events(state, Some(account_id), 8);

    if let Some(doc) = root.get_mut("document") {
        let summary_text = format!(
            "Live: {} agents · {} sessions · {} packets · kernel audit {} entries · ledger month {} tok {} · kernel fleet cost {} · ledger all-time {} tok {}",
            fleet.agents,
            fleet.sessions,
            fleet.packets,
            fleet.audit_entries,
            fmt_tok(totals.month_tokens),
            fmt_usd(totals.month_cost_usd),
            fmt_usd(fleet.fleet_cost_usd),
            fmt_tok(totals.all_time_tokens),
            fmt_usd(totals.all_time_cost_usd)
        );
        doc["summary"] = json!(summary_text);
    }

    if let Some(badges) = root
        .pointer_mut("/document/header/badges")
        .and_then(|b| b.as_array_mut())
    {
        for b in badges.iter_mut() {
            let label = b.get("label").and_then(|x| x.as_str()).unwrap_or("");
            if label == "Window" {
                b["value"] = json!("UTC month");
            } else if label == "Tokens" {
                b["value"] = json!(fmt_tok(totals.month_tokens));
            } else if label == "Cost" {
                b["value"] = json!(fmt_usd(totals.month_cost_usd));
            }
        }
    }

    if let Some(pkg) = root.get_mut("decision_package") {
        if let Some(cost) = pkg.get_mut("cost") {
            cost["amount_usd"] = json!(totals.month_cost_usd);
            if let Some(obj) = cost.as_object_mut() {
                obj.insert(
                    "change_summary".to_string(),
                    json!(format!(
                        "today {} tok {} · month {} tok {} · all-time {} tok {}",
                        fmt_tok(totals.today_tokens),
                        fmt_usd(totals.today_cost_usd),
                        fmt_tok(totals.month_tokens),
                        fmt_usd(totals.month_cost_usd),
                        fmt_tok(totals.all_time_tokens),
                        fmt_usd(totals.all_time_cost_usd)
                    )),
                );
            }
        }
    }

    let day_of_month = chrono::Utc::now().day().max(1) as f64;
    let avg_day = totals.month_cost_usd / day_of_month;
    let t_m = totals.month_tokens.max(1) as f64;
    let per_1k = totals.month_cost_usd / (t_m / 1000.0);

    if let Some(sections) = root
        .pointer_mut("/document/sections")
        .and_then(|s| s.as_array_mut())
    {
        for sec in sections.iter_mut() {
            let title = sec
                .get("title")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if title == "Cost Summary" {
                if let Some(stats) = sec
                    .get_mut("content")
                    .and_then(|c| c.get_mut("Stats"))
                    .and_then(|s| s.as_array_mut())
                {
                    for stat in stats.iter_mut() {
                        let lbl = stat.get("label").and_then(|l| l.as_str()).unwrap_or("");
                        match lbl {
                            "Window" => stat["value"] = json!("UTC calendar month"),
                            "Rollup" => stat["value"] = json!("Month-to-date"),
                            "Tokens Used" => stat["value"] = json!(fmt_tok(totals.month_tokens)),
                            "Cost" => stat["value"] = json!(fmt_usd(totals.month_cost_usd)),
                            "Agent" => {
                                stat["value"] = json!(format!(
                                    "{} agents · {} sessions · {} pkts",
                                    fleet.agents, fleet.sessions, fleet.packets
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }
            if title == "Monthly Rollup" || title == "Cost Posture" {
                if let Some(kvs) = sec
                    .get_mut("content")
                    .and_then(|c| c.get_mut("KeyValue"))
                    .and_then(|k| k.as_array_mut())
                {
                    for kv in kvs.iter_mut() {
                        let key = kv.get("key").and_then(|k| k.as_str()).unwrap_or("");
                        match key {
                            "Window" => kv["value"] = json!("UTC month (billing ledger)"),
                            "Rollup" => kv["value"] = json!("Month-to-date"),
                            "Average / day" => kv["value"] = json!(fmt_usd(avg_day)),
                            "Average / 1K tokens" => kv["value"] = json!(fmt_usd(per_1k)),
                            "Last billed call" => {
                                kv["value"] = json!(fmt_usd(totals.today_cost_usd))
                            }
                            _ => {}
                        }
                    }
                }
            }
            if title == "Cost Statement" {
                let timeline: Vec<Value> = recent
                    .iter()
                    .map(|ev| {
                        let tok = crate::services::books::billing_token_count(ev);
                        let usd = ev
                            .get("cost_usd_estimated")
                            .and_then(|x| x.as_f64())
                            .unwrap_or(0.0);
                        let ts = ev
                            .get("timestamp")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .chars()
                            .take(22)
                            .collect::<String>();
                        let et = ev
                            .get("event_type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("event");
                        let agent = ev
                            .get("agent_pid")
                            .and_then(|t| t.as_str())
                            .unwrap_or("—");
                        json!({
                            "timestamp": ts,
                            "event_type": et,
                            "message": format!("{} tok · {} · {}", fmt_tok(tok), fmt_usd(usd), agent),
                            "severity": "Ok",
                            "link": null
                        })
                    })
                    .collect();
                if let Some(content) = sec.get_mut("content") {
                    content["Timeline"] = json!(timeline);
                }
            }
        }
    }

    if let Some(footer) = root.pointer_mut("/document/footer") {
        let n = fleet.audit_entries.min(u32::MAX as usize);
        footer["receipt_count"] = json!(n as u32);
    }
}

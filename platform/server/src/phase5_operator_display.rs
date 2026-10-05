//! One-line operator summaries derived from **`phase_5_operator`** JSON (`GET /api/v1/plugins/status`).
//! Shared by the **`connector-platform`** and **`connectorctl`** binaries (this crate has no `lib.rs`).
//! The server also stores the same string under **`process_env_operator_display_line`** on **`phase_5_operator`** for API/UI consumers.

use serde_json::Value;

/// Human / CLI one-liner: `CONNECTOR_ENV=… · production_like=… · …` (returns **`None`** if `p5` is null).
pub fn process_env_operator_display_line(p5: &Value) -> Option<String> {
    if p5.is_null() {
        return None;
    }
    fn yn_bool(b: Option<bool>) -> &'static str {
        match b {
            Some(true) => "yes",
            Some(false) => "no",
            None => "?",
        }
    }
    let cenv = p5
        .get("connect_connector_env")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    let plike = yn_bool(
        p5.get("connect_env_production_like")
            .and_then(|x| x.as_bool()),
    );
    let dmt = yn_bool(p5.get("connect_dev_mode_truthy").and_then(|x| x.as_bool()));
    let rj = yn_bool(
        p5.get("connect_production_reject_dev_mode_truthy")
            .and_then(|x| x.as_bool()),
    );
    let hyg = p5
        .get("production_dev_mode_hygiene")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    Some(format!(
        "CONNECTOR_ENV={cenv} · production_like={plike} · dev_mode_truthy={dmt} · reject_dev_mode_truthy={rj} · prod_dev_mode_hygiene={hyg}",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_env_line_formats_operator_json() {
        let p5 = serde_json::json!({
            "connect_connector_env": "production",
            "connect_env_production_like": true,
            "connect_dev_mode_truthy": true,
            "connect_production_reject_dev_mode_truthy": false,
            "production_dev_mode_hygiene": "warn_on_boot",
        });
        let s = process_env_operator_display_line(&p5).expect("line");
        assert!(s.contains("CONNECTOR_ENV=production"));
        assert!(s.contains("production_like=yes"));
        assert!(s.contains("dev_mode_truthy=yes"));
        assert!(s.contains("reject_dev_mode_truthy=no"));
        assert!(s.contains("prod_dev_mode_hygiene=warn_on_boot"));
    }

    #[test]
    fn process_env_line_none_for_null() {
        assert!(process_env_operator_display_line(&Value::Null).is_none());
    }
}

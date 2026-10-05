//! E2 — Configurable DIM viability bands (independent of contract/grant/budget knobs).
//!
//! Default bands match historical hardcoded values. Override via:
//! - `CONNECTOR_DIM_BANDS_JSON` — JSON object `{ "K": [lo, hi], ... }`
//! - optional `dynamic_intelligence.bands` in connector.yaml (env set at boot)

use serde_json::Value;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct DimBands {
    /// (name, field accessor key, lo, hi)
    pub rows: Vec<(String, f32, f32)>,
}

impl Default for DimBands {
    fn default() -> Self {
        Self {
            rows: vec![
                ("K".into(), 0.55, 0.96),
                ("E".into(), 0.0, 0.35),
                ("P".into(), 0.45, 0.95),
                ("H".into(), 0.2, 0.7),
                ("X".into(), 0.0, 0.45),
                ("R".into(), 0.25, 1.0),
                ("S".into(), 0.6, 1.0),
            ],
        }
    }
}

fn parse_bands_json(raw: &str) -> Option<DimBands> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let obj = v.as_object()?;
    let mut rows = Vec::new();
    for (k, val) in obj {
        let arr = val.as_array()?;
        if arr.len() < 2 {
            continue;
        }
        let lo = arr[0].as_f64()? as f32;
        let hi = arr[1].as_f64()? as f32;
        if lo <= hi {
            rows.push((k.clone(), lo, hi));
        }
    }
    if rows.is_empty() {
        None
    } else {
        Some(DimBands { rows })
    }
}

static BANDS: OnceLock<DimBands> = OnceLock::new();

/// Cached bands for this process (env read once).
pub fn active_bands() -> &'static DimBands {
    BANDS.get_or_init(|| {
        if let Ok(raw) = std::env::var("CONNECTOR_DIM_BANDS_JSON") {
            if let Some(b) = parse_bands_json(&raw) {
                return b;
            }
        }
        DimBands::default()
    })
}

/// Map band key → current DIM scalar (for Φ recompute).
pub fn value_for_key(key: &str, coherence: f32, prediction_error: f32, precision: f32, entropy: f32, interference: f32, resource_potential: f32, self_continuity: f32) -> f32 {
    match key {
        "K" => coherence,
        "E" => prediction_error,
        "P" => precision,
        "H" => entropy,
        "X" => interference,
        "R" => resource_potential,
        "S" => self_continuity,
        _ => 0.5,
    }
}

pub fn posture_json() -> Value {
    let b = active_bands();
    serde_json::json!({
        "schema": "connector.dim_bands.v1",
        "source": if std::env::var_os("CONNECTOR_DIM_BANDS_JSON").is_some() {
            "env:CONNECTOR_DIM_BANDS_JSON"
        } else {
            "default"
        },
        "bands": b.rows.iter().map(|(n, lo, hi)| serde_json::json!({
            "name": n, "lo": lo, "hi": hi
        })).collect::<Vec<_>>(),
        "honesty": "Changing DIM bands does not alter NF³ authority, contracts, or WorldGrants",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_seven() {
        assert_eq!(DimBands::default().rows.len(), 7);
    }

    #[test]
    fn parse_override() {
        let b = parse_bands_json(r#"{"K":[0.1,0.9],"E":[0.0,0.5]}"#).unwrap();
        assert_eq!(b.rows.len(), 2);
    }
}

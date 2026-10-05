//! Honesty helpers (H1–H3) for operator UI.

/// Unknown numeric / empty → em dash (H1).
pub fn fmt_unknown(value: Option<f64>) -> String {
    value
        .filter(|v| v.is_finite())
        .map(|v| {
            if v.fract() == 0.0 {
                format!("{:.0}", v)
            } else {
                format!("{:.2}", v)
            }
        })
        .unwrap_or_else(|| "—".to_string())
}

pub fn fmt_unknown_u64(value: Option<u64>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "—".to_string())
}

pub fn fmt_unknown_str(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "—".to_string())
}

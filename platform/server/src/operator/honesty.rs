use serde_json::{json, Value};

/// Wrap operator aggregate responses with generation metadata + truth class.
///
/// `truth_class` defaults to `measured_or_config` — never silently implies a product claim.
pub fn operator_envelope(body: Value) -> Value {
    let generated_at = chrono::Utc::now().to_rfc3339();
    match body {
        Value::Object(mut map) => {
            map.entry("generated_at".to_string())
                .or_insert(json!(generated_at));
            map.entry("ok".to_string()).or_insert(json!(true));
            map.entry("truth_class".to_string())
                .or_insert(json!("measured_or_config"));
            Value::Object(map)
        }
        other => json!({
            "ok": true,
            "generated_at": generated_at,
            "truth_class": "measured_or_config",
            "data": other,
        }),
    }
}

/// Envelope for explicitly non-claim / measured-only surfaces.
pub fn measured_envelope(body: Value) -> Value {
    let mut v = operator_envelope(body);
    if let Some(obj) = v.as_object_mut() {
        obj.insert("truth_class".into(), json!("measured"));
        obj.entry("honesty".to_string()).or_insert(json!(
            "Machine-measured fields only — not a marketing or compliance claim"
        ));
    }
    v
}

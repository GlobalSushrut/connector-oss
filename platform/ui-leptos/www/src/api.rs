use gloo_net::http::{Request, RequestBuilder};
use gloo_storage::{LocalStorage, Storage};
use serde_json::Value;

const BASE: &str = "/api/v1/portal";

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: Option<String>,
    pub message: String,
    pub detail: Option<String>,
    pub hints: Vec<String>,
    pub docs: Option<String>,
}

fn is_canonical_result(value: &Value) -> bool {
    value.get("ok").and_then(|v| v.as_bool()).is_some()
        && value.get("intent").and_then(|v| v.as_object()).is_some()
        && value.get("data").is_some()
}

fn singularize(value: &str) -> String {
    value.strip_suffix('s').unwrap_or(value).to_string()
}

fn infer_intent(method: &str, path: &str) -> (String, String, String) {
    let bare = path.split('?').next().unwrap_or(path);
    let parts: Vec<&str> = bare
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let first = parts.first().copied().unwrap_or("resource");
    let last = parts.last().copied().unwrap_or(first);
    match (method, parts.as_slice()) {
        ("GET", [noun]) => ("list".to_string(), singularize(noun), "all".to_string()),
        ("GET", [noun, target]) => ("show".to_string(), singularize(noun), (*target).to_string()),
        ("POST", [noun]) => ("create".to_string(), singularize(noun), (*noun).to_string()),
        ("PATCH", [noun]) => ("update".to_string(), singularize(noun), (*noun).to_string()),
        ("DELETE", [noun]) => ("delete".to_string(), singularize(noun), (*noun).to_string()),
        _ => (
            method.to_ascii_lowercase(),
            singularize(first),
            last.to_string(),
        ),
    }
}

fn infer_summary(method: &str, path: &str, body: &Value, ok: bool) -> Value {
    let (verb, noun, target) = infer_intent(method, path);
    let message = body
        .get("message")
        .or_else(|| body.get("detail"))
        .and_then(|v| v.as_str())
        .unwrap_or("Request completed");
    serde_json::json!({
        "title": format!("{} {}", verb, noun),
        "message": message,
        "status": if ok { "completed" } else { "failed" },
        "why": body.get("detail"),
        "next": [
            format!("Review {} details for {}", noun, target)
        ]
    })
}

fn infer_trust(body: &Value) -> Value {
    serde_json::json!({
        "score": body.get("trust").cloned().or_else(|| body.pointer("/status/trust").cloned()),
        "grade": body.get("trust_grade").cloned().or_else(|| body.pointer("/status/trust_grade").cloned()),
        "verified": body.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)
    })
}

fn infer_evidence(body: &Value) -> Value {
    let mut evidence = Vec::new();
    if let Some(trace_id) = body.get("trace_id").and_then(|v| v.as_str()) {
        evidence.push(serde_json::json!({
            "kind": "trace",
            "id": trace_id,
            "label": "execution_trace",
            "verified": body.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)
        }));
    }
    for field in ["cid", "snapshot_cid", "root_cid"] {
        if let Some(cid) = body.get(field).and_then(|v| v.as_str()) {
            evidence.push(serde_json::json!({
                "kind": "cid",
                "id": cid,
                "label": field,
                "verified": true
            }));
        }
    }
    Value::Array(evidence)
}

fn infer_presentation(path: &str, body: &Value) -> Value {
    let mut mode = if path.ends_with('s') || path.contains("/list") {
        "list"
    } else {
        "detail"
    };
    let mut columns: Vec<String> = Vec::new();
    let mut row_count = None;

    if let Some(obj) = body.as_object() {
        for value in obj.values() {
            if let Some(items) = value.as_array() {
                if let Some(first) = items.first().and_then(|item| item.as_object()) {
                    columns = first.keys().take(8).cloned().collect();
                    row_count = Some(items.len());
                    mode = "list";
                    break;
                }
            }
        }
    }

    serde_json::json!({
        "mode": mode,
        "table_safe": mode == "list",
        "row_count": row_count,
        "columns": columns
    })
}

fn normalize_success_response(method: &str, path: &str, body: Value) -> Value {
    if is_canonical_result(&body) {
        return body;
    }

    let (verb, noun, target) = infer_intent(method, path);
    let ok = body.get("ok").and_then(|v| v.as_bool()).unwrap_or(true);
    let mut envelope = serde_json::json!({
        "ok": ok,
        "intent": {
            "verb": verb,
            "noun": noun,
            "target": target
        },
        "summary": infer_summary(method, path, &body, ok),
        "trust": infer_trust(&body),
        "evidence": infer_evidence(&body),
        "links": {
            "docs": "/docs"
        },
        "render": {
            "role": "user",
            "redacted": false,
            "redacted_fields": []
        },
        "presentation": infer_presentation(path, &body),
        "meta": {
            "schema": "connector.result.v1",
            "family": "canonical_semantic_package",
            "package_first": true,
            "view": "package",
            "source": "portal-ui"
        },
        "data": body.clone()
    });

    if let Some(obj) = body.as_object() {
        if let Some(envelope_obj) = envelope.as_object_mut() {
            for (key, value) in obj {
                envelope_obj
                    .entry(key.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }

    envelope
}

async fn parse_error(r: gloo_net::http::Response) -> ApiError {
    let status = r.status();
    let text = r.text().await.unwrap_or_default();
    let parsed = serde_json::from_str::<Value>(&text)
        .unwrap_or_else(|_| serde_json::json!({ "message": text }));
    let error = parsed.get("error").unwrap_or(&parsed);
    let hints = error
        .get("hints")
        .or_else(|| error.get("hint"))
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_else(Vec::new);

    ApiError {
        status,
        code: error
            .get("code")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        message: error
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Request failed")
            .to_string(),
        detail: error
            .get("detail")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
        hints,
        docs: error
            .get("docs")
            .and_then(|v| v.as_str())
            .map(|v| v.to_string()),
    }
}

fn token() -> String {
    LocalStorage::get::<String>("portal_token").unwrap_or_default()
}

fn authed(request: RequestBuilder) -> RequestBuilder {
    let token = token();
    if token.is_empty() {
        request
    } else {
        request.header("Authorization", &format!("Bearer {token}"))
    }
}

pub async fn get_value(path: &str) -> Result<Value, ApiError> {
    let url = format!("{BASE}{path}");
    let r = authed(Request::get(&url))
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?;
    if !r.ok() {
        return Err(parse_error(r).await);
    }
    r.json::<Value>()
        .await
        .map(|value| normalize_success_response("GET", path, value))
        .map_err(|e| ApiError {
            status: 200,
            code: Some("parse_error".into()),
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })
}

pub async fn post_value(path: &str, body: Value) -> Result<Value, ApiError> {
    let url = format!("{BASE}{path}");
    let r = authed(Request::post(&url))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?;
    if !r.ok() {
        return Err(parse_error(r).await);
    }
    r.json::<Value>()
        .await
        .map(|value| normalize_success_response("POST", path, value))
        .map_err(|e| ApiError {
            status: 200,
            code: Some("parse_error".into()),
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })
}

pub async fn patch_value(path: &str, body: Value) -> Result<Value, ApiError> {
    let url = format!("{BASE}{path}");
    let r = authed(Request::patch(&url))
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?;
    if !r.ok() {
        return Err(parse_error(r).await);
    }
    r.json::<Value>()
        .await
        .map(|value| normalize_success_response("PATCH", path, value))
        .map_err(|e| ApiError {
            status: 200,
            code: Some("parse_error".into()),
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })
}

pub async fn delete_value(path: &str) -> Result<Value, ApiError> {
    let url = format!("{BASE}{path}");
    let r = authed(Request::delete(&url))
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?;
    if !r.ok() {
        return Err(parse_error(r).await);
    }
    r.json::<Value>()
        .await
        .map(|value| normalize_success_response("DELETE", path, value))
        .map_err(|e| ApiError {
            status: 200,
            code: Some("parse_error".into()),
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })
}

pub async fn get_root_value(path: &str) -> Result<Value, ApiError> {
    let r = Request::get(path).send().await.map_err(|e| ApiError {
        status: 0,
        code: None,
        message: e.to_string(),
        detail: None,
        hints: Vec::new(),
        docs: None,
    })?;
    if !r.ok() {
        return Err(parse_error(r).await);
    }
    r.json::<Value>()
        .await
        .map(|value| normalize_success_response("GET", path, value))
        .map_err(|e| ApiError {
            status: 200,
            code: Some("parse_error".into()),
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })
}

pub async fn post_root_value(path: &str, body: Value) -> Result<Value, ApiError> {
    let r = Request::post(path)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?
        .send()
        .await
        .map_err(|e| ApiError {
            status: 0,
            code: None,
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })?;
    if !r.ok() {
        return Err(parse_error(r).await);
    }
    r.json::<Value>()
        .await
        .map(|value| normalize_success_response("POST", path, value))
        .map_err(|e| ApiError {
            status: 200,
            code: Some("parse_error".into()),
            message: e.to_string(),
            detail: None,
            hints: Vec::new(),
            docs: None,
        })
}

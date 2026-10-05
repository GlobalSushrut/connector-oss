use gloo_storage::{SessionStorage, Storage};
use wasm_bindgen::{JsCast, JsValue};

/// Session key for Builder ⇄ Packages CLS source round-trip (Phase 3.3–3.4).
pub const CLS_ROUNDTRIP_SESSION_KEY: &str = "connector_cls_roundtrip_source";

pub fn cls_session_get_source() -> Option<String> {
    SessionStorage::get(CLS_ROUNDTRIP_SESSION_KEY).ok()
}

pub fn cls_session_set_source(src: &str) {
    let _ = SessionStorage::set(CLS_ROUNDTRIP_SESSION_KEY, src);
}

pub fn cls_session_clear_source() {
    let _ = SessionStorage::delete(CLS_ROUNDTRIP_SESSION_KEY);
}

/// True when most non-empty, non-comment lines look like `step_id:step_type` (simple builder lane).
pub fn cls_source_simple_lane_ok(src: &str) -> bool {
    let lines: Vec<&str> = src
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if lines.is_empty() {
        return true;
    }
    let simple = lines
        .iter()
        .filter(|l| l.contains(':') && l.split(':').count() >= 2)
        .count();
    simple * 2 >= lines.len()
}

/// Open HTML returned from the API in a new tab (e.g. printable compliance brief).
/// Uses a blob URL because `window.open` cannot attach `Authorization` headers.
pub fn open_html_bytes_in_new_tab(bytes: &[u8]) {
    let Some(window) = web_sys::window() else { return };
    let arr = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
    arr.copy_from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&JsValue::from(arr));
    let bag = web_sys::BlobPropertyBag::new();
    bag.set_type("text/html;charset=utf-8");
    let Ok(blob) = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &bag) else {
        return;
    };
    let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) else { return };
    let _ = window.open_with_url_and_target_and_features(&url, "_blank", "");
    let url_revoke = url.clone();
    wasm_bindgen_futures::spawn_local(async move {
        gloo_timers::future::TimeoutFuture::new(120_000).await;
        let _ = web_sys::Url::revoke_object_url(&url_revoke);
    });
}

/// Wrap arbitrary bytes in a blob and return a `blob:` object URL.
///
/// Use this when you need to display fetched binary content inline (e.g.
/// embed a fetched PDF in an `<iframe>` or `<embed>`). The caller is
/// responsible for revoking the URL via [`revoke_object_url`] once the
/// resource is no longer referenced — leaving object URLs in memory will
/// pin the blob bytes indefinitely.
///
/// Returns `None` when the runtime can't allocate a blob (e.g. during
/// non-browser tests).
pub fn bytes_to_object_url(bytes: &[u8], mime: &str) -> Option<String> {
    let arr = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
    arr.copy_from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&JsValue::from(arr));
    let bag = web_sys::BlobPropertyBag::new();
    bag.set_type(mime);
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &bag).ok()?;
    web_sys::Url::create_object_url_with_blob(&blob).ok()
}

/// Best-effort revoke of an object URL allocated via
/// [`bytes_to_object_url`]. Safe to call with a URL that's already been
/// revoked — the no-op is preferable to leaking blob memory.
pub fn revoke_object_url(url: &str) {
    let _ = web_sys::Url::revoke_object_url(url);
}

/// Trigger a file download in the browser (CSR).
pub fn trigger_download_bytes(bytes: &[u8], filename: &str, mime: &str) {
    let Some(window) = web_sys::window() else { return };
    let Some(document) = window.document() else { return };
    if bytes.is_empty() {
        return;
    }
    let arr = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
    arr.copy_from(bytes);
    let parts = js_sys::Array::new();
    parts.push(&JsValue::from(arr));
    let bag = web_sys::BlobPropertyBag::new();
    bag.set_type(mime);
    let Ok(blob) = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &bag) else {
        return;
    };
    let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) else { return };
    let Ok(a) = document
        .create_element("a")
        .map_err(|_| ())
        .and_then(|e| e.dyn_into::<web_sys::HtmlAnchorElement>().map_err(|_| ()))
    else {
        let _ = web_sys::Url::revoke_object_url(&url);
        return;
    };
    a.set_href(&url);
    a.set_download(filename);
    let _ = a.set_attribute("rel", "noopener");
    if let Ok(style) = a.style().set_property("display", "none") {
        let _ = style;
    }
    if let Some(body) = document.body() {
        let _ = body.append_child(&a);
        a.click();
        let _ = body.remove_child(&a);
    } else {
        a.click();
    }
    let _ = web_sys::Url::revoke_object_url(&url);
}

/// UTC stamp for download filenames (`YYYYMMDDTHHMMSSZ`), matching platform PDF stamps.
pub fn utc_stamp_for_filename() -> String {
    let d = js_sys::Date::new_0();
    let y = d.get_utc_full_year() as i32;
    let mo = d.get_utc_month() as u32 + 1;
    let day = d.get_utc_date() as u32;
    let h = d.get_utc_hours() as u32;
    let mi = d.get_utc_minutes() as u32;
    let s = d.get_utc_seconds() as u32;
    format!("{y:04}{mo:02}{day:02}T{h:02}{mi:02}{s:02}Z")
}

/// Insert a UTC stamp before the extension: `brief.pdf` → `brief-20260821T163045Z.pdf`.
pub fn stamp_download_filename(filename: &str) -> String {
    let stamp = utc_stamp_for_filename();
    if let Some((stem, ext)) = filename.rsplit_once('.') {
        if !ext.is_empty() && !ext.contains('/') {
            return format!("{stem}-{stamp}.{ext}");
        }
    }
    format!("{filename}-{stamp}")
}

pub fn format_number(n: f64) -> String {
    if n >= 1_000_000.0 {
        format!("{:.1}M", n / 1_000_000.0)
    } else if n >= 1_000.0 {
        format!("{:.1}K", n / 1_000.0)
    } else {
        format!("{}", n as i64)
    }
}

pub fn format_currency_usd(usd: f64) -> String {
    format!("${:.2}", usd)
}

/// Returns a hex color string for a trust score 0–100
pub fn trust_color(score: f64) -> &'static str {
    if score >= 95.0 { "#22c55e" }
    else if score >= 85.0 { "#4ade80" }
    else if score >= 70.0 { "#facc15" }
    else if score >= 50.0 { "#f59e0b" }
    else if score >= 30.0 { "#f97316" }
    else { "#ef4444" }
}

pub fn trust_grade(score: f64) -> &'static str {
    if score >= 95.0 { "A+" }
    else if score >= 85.0 { "A" }
    else if score >= 70.0 { "B" }
    else if score >= 50.0 { "C" }
    else if score >= 30.0 { "D" }
    else { "F" }
}

pub fn time_ago(ts_ms: i64) -> String {
    let now_ms = js_sys::Date::now() as i64;
    let secs = ((now_ms - ts_ms) / 1000).max(0);
    if secs < 60 { format!("{}s ago", secs) }
    else if secs < 3600 { format!("{}m ago", secs / 60) }
    else if secs < 86400 { format!("{}h ago", secs / 3600) }
    else { format!("{}d ago", secs / 86400) }
}

pub fn time_ago_str(date_str: &str) -> String {
    // Parse ISO date string via JS Date
    let ms = js_sys::Date::parse(date_str);
    if ms.is_nan() { return String::new(); }
    time_ago(ms as i64)
}

/// Format `timestamp` from API JSON (ISO string or epoch ms) for activity feeds.
#[allow(dead_code)]
pub fn json_timestamp_label(entry: &serde_json::Value) -> String {
    entry
        .get("timestamp")
        .map(|t| {
            if let Some(s) = t.as_str() {
                let ago = time_ago_str(s);
                if !ago.is_empty() {
                    ago
                } else {
                    s.to_string()
                }
            } else if let Some(n) = t.as_i64() {
                time_ago(n)
            } else if let Some(n) = t.as_u64() {
                time_ago(n as i64)
            } else if let Some(f) = t.as_f64() {
                time_ago(f as i64)
            } else {
                t.to_string()
            }
        })
        .unwrap_or_else(|| "—".into())
}

pub fn pretty_json(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".into())
}

/// Truncate a string to max_len with ellipsis
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    }
}

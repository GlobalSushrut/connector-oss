//! Connector-native browser world — document exploration of the real internet.
//!
//! Not Chromium computer-use (click/type/JS). Each GET is a world address:
//! grant → dest-pinned Landlock pore → record fundamentals (URL, status, title,
//! excerpt, links, digest). Redirects are not followed; Location is a next hop
//! the agent must navigate so Connector sees every jump.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::kernel::world_gateway;
use crate::pore_worker::parse_url_host_port;
use crate::state::PlatformState;
use crate::substrate::egress_policy;

pub const SESSION_FOLDER: &str = "browser_sessions_v1";
pub const PAGE_FOLDER: &str = "browser_pages_v1";
pub const SCHEMA: &str = "connector.browser.world.v1";
pub const ADDR_TYPE: &str = "browser";
pub const CAP_NAVIGATE: &str = "browse.navigate";
pub const DEFAULT_MAX_BYTES: usize = 262_144;
pub const HARD_MAX_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentFundamentals {
    pub title: String,
    pub excerpt: String,
    pub links: Vec<String>,
    pub same_origin_links: usize,
    pub cross_origin_links: usize,
}

pub fn origin_of(url: &str) -> Result<String, String> {
    let (host, port) = parse_url_host_port(url)?;
    let https = url.trim().starts_with("https://");
    let scheme = if https { "https" } else { "http" };
    let default = if https { 443 } else { 80 };
    if port == default {
        Ok(format!("{scheme}://{host}"))
    } else {
        Ok(format!("{scheme}://{host}:{port}"))
    }
}

pub fn extract_document(html: &str, page_url: &str) -> DocumentFundamentals {
    let title = capture_tag(html, "title").unwrap_or_default();
    let stripped = strip_tags(&strip_blocks(html));
    let excerpt: String = stripped.chars().take(1_200).collect();
    let origin = origin_of(page_url).unwrap_or_default();
    let links = extract_hrefs(html, page_url);
    let mut same = 0usize;
    let mut cross = 0usize;
    for l in &links {
        if let Ok(o) = origin_of(l) {
            if o == origin {
                same += 1;
            } else {
                cross += 1;
            }
        } else {
            same += 1;
        }
    }
    DocumentFundamentals {
        title: title.chars().take(240).collect(),
        excerpt: excerpt.trim().to_string(),
        links: links.into_iter().take(40).collect(),
        same_origin_links: same,
        cross_origin_links: cross,
    }
}

/// Governed navigate: grant + pore + fetch + record. One URL hop.
pub fn navigate(
    state: &PlatformState,
    agent_pid: &str,
    url: &str,
    session_id: Option<&str>,
    max_bytes: Option<usize>,
    goal_id: Option<&str>,
    situation: Option<&[f64]>,
) -> Result<Value, Value> {
    let url = url.trim();
    if agent_pid.trim().is_empty() {
        return Err(json!({"ok": false, "error": "agent_pid_required"}));
    }
    if url.is_empty() {
        return Err(json!({"ok": false, "error": "url_required"}));
    }
    if let Err(code) = egress_policy::assert_safe_outbound_url(url) {
        return Err(json!({"ok": false, "error": code, "url": url}));
    }
    let origin = origin_of(url).map_err(|e| json!({"ok": false, "error": e}))?;
    let host = parse_url_host_port(url)
        .map(|(h, _)| h)
        .unwrap_or_default();
    if let Err(e) = crate::kernel::llm_vendor_cut::deny_agent_vendor_dial(agent_pid, &host) {
        return Err(json!({
            "ok": false,
            "error": "vendor_exclusive",
            "message": e,
            "honesty": "LLM vendor hosts are the Connector cage, not the browser world",
        }));
    }
    if let Err(e) = world_gateway::assert_grant_allows(state, agent_pid, url, CAP_NAVIGATE) {
        if world_gateway::assert_grant_allows(state, agent_pid, &origin, CAP_NAVIGATE).is_err() {
            return Err(json!({
                "ok": false,
                "error": "world_grant_required",
                "message": e,
                "address": origin,
                "capability": CAP_NAVIGATE,
                "honesty": "Owner must grant this origin as world type browser (or covering http_api)",
            }));
        }
    }
    let chain = match crate::kernel::fleet_chain::before_browser_fetch(
        state,
        agent_pid,
        &origin,
        goal_id,
        situation,
    ) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    if let Err(message) = egress_policy::assert_agent_l7_egress_allowed(state, agent_pid, url) {
        return Err(json!({"ok": false, "error": "l7_egress_denied", "message": message}));
    }

    let cap = max_bytes
        .unwrap_or(DEFAULT_MAX_BYTES)
        .clamp(1_024, HARD_MAX_BYTES);
    let sid = session_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            format!(
                "br_{}",
                &uuid::Uuid::new_v4().to_string().replace('-', "")[..12]
            )
        });

    let headers = json!({
        "user-agent": "ConnectorBrowser/1.0 (governed world explorer)",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "en",
    });
    let (status, content_type, location, raw, landlock) =
        fetch_document(state, agent_pid, url, &headers)?;
    let truncated = raw.len() > cap;
    let body = if truncated {
        raw.chars().take(cap).collect::<String>()
    } else {
        raw
    };
    let sha = format!("{:x}", Sha256::digest(body.as_bytes()));
    let fundamentals =
        if content_type.to_ascii_lowercase().contains("html") || looks_like_html(&body) {
            extract_document(&body, url)
        } else {
            DocumentFundamentals {
                title: String::new(),
                excerpt: body.chars().take(800).collect(),
                links: vec![],
                same_origin_links: 0,
                cross_origin_links: 0,
            }
        };

    if let Some(chain) = chain.as_ref() {
        let goal = chain.get("goal_id").and_then(|v| v.as_str()).unwrap_or("");
        let digest = chain
            .pointer("/sequence/sequence_digest")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !goal.is_empty() && !digest.is_empty() {
            crate::kernel::fleet_chain::mark_effect_taken(state, goal, agent_pid, digest);
        }
    }

    let page = json!({
        "schema": "connector.browser.page.v1",
        "session_id": sid,
        "agent_pid": agent_pid,
        "url": url,
        "origin": origin,
        "status": status,
        "content_type": content_type,
        "location": location,
        "title": fundamentals.title,
        "excerpt": fundamentals.excerpt,
        "links": fundamentals.links,
        "same_origin_links": fundamentals.same_origin_links,
        "cross_origin_links": fundamentals.cross_origin_links,
        "sha256": sha,
        "bytes": body.len(),
        "truncated": truncated,
        "landlock_child": landlock,
        "followed_redirect": false,
        "at_ms": chrono::Utc::now().timestamp_millis(),
        "fleet_chain": chain,
        "honesty": "One hop. 3xx Location is not auto-followed — navigate again so Connector records the jump. Not computer-use.",
    });

    persist_page(state, agent_pid, &sid, &origin, &page)?;
    Ok(json!({
        "ok": true,
        "schema": SCHEMA,
        "session_id": sid,
        "page": page,
        "next": location,
    }))
}

pub fn get_session(state: &PlatformState, session_id: &str) -> Option<Value> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(SESSION_FOLDER, session_id.trim())
        .ok()
        .flatten()
}

pub fn list_sessions(state: &PlatformState, agent_pid: Option<&str>) -> Vec<Value> {
    let Ok(es) = state.engine_store.lock() else {
        return vec![];
    };
    let Ok(keys) = es.folder_keys(SESSION_FOLDER, None) else {
        return vec![];
    };
    let want = agent_pid.map(|s| s.trim().to_string());
    keys.into_iter()
        .filter_map(|k| es.folder_get(SESSION_FOLDER, &k).ok().flatten())
        .filter(|v| {
            want.as_ref()
                .map(|p| v.get("agent_pid").and_then(|x| x.as_str()).unwrap_or("") == p)
                .unwrap_or(true)
        })
        .collect()
}

pub fn posture() -> Value {
    json!({
        "schema": SCHEMA,
        "world_type": ADDR_TYPE,
        "capability": CAP_NAVIGATE,
        "computer_use": false,
        "javascript": false,
        "cookie_jar": false,
        "auto_redirect": false,
        "record": [SESSION_FOLDER, PAGE_FOLDER],
        "honesty": "Document GET explorer on a granted origin. Chromium click/type remains unsupported_here.",
    })
}

fn fetch_document(
    state: &PlatformState,
    agent_pid: &str,
    url: &str,
    headers: &Value,
) -> Result<(u16, String, Option<String>, String, bool), Value> {
    if crate::kernel::landlock_child::enforced() {
        let v = crate::kernel::landlock_child::http_fetch(
            state,
            agent_pid,
            url,
            url,
            "GET",
            headers.clone(),
            None,
            20_000,
        )
        .map_err(|e| json!({"ok": false, "error": e, "landlock_child": true}))?;
        return Ok((
            v.get("status").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
            v.get("content_type")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            v.get("location")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            body_text(v.get("body")),
            true,
        ));
    }
    fetch_in_process_blocking(url, headers)
        .map_err(|e| json!({"ok": false, "error": e, "landlock_child": false}))
}

fn fetch_in_process_blocking(
    url: &str,
    headers: &Value,
) -> Result<(u16, String, Option<String>, String, bool), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .connect_timeout(std::time::Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.get(url);
    if let Some(obj) = headers.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                req = req.header(k, s);
            }
        }
    }
    let resp = req.send().map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let text = resp.text().unwrap_or_default();
    let _ = url;
    Ok((status, content_type, location, text, false))
}

fn persist_page(
    state: &PlatformState,
    agent_pid: &str,
    session_id: &str,
    origin: &str,
    page: &Value,
) -> Result<(), Value> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| json!({"ok": false, "error": "engine_store_lock"}))?;
    let page_id = format!(
        "{}::{}",
        session_id,
        page.get("at_ms").and_then(|v| v.as_i64()).unwrap_or(0)
    );
    let _ = es.folder_put(PAGE_FOLDER, &page_id, page);
    let mut sess = es
        .folder_get(SESSION_FOLDER, session_id)
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            json!({
                "schema": "connector.browser.session.v1",
                "session_id": session_id,
                "agent_pid": agent_pid,
                "origin": origin,
                "pages": [],
                "started_ms": chrono::Utc::now().timestamp_millis(),
            })
        });
    if let Some(arr) = sess.get_mut("pages").and_then(|v| v.as_array_mut()) {
        arr.push(json!({
            "url": page.get("url"),
            "status": page.get("status"),
            "title": page.get("title"),
            "sha256": page.get("sha256"),
            "at_ms": page.get("at_ms"),
            "page_id": page_id,
        }));
        if arr.len() > 80 {
            let drop_n = arr.len() - 80;
            arr.drain(0..drop_n);
        }
    }
    sess["updated_ms"] = json!(chrono::Utc::now().timestamp_millis());
    sess["page_count"] = json!(sess
        .get("pages")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0));
    es.folder_put(SESSION_FOLDER, session_id, &sess)
        .map_err(|e| json!({"ok": false, "error": e.to_string()}))?;
    Ok(())
}

fn body_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn looks_like_html(s: &str) -> bool {
    let t = s.trim_start();
    let head = t.chars().take(16).collect::<String>().to_ascii_lowercase();
    head.starts_with("<!doctype")
        || head.starts_with("<html")
        || t.to_ascii_lowercase().contains("<title")
}

fn capture_tag(html: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let lower = html.to_ascii_lowercase();
    let start = lower.find(&open.to_ascii_lowercase())?;
    let after = html[start..].find('>')? + start + 1;
    let end_rel = lower[after..].find(&close.to_ascii_lowercase())?;
    Some(html[after..after + end_rel].trim().to_string())
}

fn strip_blocks(html: &str) -> String {
    let mut s = html.to_string();
    for tag in ["script", "style", "noscript"] {
        loop {
            let lower = s.to_ascii_lowercase();
            let open = format!("<{tag}");
            let close = format!("</{tag}>");
            let Some(a) = lower.find(&open) else { break };
            let Some(b) = lower[a..].find(&close) else {
                break;
            };
            let end = a + b + close.len();
            s.replace_range(a..end, " ");
        }
    }
    s
}

fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_hrefs(html: &str, page_url: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = html.to_ascii_lowercase();
    let mut idx = 0;
    while let Some(h) = lower[idx..].find("href=") {
        let abs = idx + h + 5;
        let rest = html.get(abs..).unwrap_or("");
        let rest = rest.trim_start();
        let (quoted, rest) = if let Some(r) = rest.strip_prefix('"') {
            (true, r)
        } else if let Some(r) = rest.strip_prefix('\'') {
            (true, r)
        } else {
            (false, rest)
        };
        let end = if quoted {
            rest.find(['"', '\'']).unwrap_or(rest.len().min(512))
        } else {
            rest.find(|c: char| c.is_whitespace() || c == '>')
                .unwrap_or(rest.len().min(512))
        };
        let raw = rest[..end].trim();
        if let Some(absu) = resolve_link(page_url, raw) {
            if !out.iter().any(|x| x == &absu) {
                out.push(absu);
            }
        }
        idx = abs + 1;
        if out.len() >= 40 {
            break;
        }
    }
    out
}

fn resolve_link(page_url: &str, href: &str) -> Option<String> {
    let h = href.trim();
    if h.is_empty() || h.starts_with('#') || h.starts_with("javascript:") || h.starts_with("mailto:")
    {
        return None;
    }
    if h.starts_with("http://") || h.starts_with("https://") {
        return Some(h.to_string());
    }
    let origin = origin_of(page_url).ok()?;
    if let Some(rest) = h.strip_prefix("//") {
        let scheme = if page_url.starts_with("https") {
            "https://"
        } else {
            "http://"
        };
        return Some(format!("{scheme}{rest}"));
    }
    if h.starts_with('/') {
        return Some(format!("{origin}{h}"));
    }
    let base = page_url.rsplit_once('/').map(|(a, _)| a).unwrap_or(page_url);
    Some(format!("{base}/{h}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_strips_path() {
        assert_eq!(
            origin_of("https://example.com/a/b?x=1").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            origin_of("http://localhost:8080/x").unwrap(),
            "http://localhost:8080"
        );
    }

    #[test]
    fn extracts_title_links_excerpt() {
        let html = r#"<html><head><title>Hello World</title>
            <script>ignore()</script></head>
            <body><p>Visible text here.</p>
            <a href="/next">n</a>
            <a href="https://other.test/x">o</a>
            </body></html>"#;
        let d = extract_document(html, "https://example.com/page");
        assert_eq!(d.title, "Hello World");
        assert!(d.excerpt.contains("Visible text"));
        assert!(!d.excerpt.contains("ignore"));
        assert!(d.links.iter().any(|l| l == "https://example.com/next"));
        assert!(d.links.iter().any(|l| l == "https://other.test/x"));
        assert_eq!(d.same_origin_links, 1);
        assert_eq!(d.cross_origin_links, 1);
    }
}

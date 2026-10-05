//! AIOS-A6 — `connector deploy`, `connector run`, `connector diff` commands
//!
//! ```text
//! aapi deploy agent.yaml               — register manifest, start agent
//! aapi deploy agent.yaml --dry-run     — validate only, no state mutation
//! aapi run    agent.yaml --input "hi"  — ephemeral once-off run, then teardown
//! aapi diff   <name>                   — diff live manifest vs file on disk
//! ```

use std::path::Path;
use std::time::Duration;

// ── HTTP helpers ──────────────────────────────────────────────────────────────

fn platform_url(gateway: &str) -> String {
    std::env::var("CONNECTOR_SERVER_URL")
        .unwrap_or_else(|_| gateway.replace(":8080", ":9090"))
}

fn auth_header() -> Option<String> {
    std::env::var("CONNECTOR_API_KEY")
        .ok()
        .or_else(|| std::env::var("CONNECTOR_TOKEN").ok())
        .map(|k| format!("Bearer {}", k))
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
}

fn add_auth(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Some(h) = auth_header() {
        rb.header("Authorization", h)
    } else {
        rb
    }
}

fn load_manifest_source(path: &str) -> Result<(String, &'static str), Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read '{}': {}", path, e))?;
    let format = if path.ends_with(".json") { "json" } else { "yaml" };
    Ok((raw, format))
}

// ── Manifest loading ──────────────────────────────────────────────────────────

/// Load and parse an `agent.yaml` file into a serde_json::Value.
/// Supports both YAML and JSON extensions.
fn load_manifest(path: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let (raw, format) = load_manifest_source(path)?;

    let manifest: serde_json::Value = if format == "json" {
        serde_json::from_str(&raw)?
    } else {
        let yaml_val: serde_yaml::Value = serde_yaml::from_str(&raw)
            .map_err(|e| format!("YAML parse error in '{}': {}", path, e))?;
        serde_json::to_value(yaml_val)?
    };

    Ok(manifest)
}

/// Validate the manifest has required fields; returns a list of validation errors.
fn validate_manifest(manifest: &serde_json::Value) -> Vec<String> {
    let mut errors = Vec::new();

    let api_version = manifest.get("apiVersion").and_then(|v| v.as_str()).unwrap_or("");
    if !api_version.starts_with("connector/") {
        errors.push(format!("apiVersion must be 'connector/v1' (got '{}')", api_version));
    }

    let kind = manifest.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if kind != "Agent" {
        errors.push(format!("kind must be 'Agent' (got '{}')", kind));
    }

    let name = manifest
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if name.is_empty() {
        errors.push("metadata.name is required".to_string());
    }

    if manifest.get("spec").is_none() {
        errors.push("spec section is required".to_string());
    }

    errors
}

// ── deploy ────────────────────────────────────────────────────────────────────

/// `aapi deploy <path> [--dry-run]`
pub async fn deploy(
    gateway: &str,
    path: &str,
    dry_run: bool,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (manifest_raw, manifest_format) = load_manifest_source(path)?;
    let manifest = load_manifest(path)?;

    // Validate
    let errors = validate_manifest(&manifest);
    if !errors.is_empty() {
        eprintln!("Manifest validation failed:");
        for e in &errors {
            eprintln!("  ✗ {}", e);
        }
        if dry_run {
            println!("\nDry-run complete — {} error(s) found.", errors.len());
        }
        std::process::exit(1);
    }

    let name = manifest["metadata"]["name"].as_str().unwrap_or("unknown");
    let version = manifest["metadata"]
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("1.0.0");

    if dry_run {
        println!("Dry-run: manifest '{}' v{} is valid.", name, version);
        println!("\n  apiVersion : {}", manifest.get("apiVersion").unwrap_or(&serde_json::json!("-")));
        println!("  kind       : {}", manifest.get("kind").unwrap_or(&serde_json::json!("-")));
        println!("  name       : {}", name);
        println!("  version    : {}", version);
        if let Some(spec) = manifest.get("spec") {
            if let Some(model) = spec.get("model") {
                println!("  model      : {}", model.get("name").unwrap_or(&serde_json::json!("-")));
            }
            if let Some(res) = spec.get("resources") {
                println!("  token_budget: {}", res.get("token_budget").unwrap_or(&serde_json::json!("-")));
                println!("  priority    : {}", res.get("priority").unwrap_or(&serde_json::json!("-")));
            }
        }
        println!("\nNo changes applied (dry-run).");
        return Ok(());
    }

    // POST to platform registry + agent registration endpoint
    let url = format!("{}/api/v1/deploy", platform_url(gateway));
    let body = serde_json::json!({
        "manifest": manifest_raw,
        "format": manifest_format,
        "dry_run": false,
        "deployed_by": "aapi-cli",
    });

    let resp = add_auth(http_client().post(&url).json(&body))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&resp)?),
        _ => {
            let pid = resp.get("agent_pid").and_then(|v| v.as_str()).unwrap_or(name);
            let status = if resp.get("deployed").and_then(|v| v.as_bool()).unwrap_or(false) {
                "deployed"
            } else {
                "unknown"
            };
            let cid = resp.get("cid").and_then(|v| v.as_str()).unwrap_or("-");
            let ver = resp.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
            println!("Deployed agent '{}'", name);
            println!("  PID          : {}", pid);
            println!("  Status       : {}", status);
            println!("  Manifest CID : {}", cid);
            println!("  Version      : {}", ver);
            println!("\nRun `aapi agent ps` to see all live agents.");
        }
    }
    Ok(())
}

pub async fn upgrade(
    gateway: &str,
    path: &str,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = load_manifest(path)?;
    let name = manifest
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let requested_version = manifest
        .get("metadata")
        .and_then(|m| m.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let history_url = format!("{}/api/v1/deploy/history/{}", platform_url(gateway), name);
    let history_resp = add_auth(http_client().get(&history_url)).send().await?;

    if history_resp.status() == reqwest::StatusCode::NOT_FOUND {
        eprintln!("Agent '{}' is not currently deployed. Use `aapi deploy {}` first.", name, path);
        std::process::exit(1);
    }

    let history_json = history_resp.error_for_status()?.json::<serde_json::Value>().await?;
    let previous_version = history_json.get("active_version").and_then(|v| v.as_u64()).unwrap_or(0);
    let (manifest_raw, manifest_format) = load_manifest_source(path)?;
    let deploy_url = format!("{}/api/v1/deploy", platform_url(gateway));
    let body = serde_json::json!({
        "manifest": manifest_raw,
        "format": manifest_format,
        "dry_run": false,
        "deployed_by": "aapi-cli",
    });
    let resp = add_auth(http_client().post(&deploy_url).json(&body))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "previous_active_version": previous_version,
            "requested_manifest_version": requested_version,
            "result": resp,
        }))?);
        return Ok(());
    }

    let new_version = resp.get("version").and_then(|v| v.as_u64()).unwrap_or(previous_version + 1);
    let cid = resp.get("cid").and_then(|v| v.as_str()).unwrap_or("-");
    println!("Upgraded agent '{}'", name);
    println!("  Previous rev : {}", previous_version);
    println!("  New rev      : {}", new_version);
    println!("  Manifest ver : {}", requested_version);
    println!("  Manifest CID : {}", cid);
    println!("\nRun `aapi history {}` to inspect all revisions.", name);
    Ok(())
}

pub async fn history(
    gateway: &str,
    name: &str,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/deploy/history/{}", platform_url(gateway), name);
    let resp = add_auth(http_client().get(&url))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    let active_version = resp.get("active_version").and_then(|v| v.as_u64()).unwrap_or(0);
    let count = resp.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
    println!("Revision history for '{}'", name);
    println!("  Active rev : {}", active_version);
    println!("  Revisions  : {}", count);
    println!();

    if let Some(versions) = resp.get("versions").and_then(|v| v.as_array()) {
        for version in versions {
            let version_index = version.get("version_index").and_then(|v| v.as_u64()).unwrap_or(0);
            let cid = version.get("cid").and_then(|v| v.as_str()).unwrap_or("-");
            let deployed_by = version.get("deployed_by").and_then(|v| v.as_str()).unwrap_or("-");
            let deployed_at = version.get("deployed_at").and_then(|v| v.as_u64()).unwrap_or(0);
            let active_marker = if version.get("is_active").and_then(|v| v.as_bool()).unwrap_or(false) {
                "*"
            } else {
                " "
            };
            println!(
                "{} rev {:<4} cid={} deployed_by={} at={}",
                active_marker,
                version_index,
                cid,
                deployed_by,
                deployed_at
            );
        }
    }

    Ok(())
}

// ── run ───────────────────────────────────────────────────────────────────────

/// `aapi run <path> --input <text>` — ephemeral agent: deploy, invoke once, teardown.
pub async fn run(
    gateway: &str,
    path: &str,
    input: &str,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (manifest_raw, manifest_format) = load_manifest_source(path)?;
    let manifest = load_manifest(path)?;

    let errors = validate_manifest(&manifest);
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("  ✗ {}", e);
        }
        std::process::exit(1);
    }

    let name = manifest["metadata"]["name"].as_str().unwrap_or("ephemeral");
    let base = platform_url(gateway);

    // Deploy ephemeral
    let deploy_url = format!("{}/api/v1/deploy", base);
    let deploy_body = serde_json::json!({
        "manifest": manifest_raw,
        "format": manifest_format,
        "deployed_by": "aapi-cli",
    });
    let deploy_resp = add_auth(http_client().post(&deploy_url).json(&deploy_body))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    let pid = match deploy_resp.get("agent_pid").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Deploy response missing 'agent_pid': {}", deploy_resp);
            std::process::exit(1);
        }
    };

    println!("Deployed ephemeral agent '{}' (pid: {})", name, pid);

    // Invoke once via VĀKYA submit
    let submit_url = format!("{}/api/v1/agents/{}/invoke", base, pid);
    let invoke_body = serde_json::json!({
        "input": input,
        "ephemeral": true,
    });
    let invoke_resp = add_auth(http_client().post(&submit_url).json(&invoke_body))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    // Teardown
    let delete_url = format!("{}/api/v1/agents/{}", base, pid);
    let _ = add_auth(http_client().delete(&delete_url))
        .send()
        .await;

    println!("Agent '{}' torn down.", name);

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&invoke_resp)?),
        _ => {
            let output = invoke_resp
                .get("output")
                .or_else(|| invoke_resp.get("result"))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| invoke_resp.to_string().leak());
            println!("\nOutput:\n{}", output);
        }
    }
    Ok(())
}

// ── diff ──────────────────────────────────────────────────────────────────────

/// `aapi diff <name> [--file agent.yaml]` — compare running manifest vs file on disk.
pub async fn diff(
    gateway: &str,
    name: &str,
    file: Option<&str>,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let base = platform_url(gateway);

    // Fetch running manifest from registry
    let url = format!("{}/api/v1/registry/{}/manifest", base, name);
    let live_resp = add_auth(http_client().get(&url))
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    let live_manifest = live_resp.get("manifest").cloned()
        .unwrap_or_else(|| live_resp.clone());

    // Try to load disk manifest
    let disk_path = file.map(|f| f.to_string())
        .unwrap_or_else(|| format!("{}.yaml", name));

    if !Path::new(&disk_path).exists() {
        println!("No local file '{}' found for diff.", disk_path);
        println!("Live manifest:\n{}", serde_json::to_string_pretty(&live_manifest)?);
        return Ok(());
    }

    let disk_manifest = load_manifest(&disk_path)?;

    if format == "json" {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "live": live_manifest,
            "disk": disk_manifest,
        }))?);
        return Ok(());
    }

    // Text diff: compare key fields
    println!("Diff: '{}' (live vs {})", name, disk_path);
    println!("{}", "─".repeat(60));

    let live_ver = live_manifest.get("metadata")
        .and_then(|m| m.get("version")).and_then(|v| v.as_str()).unwrap_or("-");
    let disk_ver = disk_manifest.get("metadata")
        .and_then(|m| m.get("version")).and_then(|v| v.as_str()).unwrap_or("-");

    if live_ver != disk_ver {
        println!("  version    : live={} → disk={}", live_ver, disk_ver);
    } else {
        println!("  version    : {} (unchanged)", live_ver);
    }

    // Compare spec fields
    for key in &["model", "instructions", "resources", "security", "lifecycle"] {
        let live_val = live_manifest.get("spec").and_then(|s| s.get(key));
        let disk_val = disk_manifest.get("spec").and_then(|s| s.get(key));
        match (live_val, disk_val) {
            (Some(l), Some(d)) if l != d => {
                println!("  spec.{:<14}: changed", key);
            }
            (None, Some(_)) => println!("  spec.{:<14}: added in disk file", key),
            (Some(_), None) => println!("  spec.{:<14}: removed in disk file", key),
            _ => {}
        }
    }

    let live_json = serde_json::to_string(&live_manifest)?;
    let disk_json = serde_json::to_string(&disk_manifest)?;
    if live_json == disk_json {
        println!("\n  No differences found — live manifest matches disk file.");
    } else {
        println!("\nRun `aapi deploy {}` to apply disk changes.", disk_path);
    }
    Ok(())
}

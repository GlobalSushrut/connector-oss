//! Library surface for the `cargo-connector` Cargo subcommand (used by tests).

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPluginSpec {
    pub vendor: String,
    pub slug: String,
    /// Rust package / binary name (`snake_case`).
    pub rust_crate: String,
    /// Human-readable plugin title.
    pub display_name: String,
    /// Directory to create under `parent` (e.g. `acme-hello`).
    pub project_dir_name: String,
}

/// Parse `vendor/slug` or bare `slug` (vendor defaults to `local`). Normalizes to lowercase slugs.
pub fn parse_plugin_spec(name: &str) -> Result<NewPluginSpec, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("plugin name must be non-empty".into());
    }
    let (vendor, slug) = if let Some((v, s)) = name.split_once('/') {
        let v = slug_segment(v)?;
        let s = slug_segment(s)?;
        if s.is_empty() {
            return Err("slug part after '/' must be non-empty".into());
        }
        (v, s)
    } else {
        ("local".to_string(), slug_segment(name)?)
    };
    if vendor.is_empty() {
        return Err("vendor segment must be non-empty".into());
    }
    let rust_crate = slug.replace('-', "_");
    if rust_crate.is_empty() || rust_crate.chars().next() == Some('_') {
        return Err("could not derive a Rust crate name from the slug".into());
    }
    let display_name = title_from_slug(&slug);
    let project_dir_name = format!("{vendor}-{slug}");
    Ok(NewPluginSpec {
        vendor,
        slug,
        rust_crate,
        display_name,
        project_dir_name,
    })
}

fn slug_segment(raw: &str) -> Result<String, String> {
    let raw = raw.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return Err("segment must be non-empty".into());
    }
    let mut out = String::with_capacity(raw.len());
    let mut prev_hyphen = false;
    for c in raw.chars() {
        let c = match c {
            'a'..='z' | '0'..='9' | '-' => c,
            '_' | ' ' => '-',
            _ => {
                return Err(format!(
                    "invalid character in `{raw}` (only a-z, 0-9, hyphen, underscore, space)"
                ));
            }
        };
        if c == '-' {
            if out.is_empty() || prev_hyphen {
                continue;
            }
            prev_hyphen = true;
            out.push(c);
        } else {
            prev_hyphen = false;
            out.push(c);
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        return Err("segment became empty after normalization".into());
    }
    Ok(out)
}

fn title_from_slug(slug: &str) -> String {
    slug
        .split('-')
        .filter(|s| !s.is_empty())
        .map(|w| {
            let mut it = w.chars();
            let first = it.next().unwrap_or_default().to_uppercase().to_string();
            first + it.as_str()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn plugin_toml(spec: &NewPluginSpec) -> String {
    let id = format!("{}/{}", spec.vendor, spec.slug);
    let route_base = format!("/plugins/{}", spec.slug);
    let admin = format!("/plugins/{}/admin/*", spec.slug);
    format!(
        r#"# AGOS plugin scaffold — run `cargo build --release`, then package with connector-cpkg / Hub when ready.
# Validate: `connectorctl plugin verify .`

[plugin]
id = "{id}"
name = "{name}"
version = "0.1.0"
author = "{author}"
license = "MIT"
min_kernel = "0.1.0"
agos_abi = "agos.v1"

[runtime]
type = "subprocess"
entrypoint = "target/release/{bin}"
memory_mb = 64
vcpus = 1
shared = false
max_concurrency = 4
idle_window = "30s"
cold_start_budget_ms = 500

[routes]
prefix = "{route_base}"
admin = "{admin}"

[capabilities]
required = ["audit.write"]

[ui]
pages = [{{ path = "{route_base}", title = "{name}", role = "operator" }}]
"#,
        id = id,
        name = spec.display_name.replace('"', "'"),
        author = if spec.vendor == "local" {
            "local"
        } else {
            &spec.vendor
        },
        bin = spec.rust_crate,
        route_base = route_base,
        admin = admin,
    )
}

fn cargo_toml(spec: &NewPluginSpec) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"
publish = false

[[bin]]
name = "{name}"
path = "src/main.rs"
"#,
        name = spec.rust_crate,
    )
}

fn main_rs(spec: &NewPluginSpec) -> String {
    format!(
        r#"//! Entry point for `{id}` (AGOS subprocess plugin).
//!
//! Under Connector, the kernel may pass a handshake via `AGOS_HANDSHAKE_*` env vars
//! (see `connector-plugin-handshake` / `agos-sdk`). This scaffold keeps a minimal
//! `std` binary so `cargo build` works out of the box.

fn main() {{
    println!("{{}} v{{}} — OK", "{title}", env!("CARGO_PKG_VERSION"));
}}
"#,
        id = format!("{}/{}", spec.vendor, spec.slug),
        title = spec.display_name.replace('"', "'"),
    )
}

fn gitignore() -> &'static str {
    "/target\nCargo.lock\n"
}

/// Writes a new Rust AGOS plugin project at `parent_dir / spec.project_dir_name`.
pub fn write_scaffold(parent_dir: &Path, spec: &NewPluginSpec) -> Result<PathBuf, String> {
    let root = parent_dir.join(&spec.project_dir_name);
    if root.exists() {
        return Err(format!(
            "destination already exists: {}",
            root.display()
        ));
    }
    fs::create_dir_all(root.join("src")).map_err(|e| e.to_string())?;
    fs::write(root.join("plugin.toml"), plugin_toml(spec)).map_err(|e| e.to_string())?;
    fs::write(root.join("Cargo.toml"), cargo_toml(spec)).map_err(|e| e.to_string())?;
    fs::write(root.join("src/main.rs"), main_rs(spec)).map_err(|e| e.to_string())?;
    fs::write(root.join(".gitignore"), gitignore()).map_err(|e| e.to_string())?;
    Ok(root)
}

/// `args`: full `std::env::args()` including argv0 (e.g. `cargo-connector`, `connector`, `new`, `acme/foo`).
/// `parent`: directory in which the project folder is created (normally `std::env::current_dir()`).
pub fn run_cli_in(parent: &Path, args: &[String]) -> Result<(), String> {
    let pos = args.iter().position(|a| a == "new");
    let Some(i) = pos else {
        return Err(usage());
    };
    let mut lang = "rust";
    let mut name: Option<String> = None;
    let mut j = i + 1;
    while j < args.len() {
        match args[j].as_str() {
            "--lang" => {
                j += 1;
                if j >= args.len() {
                    return Err("--lang requires a value (rust|go|python)".into());
                }
                lang = args[j].as_str();
                j += 1;
            }
            s if s.starts_with('-') => return Err(format!("unknown flag: {s}")),
            s => {
                if name.is_some() {
                    return Err("unexpected extra argument after plugin name".into());
                }
                name = Some(s.to_string());
                j += 1;
            }
        }
    }
    let Some(name) = name else {
        return Err("missing <name> (e.g. `my-vendor/my-plugin` or `greeter`)".into());
    };
    match lang {
        "rust" => {}
        "go" | "python" => {
            return Err(format!(
                "language `{lang}` is not implemented yet; use `--lang rust` (default)"
            ));
        }
        _ => return Err(format!("unknown --lang `{lang}` (expected rust|go|python)")),
    }
    let spec = parse_plugin_spec(&name)?;
    let out = write_scaffold(parent, &spec)?;
    eprintln!(
        "Created AGOS Rust plugin `{}` at {}",
        format!("{}/{}", spec.vendor, spec.slug),
        out.display()
    );
    eprintln!("Next: cd {} && cargo build --release", spec.project_dir_name);
    eprintln!("Then: connectorctl plugin verify .");
    Ok(())
}

/// Same as [`run_cli_in`] with `parent = std::env::current_dir()`.
pub fn run_cli(args: &[String]) -> Result<(), String> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    run_cli_in(&cwd, args)
}

fn usage() -> String {
    "usage: cargo connector new <name> [--lang rust|go|python]\n\
     \n\
     <name> — `vendor/slug` (lowercase letters, digits, hyphen) or bare `slug` (vendor defaults to `local`).\n\
     Example: cargo connector new acme/hello-world"
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bare_slug() {
        let s = parse_plugin_spec("hello").unwrap();
        assert_eq!(s.vendor, "local");
        assert_eq!(s.slug, "hello");
        assert_eq!(s.rust_crate, "hello");
    }

    #[test]
    fn parse_vendor_slug() {
        let s = parse_plugin_spec("Acme/Hello-World").unwrap();
        assert_eq!(s.vendor, "acme");
        assert_eq!(s.slug, "hello-world");
        assert_eq!(s.rust_crate, "hello_world");
        assert_eq!(s.display_name, "Hello World");
        assert_eq!(s.project_dir_name, "acme-hello-world");
    }

    #[test]
    fn write_scaffold_smoke() {
        let dir = std::env::temp_dir().join(format!(
            "cargo-connector-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let spec = parse_plugin_spec("local/tiny").unwrap();
        let root = write_scaffold(&dir, &spec).unwrap();
        assert!(root.join("plugin.toml").exists());
        assert!(root.join("Cargo.toml").exists());
        assert!(root.join("src/main.rs").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_cli_accepts_cargo_subcommand_argv() {
        let dir = std::env::temp_dir().join(format!(
            "cargo-connector-cli-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let args = vec![
            "cargo-connector".into(),
            "connector".into(),
            "new".into(),
            "demo/cli-plug".into(),
        ];
        run_cli_in(&dir, &args).expect("cli");
        assert!(dir.join("demo-cli-plug").join("plugin.toml").is_file());
        let _ = fs::remove_dir_all(&dir);
    }
}

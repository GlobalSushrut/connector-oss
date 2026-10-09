use crate::config::{PermissionCheck, ResolvedRole};

#[derive(Debug, Clone)]
pub struct FsGuardResult {
    pub allowed: bool,
    pub verdict: String,
    pub reason: String,
    pub content_modified: bool,
    pub original_length: usize,
    pub sanitized_length: usize,
    pub sanitized_content: String,
}

pub fn check_write(resolved: &ResolvedRole, path: &str, operation: &str) -> PermissionCheck {
    resolved.check_file(operation, path)
}

pub fn scan_message_for_files(content: &str, resolved: &ResolvedRole) -> Vec<(String, PermissionCheck)> {
    let mut results = Vec::new();
    let path_patterns = [
        regex::Regex::new(r"(?m)^(?:File|file|Path|path):\s*(.+)$").ok(),
        regex::Regex::new(r"```\w*\s*@?([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})").ok(),
        regex::Regex::new(r"(?:^|\s)([a-zA-Z0-9_.-]+/[a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})(?:\s|$|:|\n)").ok(),
    ];
    for pat in path_patterns.iter().flatten() {
        for cap in pat.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let path = m.as_str().trim();
                if !path.is_empty() && path.len() < 256 {
                    let check = resolved.check_file("read", path);
                    results.push((path.to_string(), check));
                }
            }
        }
    }
    results
}

pub fn guard_content(content: &str, resolved: &ResolvedRole) -> FsGuardResult {
    let original_length = content.len();
    let mut sanitized = content.to_string();
    let mut modified = false;
    let checks = scan_message_for_files(content, resolved);
    for (path, check) in &checks {
        if !check.allowed {
            let path_escaped = regex::escape(path);
            if let Ok(re) = regex::Regex::new(&format!(r"(?s)(File:\s*{}.*?)(?=File:|```|\z)", path_escaped)) {
                let replacement = format!("[FILE HIDDEN BY POLICY: {} — {}]", path, check.reason);
                sanitized = re.replace_all(&sanitized, replacement.as_str()).to_string();
                modified = true;
            }
        }
    }
    FsGuardResult {
        allowed: true,
        verdict: if modified { "PROCESSED".to_string() } else { "ALLOW".to_string() },
        reason: if modified {
            format!("Filtered {} blocked file references", checks.iter().filter(|(_, c)| !c.allowed).count())
        } else {
            "Content clean".to_string()
        },
        content_modified: modified,
        original_length,
        sanitized_length: sanitized.len(),
        sanitized_content: sanitized,
    }
}

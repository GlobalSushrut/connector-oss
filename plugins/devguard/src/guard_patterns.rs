/// Extracted from server-side exec_guard dangerous command classifier.
/// DevGuard keeps this list plugin-owned; Connector only enforces policy API checks.

pub const ALWAYS_DENY: &[(&str, &str)] = &[
    ("rm -rf /", "Recursive delete of root filesystem"),
    ("rm -rf ~", "Recursive delete of home directory"),
    ("rm -rf .", "Recursive delete of current directory"),
    ("rm -rf /*", "Recursive delete of root filesystem"),
    (":(){ :|:& };:", "Fork bomb"),
    ("> /dev/sda", "Direct write to block device"),
    ("dd if=/dev/zero of=/dev/sd", "Disk wipe"),
    ("mkfs.", "Filesystem format"),
    ("chmod -R 777 /", "Permission wipe on root"),
];

pub const ALWAYS_FLAG: &[(&str, &str)] = &[
    ("curl | bash", "Remote code execution via pipe"),
    ("curl | sh", "Remote code execution via pipe"),
    ("wget | bash", "Remote code execution via pipe"),
    ("wget | sh", "Remote code execution via pipe"),
    ("eval ", "Dynamic code execution"),
    ("exec ", "Process replacement"),
    ("sudo ", "Privilege escalation"),
    ("su -", "User switch"),
    ("ssh ", "Remote shell access"),
    ("scp ", "Remote file copy"),
    ("rsync ", "Remote sync"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternVerdict {
    Deny,
    Flagged,
}

pub fn classify_command(command: &str) -> Option<(PatternVerdict, String, bool)> {
    let cmd = command.trim();
    for (pattern, reason) in ALWAYS_DENY {
        if cmd.contains(pattern) {
            return Some((PatternVerdict::Deny, reason.to_string(), false));
        }
    }
    for (pattern, reason) in ALWAYS_FLAG {
        if cmd.contains(pattern) {
            return Some((
                PatternVerdict::Flagged,
                reason.to_string(),
                has_network_egress(cmd),
            ));
        }
    }
    if (cmd.contains("| bash") || cmd.contains("| sh") || cmd.contains("| zsh"))
        && (cmd.contains("curl") || cmd.contains("wget"))
    {
        return Some((
            PatternVerdict::Deny,
            "Remote code execution via pipe detected".to_string(),
            true,
        ));
    }
    None
}

pub fn has_network_egress(command: &str) -> bool {
    let cmd = command.to_ascii_lowercase();
    ["curl ", "wget ", "ssh ", "scp ", "rsync ", "nc ", "telnet ", "nmap "]
        .iter()
        .any(|p| cmd.contains(p))
}

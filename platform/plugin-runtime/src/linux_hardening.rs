//! Linux **`prctl`** hardening for host subprocess plugins (Phase **5.9**).

#[cfg(target_os = "linux")]
fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn seccomp_mode_from_env() -> Option<String> {
    // Intent selector takes precedence and maps to a concrete seccomp mode.
    if let Ok(raw_intent) = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT") {
        let intent = raw_intent.trim().to_ascii_lowercase();
        if !intent.is_empty() {
            return match intent.as_str() {
                "off" | "none" | "disabled" => None,
                "strict" => Some("strict".to_string()),
                "safe_default" | "safe-default" | "safe" => Some("deny_dangerous".to_string()),
                "no_network" | "no-network" => Some("network_deny".to_string()),
                "no_ingress" | "no-ingress" => Some("network_ingress_deny".to_string()),
                other => Some(other.to_string()),
            };
        }
    }
    let raw = std::env::var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP").ok()?;
    let mode = raw.trim().to_ascii_lowercase();
    if mode.is_empty() || mode == "off" || mode == "0" || mode == "false" {
        None
    } else {
        Some(mode)
    }
}

#[cfg(target_os = "linux")]
#[inline]
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(target_os = "linux")]
#[inline]
fn bpf_jump_eq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    }
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn deny_dangerous_syscalls() -> &'static [u32] {
    &[
        libc::SYS_add_key as u32,
        libc::SYS_request_key as u32,
        libc::SYS_keyctl as u32,
        libc::SYS_unshare as u32,
        libc::SYS_perf_event_open as u32,
        libc::SYS_bpf as u32,
        libc::SYS_userfaultfd as u32,
        libc::SYS_clone3 as u32,
    ]
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn deny_network_syscalls() -> &'static [u32] {
    &[
        libc::SYS_socket as u32,
        libc::SYS_socketpair as u32,
        libc::SYS_connect as u32,
        libc::SYS_accept as u32,
        libc::SYS_accept4 as u32,
        libc::SYS_bind as u32,
        libc::SYS_listen as u32,
        libc::SYS_sendto as u32,
        libc::SYS_sendmsg as u32,
        libc::SYS_recvfrom as u32,
        libc::SYS_recvmsg as u32,
        libc::SYS_shutdown as u32,
        libc::SYS_setsockopt as u32,
    ]
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn deny_network_ingress_syscalls() -> &'static [u32] {
    &[
        libc::SYS_accept as u32,
        libc::SYS_accept4 as u32,
        libc::SYS_bind as u32,
        libc::SYS_listen as u32,
    ]
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn install_seccomp_errno_filter(denies: &[u32], label: &str) -> Result<(), std::io::Error> {
    let mut filter: Vec<libc::sock_filter> = Vec::new();
    // load seccomp_data.nr (offset 0)
    filter.push(bpf_stmt(
        (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        0,
    ));
    for &nr in denies {
        filter.push(bpf_jump_eq(nr, 0, 1));
        filter.push(bpf_stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));
    }
    filter.push(bpf_stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        libc::SECCOMP_RET_ALLOW,
    ));
    let mut prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            0usize,
            &mut prog as *mut libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "enable seccomp {}: {}",
                label,
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn install_seccomp_deny_dangerous() -> Result<(), std::io::Error> {
    install_seccomp_errno_filter(deny_dangerous_syscalls(), "deny_dangerous")
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn install_seccomp_network_deny() -> Result<(), std::io::Error> {
    install_seccomp_errno_filter(deny_network_syscalls(), "network_deny")
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn install_seccomp_network_ingress_deny() -> Result<(), std::io::Error> {
    install_seccomp_errno_filter(deny_network_ingress_syscalls(), "network_ingress_deny")
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn install_seccomp_deny_dangerous() -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP=deny_dangerous currently supports x86_64/aarch64 Linux only",
    ))
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn install_seccomp_network_deny() -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP=network_deny currently supports x86_64/aarch64 Linux only",
    ))
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn install_seccomp_network_ingress_deny() -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP=network_ingress_deny currently supports x86_64/aarch64 Linux only",
    ))
}

fn productionish_env() -> bool {
    matches!(
        std::env::var("CONNECTOR_ENV")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "production" | "prod" | "staging" | "pilots" | "pilot"
    ) || env_truthy("CONNECTOR_DEFENSE_STRICT")
}

/// Parse `CONNECTOR_MATRIX_EGRESS_MARK` (hex `0x…` or decimal) for intelligence-plane SO_MARK.
#[cfg(target_os = "linux")]
pub fn matrix_egress_mark_from_env() -> Option<u32> {
    let raw = std::env::var("CONNECTOR_MATRIX_EGRESS_MARK").ok()?;
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    s.parse::<u32>().ok()
}

/// Apply SO_MARK so nftables `inet connector_matrix` / iptables-nft can cut
/// **intelligence** egress (mark-keyed matrix tables — not OS-PID firewalling).
#[cfg(target_os = "linux")]
pub fn socket_set_matrix_mark(fd: libc::c_int, mark: u32) -> Result<(), std::io::Error> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Best-effort: mark already-open sockets in this process from cage env.
/// New sockets created after this still need `socket_set_matrix_mark` (or equivalent).
#[cfg(target_os = "linux")]
fn apply_matrix_mark_to_open_sockets(mark: u32) {
    let Ok(dir) = std::fs::read_dir("/proc/self/fd") else {
        return;
    };
    for ent in dir.flatten() {
        let Ok(fd) = ent.file_name().to_string_lossy().parse::<libc::c_int>() else {
            continue;
        };
        if fd < 3 {
            continue;
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            continue;
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFSOCK {
            continue;
        }
        let _ = socket_set_matrix_mark(fd, mark);
    }
}

#[cfg(target_os = "linux")]
fn apply_intelligence_matrix_mark_env() {
    let Some(mark) = matrix_egress_mark_from_env() else {
        return;
    };
    // Only when this worker is on the CDMI intelligence execution plane.
    if !env_truthy("CONNECTOR_INTELLIGENCE_EXECUTION_PLANE")
        && std::env::var("CONNECTOR_AGENT_PID").ok().filter(|s| !s.is_empty()).is_none()
    {
        return;
    }
    apply_matrix_mark_to_open_sockets(mark);
    // Probe-mark a fresh UDP socket so SO_MARK capability is exercised for the plane;
    // runtimes should call `socket_set_matrix_mark` on each new fd (exported helper).
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd >= 0 {
        let _ = socket_set_matrix_mark(fd, mark);
        unsafe {
            libc::close(fd);
        }
    }
}

/// Strip glob suffixes (`/**`, `/*`) to a concrete path for Landlock path_beneath.
#[cfg(target_os = "linux")]
fn landlock_path_from_pattern(pat: &str) -> Option<std::path::PathBuf> {
    let s = pat
        .trim()
        .trim_end_matches("/**")
        .trim_end_matches("/*")
        .trim_end_matches('*')
        .trim_end_matches('/');
    if s.is_empty() {
        return None;
    }
    let p = std::path::PathBuf::from(s);
    if p.exists() {
        Some(p)
    } else {
        // Allowlist parent if leaf missing (volatile cage may create later).
        p.parent().map(|par| par.to_path_buf()).filter(|par| par.exists())
    }
}

/// DI-3 — Landlock fail-closed when Ring-1 / prod / explicit env (not `CONNECTOR_KERNEL_FAIL_CLOSED`).
pub fn landlock_fail_closed_enabled() -> bool {
    // Hosted playground uses CONNECTOR_ENV=pilots (productionish) but has no Landlock cage.
    // Only honor an explicit fail-closed flag there — otherwise Talk hits fs_allowlist_required.
    if env_truthy("CONNECTOR_PLAYGROUND") {
        return env_truthy("CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED");
    }
    env_truthy("CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED")
        || env_truthy("CONNECTOR_IIA_RING1")
        || productionish_env()
}

/// Probe Landlock ABI availability in this process (create_ruleset + close). Parent honesty only.
#[cfg(target_os = "linux")]
pub fn landlock_kernel_abi_available() -> bool {
    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }
    let attr = LandlockRulesetAttr {
        handled_access_fs: 1 << 2, // READ_FILE
    };
    let ruleset = unsafe {
        libc::syscall(
            444, // SYS_landlock_create_ruleset
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0usize,
        )
    };
    if ruleset < 0 {
        return false;
    }
    unsafe {
        libc::close(ruleset as i32);
    }
    true
}

#[cfg(not(target_os = "linux"))]
pub fn landlock_kernel_abi_available() -> bool {
    false
}

/// Operator-facing Landlock posture (intent / mode / kernel probe — never claim child applied).
pub fn landlock_posture_snapshot() -> serde_json::Value {
    let intent = env_truthy("CONNECTOR_DOCKLOCK_LANDLOCK")
        || env_truthy("CONNECTOR_DOCKLOCK_VOLATILE")
        || env_truthy("CONNECTOR_INTELLIGENCE_EXECUTION_PLANE");
    let fail_closed = landlock_fail_closed_enabled();
    let abi = landlock_kernel_abi_available();
    serde_json::json!({
        "intent": intent,
        "fail_closed": fail_closed,
        "mode": if fail_closed { "fail_closed" } else { "soft_fail" },
        "kernel_abi_available": abi,
        "applied": if abi && intent { "unknown_until_child_restrict" } else { "not_applied" },
        "honesty": "Parent never claims Landlock applied from cage intent alone — child restrict_self is the truth.",
    })
}

/// B40: Landlock FS cage from `CONNECTOR_DOCKLOCK_FS_READ` / `_FS_WRITE` (colon-separated).
#[cfg(target_os = "linux")]
fn apply_docklock_landlock_env() -> Result<(), std::io::Error> {
    if !env_truthy("CONNECTOR_DOCKLOCK_LANDLOCK")
        && !env_truthy("CONNECTOR_DOCKLOCK_VOLATILE")
        && !env_truthy("CONNECTOR_INTELLIGENCE_EXECUTION_PLANE")
    {
        return Ok(());
    }
    let read_raw = std::env::var("CONNECTOR_DOCKLOCK_FS_READ").unwrap_or_default();
    let write_raw = std::env::var("CONNECTOR_DOCKLOCK_FS_WRITE").unwrap_or_default();
    if read_raw.trim().is_empty() && write_raw.trim().is_empty() {
        return Ok(());
    }

    let fail_closed = landlock_fail_closed_enabled();

    // Landlock ABI constants (linux/landlock.h) — fail-closed under Ring-1/prod.
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

    let handled = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REFER
        | LANDLOCK_ACCESS_FS_TRUNCATE;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }
    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: handled,
    };
    // SYS_landlock_create_ruleset = 444 on x86_64/aarch64 (Linux 5.13+)
    let ruleset = unsafe {
        libc::syscall(
            444, // SYS_landlock_create_ruleset
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0usize,
        )
    };
    if ruleset < 0 {
        if fail_closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "landlock_create_ruleset failed (CONNECTOR_DOCKLOCK_LANDLOCK_FAIL_CLOSED / Ring-1 / prod)",
            ));
        }
        // Kernel without Landlock — soft fail (lab).
        return Ok(());
    }
    let ruleset_fd = ruleset as i32;

    let read_access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR;
    let write_access = read_access
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_TRUNCATE;

    let mut added = 0u32;
    for (raw, access) in [(&read_raw, read_access), (&write_raw, write_access)] {
        for part in raw.split([':', ',']) {
            let Some(path) = landlock_path_from_pattern(part) else {
                continue;
            };
            let path_c = std::ffi::CString::new(path.to_string_lossy().as_bytes())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path"))?;
            let parent_fd = unsafe {
                libc::open(
                    path_c.as_ptr(),
                    libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
                )
            };
            if parent_fd < 0 {
                // Retry as file path (O_PATH without DIRECTORY).
                let parent_fd = unsafe { libc::open(path_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if parent_fd < 0 {
                    continue;
                }
                let path_attr = LandlockPathBeneathAttr {
                    allowed_access: access,
                    parent_fd,
                };
                let rc = unsafe {
                    libc::syscall(
                        445, // SYS_landlock_add_rule
                        ruleset_fd,
                        1, // LANDLOCK_RULE_PATH_BENEATH
                        &path_attr as *const LandlockPathBeneathAttr,
                        0usize,
                    )
                };
                unsafe {
                    libc::close(parent_fd);
                }
                if rc == 0 {
                    added += 1;
                }
                continue;
            }
            let path_attr = LandlockPathBeneathAttr {
                allowed_access: access,
                parent_fd,
            };
            let rc = unsafe {
                libc::syscall(
                    445,
                    ruleset_fd,
                    1,
                    &path_attr as *const LandlockPathBeneathAttr,
                    0usize,
                )
            };
            unsafe {
                libc::close(parent_fd);
            }
            if rc == 0 {
                added += 1;
            }
        }
    }

    if added == 0 {
        unsafe {
            libc::close(ruleset_fd);
        }
        if fail_closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "landlock: no path rules applied (fail-closed; check CONNECTOR_DOCKLOCK_FS_READ/WRITE)",
            ));
        }
        return Ok(());
    }
    // Enforce no_new_privs before restrict_self (Landlock requirement).
    let _ = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    let rc = unsafe {
        libc::syscall(
            446, // SYS_landlock_restrict_self
            ruleset_fd,
            0usize,
        )
    };
    unsafe {
        libc::close(ruleset_fd);
    }
    if rc != 0 {
        if fail_closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "landlock_restrict_self failed (fail-closed)",
            ));
        }
        // Soft-fail: Landlock optional under lab kernels.
        return Ok(());
    }
    // Child-visible stamp (parent still reports unknown_until_child_restrict).
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("CONNECTOR_DOCKLOCK_LANDLOCK_STATUS", "applied");
    }
    Ok(())
}

/// Apply **`PR_SET_NO_NEW_PRIVS`** / **`PR_SET_DUMPABLE`** when respective env vars are set
/// (or by default under production/defense-strict).
/// Called from **`pre_exec`** after **`setpgid`** (subprocess spawn).
#[cfg(target_os = "linux")]
pub fn apply_linux_hardening_env() -> Result<(), std::io::Error> {
    let seccomp_mode = seccomp_mode_from_env();
    let prod = productionish_env();
    let need_no_new_privs = env_truthy("CONNECTOR_PLUGIN_SUBPROCESS_NO_NEW_PRIVS")
        || seccomp_mode.is_some()
        || (prod && !env_truthy("CONNECTOR_PLUGIN_SUBPROCESS_ALLOW_PRIVS"));
    if need_no_new_privs {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let need_not_dumpable = env_truthy("CONNECTOR_PLUGIN_SUBPROCESS_NOT_DUMPABLE")
        || (prod && !env_truthy("CONNECTOR_PLUGIN_SUBPROCESS_ALLOW_DUMPABLE"));
    if need_not_dumpable {
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    // Mark sockets before seccomp may deny setsockopt (network_deny includes it).
    apply_intelligence_matrix_mark_env();
    // B40: Landlock FS allowlist from DockLock cage (before seccomp).
    apply_docklock_landlock_env()?;
    if let Some(mode) = seccomp_mode {
        match mode.as_str() {
            // Kernel strict mode: read/write/_exit/sigreturn only.
            "strict" | "mode_strict" => {
                if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_STRICT, 0, 0, 0) } != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("enable seccomp strict: {}", std::io::Error::last_os_error()),
                    ));
                }
            }
            // Filter mode: block a high-risk syscall set while allowing normal plugin operation.
            "deny_dangerous" | "deny-dangerous" | "baseline" => {
                install_seccomp_deny_dangerous()?;
            }
            // Filter mode: deny socket-oriented syscalls with EPERM.
            "network_deny" | "network-deny" => {
                install_seccomp_network_deny()?;
            }
            // Filter mode: deny inbound/socket-server syscalls while allowing outbound client sockets.
            "network_ingress_deny" | "network-ingress-deny" | "ingress_deny" | "ingress-deny" => {
                install_seccomp_network_ingress_deny()?;
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "unsupported CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP mode: {} (supported: strict, deny_dangerous, network_deny, network_ingress_deny, off)",
                        other
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[inline]
pub fn apply_linux_hardening_env() -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn env_truthy_parsing() {
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_TEST_XY");
        assert!(!env_truthy("CONNECTOR_PLUGIN_SUBPROCESS_TEST_XY"));
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_TEST_XY", "1");
        assert!(env_truthy("CONNECTOR_PLUGIN_SUBPROCESS_TEST_XY"));
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_TEST_XY");
    }

    #[test]
    fn matrix_egress_mark_parses_hex_and_decimal() {
        std::env::remove_var("CONNECTOR_MATRIX_EGRESS_MARK");
        assert_eq!(matrix_egress_mark_from_env(), None);
        std::env::set_var("CONNECTOR_MATRIX_EGRESS_MARK", "0xCD001234");
        assert_eq!(matrix_egress_mark_from_env(), Some(0xCD001234));
        std::env::set_var("CONNECTOR_MATRIX_EGRESS_MARK", "42");
        assert_eq!(matrix_egress_mark_from_env(), Some(42));
        std::env::remove_var("CONNECTOR_MATRIX_EGRESS_MARK");
    }

    #[test]
    fn seccomp_mode_parsing() {
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT");
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP");
        assert_eq!(seccomp_mode_from_env(), None);
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP", "off");
        assert_eq!(seccomp_mode_from_env(), None);
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP", "strict");
        assert_eq!(seccomp_mode_from_env(), Some("strict".to_string()));
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP", "deny_dangerous");
        assert_eq!(
            seccomp_mode_from_env(),
            Some("deny_dangerous".to_string())
        );
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP", "network_deny");
        assert_eq!(seccomp_mode_from_env(), Some("network_deny".to_string()));
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP", "network_ingress_deny");
        assert_eq!(
            seccomp_mode_from_env(),
            Some("network_ingress_deny".to_string())
        );
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT");
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP");
    }

    #[test]
    fn seccomp_intent_mapping_and_precedence() {
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT");
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP");
        assert_eq!(seccomp_mode_from_env(), None);

        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT", "safe_default");
        assert_eq!(seccomp_mode_from_env(), Some("deny_dangerous".to_string()));
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT", "no_network");
        assert_eq!(seccomp_mode_from_env(), Some("network_deny".to_string()));
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT", "no_ingress");
        assert_eq!(seccomp_mode_from_env(), Some("network_ingress_deny".to_string()));

        // Intent wins over explicit mode.
        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP", "strict");
        assert_eq!(seccomp_mode_from_env(), Some("network_ingress_deny".to_string()));

        std::env::set_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT", "off");
        assert_eq!(seccomp_mode_from_env(), None);

        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP_INTENT");
        std::env::remove_var("CONNECTOR_PLUGIN_SUBPROCESS_SECCOMP");
    }
}

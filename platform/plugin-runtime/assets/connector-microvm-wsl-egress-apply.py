#!/usr/bin/env python3
"""Apply Linux TAP + iptables (+ optional ip6tables) inside WSL2 for Connector microVM egress (Phase 5.7.2).

Input JSON path (argv[1]) schema:
  vm_id, v4: [["dotted", port], ...], v6: [["addr", port], ...], allow_resolver_dns: bool

Prints one JSON line to stdout: ok, network_iface, ip_boot_arg, detail (telemetry + cleanup_hint).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple


def emit(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def fnv1a64(s: str) -> int:
    h = 1469598103934665603
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def tap_name(vm_id: str) -> str:
    h = fnv1a64(vm_id)
    return f"fc{h & 0x0000FFFFFFFFFFFF:012x}"


def subnet_octet(vm_id: str) -> int:
    h = fnv1a64(vm_id)
    return (h % 200) + 20


def ipt_chain(vm_id: str) -> str:
    h = fnv1a64(vm_id)
    x = (h & 0xFFFFFFFF) ^ ((h >> 32) & 0xFFFFFFFF)
    return f"cvm{x:08x}"


def ipt6_chain(vm_id: str) -> str:
    h = fnv1a64(vm_id)
    x = (h & 0xFFFFFFFF) ^ ((h >> 32) & 0xFFFFFFFF)
    return f"c6m{x:08x}"


def ula_guest_host(vm_id: str) -> Tuple[str, str]:
    h = fnv1a64(vm_id) & 0xFFFF
    gw = f"fd00:c0ff:ee99:{h:04x}::1"
    guest = f"fd00:c0ff:ee99:{h:04x}::2"
    return guest, gw


def run_cmd(args: List[str], ctx: str) -> None:
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{ctx}: rc={p.returncode} stderr={p.stderr!r} stdout={p.stdout!r}")


def run_cmd_best(args: List[str]) -> None:
    subprocess.run(args, capture_output=True, text=True)


def default_wan_v4() -> str:
    p = subprocess.run(["ip", "route", "get", "1.1.1.1"], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"ip_route_get_v4:{p.stderr}")
    s = p.stdout
    i = s.find(" dev ")
    if i < 0:
        raise RuntimeError(f"parse_ip_route_v4:{s!r}")
    rest = s[i + 5 :].strip().split()
    if not rest:
        raise RuntimeError("empty_wan_v4")
    return rest[0]


def default_wan_v6(probe: str) -> str:
    p = subprocess.run(["ip", "-6", "route", "get", probe], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"ip_route_get_v6:{p.stderr}")
    s = p.stdout
    i = s.find(" dev ")
    if i < 0:
        raise RuntimeError(f"parse_ip_route_v6:{s!r}")
    rest = s[i + 5 :].strip().split()
    if not rest:
        raise RuntimeError("empty_wan_v6")
    return rest[0]


def ensure_ipv4_forward() -> None:
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
    p = subprocess.run(["sysctl", "-n", "net.ipv4.ip_forward"], capture_output=True, text=True)
    if p.stdout.strip() != "1":
        raise RuntimeError("net.ipv4.ip_forward_not_1")


def ensure_ipv6_forward() -> None:
    for k in ("net.ipv6.conf.all.forwarding", "net.ipv6.conf.default.forwarding"):
        subprocess.run(["sysctl", "-w", f"{k}=1"], capture_output=True)
    p = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.forwarding"], capture_output=True, text=True)
    if p.stdout.strip() != "1":
        raise RuntimeError("net.ipv6.conf.all.forwarding_not_1")


def resolv_v4_nameservers() -> List[str]:
    out: List[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    ip = parts[1]
                    if ":" not in ip:
                        out.append(ip)
    except OSError:
        pass
    return out


def resolv_v6_nameservers() -> List[str]:
    out: List[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    ip = parts[1]
                    if ":" in ip:
                        out.append(ip)
    except OSError:
        pass
    return out


def apply(cfg_path: str) -> Dict[str, Any]:
    with open(cfg_path, encoding="utf-8") as f:
        spec = json.load(f)
    vm_id = spec.get("vm_id") or ""
    v4: List[Tuple[str, int]] = [(str(a), int(p)) for a, p in spec.get("v4") or []]
    v6: List[Tuple[str, int]] = [(str(a), int(p)) for a, p in spec.get("v6") or []]
    allow_dns = bool(spec.get("allow_resolver_dns", True))
    if not vm_id:
        raise RuntimeError("vm_id_required")
    v4 = sorted(set(v4))
    v6 = sorted(set(v6))
    if not v4 and not v6:
        raise RuntimeError("no_tcp_dests")

    tap = tap_name(vm_id)
    chain = ipt_chain(vm_id)
    chain6 = ipt6_chain(vm_id)
    x = subnet_octet(vm_id)
    guest_ip = f"10.200.{x}.2"
    gw_ip = f"10.200.{x}.1"
    ip_boot_arg = f"ip={guest_ip}::{gw_ip}:255.255.255.0::eth0:off"
    uid = os.getuid()
    gid = os.getgid()

    wan = default_wan_v4()
    wan_v6 = ""
    guest_v6_s = ""
    gw_v6_s = ""
    if v6:
        wan_v6 = default_wan_v6(v6[0][0])
        guest_v6_s, gw_v6_s = ula_guest_host(vm_id)

    # best-effort teardown of prior state
    run_cmd_best(
        ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", f"{guest_ip}/32", "-o", wan, "-j", "MASQUERADE"]
    )
    run_cmd_best(["iptables", "-D", "FORWARD", "-i", tap, "-j", chain])
    run_cmd_best(["iptables", "-F", chain])
    run_cmd_best(["iptables", "-X", chain])
    if v6 and guest_v6_s and wan_v6:
        run_cmd_best(
            [
                "ip6tables",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                f"{guest_v6_s}/128",
                "-o",
                wan_v6,
                "-j",
                "MASQUERADE",
            ]
        )
        run_cmd_best(["ip6tables", "-D", "FORWARD", "-i", tap, "-j", chain6])
        run_cmd_best(["ip6tables", "-F", chain6])
        run_cmd_best(["ip6tables", "-X", chain6])
    run_cmd_best(["ip", "link", "delete", tap])

    run_cmd(
        ["ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", str(uid), "group", str(gid)],
        "tuntap_add",
    )
    run_cmd(["ip", "link", "set", "dev", tap, "up"], "link_up")
    run_cmd(["ip", "addr", "add", f"{gw_ip}/24", "dev", tap], "addr_v4")
    if v6 and guest_v6_s:
        run_cmd(["ip", "-6", "addr", "add", f"{gw_v6_s}/64", "dev", tap], "addr_v6")

    ensure_ipv4_forward()
    if v6:
        ensure_ipv6_forward()

    run_cmd(["iptables", "-N", chain], "new_chain")
    run_cmd(
        ["iptables", "-A", chain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
        "established_v4",
    )
    if allow_dns:
        for ns in resolv_v4_nameservers():
            for proto in ("udp", "tcp"):
                run_cmd(
                    ["iptables", "-A", chain, "-d", ns, "-p", proto, "--dport", "53", "-j", "ACCEPT"],
                    "dns_v4",
                )
    for addr, port in v4:
        run_cmd(
            ["iptables", "-A", chain, "-d", addr, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
            "tcp_v4",
        )
    run_cmd(["iptables", "-A", chain, "-j", "DROP"], "drop_v4")
    run_cmd(["iptables", "-I", "FORWARD", "1", "-i", tap, "-j", chain], "jump_fwd_v4")
    run_cmd(
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", f"{guest_ip}/32", "-o", wan, "-j", "MASQUERADE"],
        "masq_v4",
    )

    extra_boot: List[str] = []
    if v6 and guest_v6_s:
        run_cmd(["ip6tables", "-N", chain6], "new_chain6")
        run_cmd(
            ["ip6tables", "-A", chain6, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            "established_v6",
        )
        if allow_dns:
            for ns in resolv_v6_nameservers():
                for proto in ("udp", "tcp"):
                    run_cmd(
                        ["ip6tables", "-A", chain6, "-d", ns, "-p", proto, "--dport", "53", "-j", "ACCEPT"],
                        "dns_v6",
                    )
        for addr, port in v6:
            run_cmd(
                ["ip6tables", "-A", chain6, "-d", addr, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
                "tcp_v6",
            )
        run_cmd(["ip6tables", "-A", chain6, "-j", "DROP"], "drop_v6")
        run_cmd(["ip6tables", "-I", "FORWARD", "1", "-i", tap, "-j", chain6], "jump_fwd_v6")
        run_cmd(
            [
                "ip6tables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                f"{guest_v6_s}/128",
                "-o",
                wan_v6,
                "-j",
                "MASQUERADE",
            ],
            "masq_v6",
        )
        extra_boot.append(f"connector.microvm_guest_ipv6={guest_v6_s}")
        iface = os.environ.get("CONNECTOR_MICROVM_GUEST_IFACE", "").strip()
        if iface:
            extra_boot.append(f"connector.microvm_guest_iface={iface}")

    detail: Dict[str, Any] = {
        "egress_enforce": "iptables_forward_wsl2",
        "tap": tap,
        "guest_ipv4": guest_ip,
        "gw_ipv4": gw_ip,
        "wan_if": wan,
        "iptables_chain": chain,
        "tcp_allow_v4": [f"{a}:{p}" for a, p in v4],
        "resolver_dns_v4_allowed": resolv_v4_nameservers() if allow_dns else [],
        "extra_boot_args": extra_boot,
    }
    if v6 and guest_v6_s:
        detail["guest_ipv6"] = guest_v6_s
        detail["gw_ipv6"] = gw_v6_s
        detail["wan_if_v6"] = wan_v6
        detail["ip6tables_chain"] = chain6
        detail["tcp_allow_v6"] = [f"{a}:{p}" for a, p in v6]
        detail["resolver_dns_v6_allowed"] = resolv_v6_nameservers() if allow_dns else []

    detail["cleanup_hint"] = {
        "iptables_forward_delete": ["iptables", "-D", "FORWARD", "-i", tap, "-j", chain],
        "iptables_chain_flush": ["iptables", "-F", chain],
        "iptables_chain_delete": ["iptables", "-X", chain],
        "nat_delete": [
            "iptables",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            f"{guest_ip}/32",
            "-o",
            wan,
            "-j",
            "MASQUERADE",
        ],
        "tap_delete": ["ip", "link", "delete", tap],
    }
    if v6 and guest_v6_s:
        detail["cleanup_hint"]["ip6tables_forward_delete"] = ["ip6tables", "-D", "FORWARD", "-i", tap, "-j", chain6]
        detail["cleanup_hint"]["ip6tables_chain_flush"] = ["ip6tables", "-F", chain6]
        detail["cleanup_hint"]["ip6tables_chain_delete"] = ["ip6tables", "-X", chain6]
        detail["cleanup_hint"]["nat6_delete"] = [
            "ip6tables",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            f"{guest_v6_s}/128",
            "-o",
            wan_v6,
            "-j",
            "MASQUERADE",
        ]

    return {
        "ok": True,
        "network_iface": {"iface_id": "eth0", "host_dev_name": tap},
        "ip_boot_arg": ip_boot_arg,
        "detail": detail,
    }


def cleanup_watch(argv: List[str]) -> int:
    """--watch-pid <n> --detail-json <path> — remove iptables/TAP after Firecracker PID exits."""
    pid = 0
    detail_path = ""
    i = 0
    while i < len(argv):
        if argv[i] == "--watch-pid" and i + 1 < len(argv):
            pid = int(argv[i + 1])
            i += 2
        elif argv[i] == "--detail-json" and i + 1 < len(argv):
            detail_path = argv[i + 1]
            i += 2
        else:
            i += 1
    if pid <= 0 or not detail_path:
        sys.stderr.write("cleanup_watch: need --watch-pid and --detail-json\n")
        return 2
    with open(detail_path, encoding="utf-8") as f:
        detail = json.load(f)
    tap = detail.get("tap") or ""
    chain = detail.get("iptables_chain") or ""
    guest_ip = detail.get("guest_ipv4") or ""
    wan = detail.get("wan_if") or ""
    chain6 = detail.get("ip6tables_chain") or ""
    guest_v6 = detail.get("guest_ipv6") or ""
    wan_v6 = detail.get("wan_if_v6") or ""
    proc_path = f"/proc/{pid}"
    while os.path.exists(proc_path):
        time.sleep(2)
    if guest_ip and wan:
        run_cmd_best(
            ["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", f"{guest_ip}/32", "-o", wan, "-j", "MASQUERADE"]
        )
    if tap and chain:
        run_cmd_best(["iptables", "-D", "FORWARD", "-i", tap, "-j", chain])
        run_cmd_best(["iptables", "-F", chain])
        run_cmd_best(["iptables", "-X", chain])
    if tap and chain6 and guest_v6 and wan_v6:
        run_cmd_best(
            [
                "ip6tables",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                f"{guest_v6}/128",
                "-o",
                wan_v6,
                "-j",
                "MASQUERADE",
            ]
        )
        run_cmd_best(["ip6tables", "-D", "FORWARD", "-i", tap, "-j", chain6])
        run_cmd_best(["ip6tables", "-F", chain6])
        run_cmd_best(["ip6tables", "-X", chain6])
    if tap:
        run_cmd_best(["ip", "link", "delete", tap])
    return 0


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--cleanup-watch":
        return cleanup_watch(sys.argv[2:])
    if len(sys.argv) != 2:
        emit({"ok": False, "code": "usage", "message": "connector-microvm-wsl-egress-apply.py <spec.json>"})
        return 2
    try:
        out = apply(sys.argv[1])
        emit(out)
        return 0
    except Exception as e:
        emit({"ok": False, "code": "apply_failed", "message": str(e)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

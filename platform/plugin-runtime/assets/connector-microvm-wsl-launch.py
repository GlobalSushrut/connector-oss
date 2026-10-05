#!/usr/bin/env python3
"""Run Firecracker inside WSL2 with the same UDS API sequence as connector-microvm host.rs.

Reads one JSON config file (FirecrackerVmConfig-shaped). Prints a single JSON object to stdout:
  ok: true  -> pid, api_socket_path, log_path, vm_id, firecracker_bin
  ok: false -> code, message, optional detail
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from typing import Any, Dict


def emit(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def put_api(sock_path: str, path: str, body: dict[str, Any]) -> None:
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    req = (
        f"PUT {path} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "\r\n"
    ).encode("utf-8") + payload
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(sock_path)
        s.sendall(req)
        s.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
        resp = b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        s.close()
    if not (resp.startswith("HTTP/1.1 204") or resp.startswith("HTTP/1.1 200")):
        raise RuntimeError(f"api_put_failed:{path}:{resp[:800]}")


def main() -> int:
    if len(sys.argv) != 2:
        emit({"ok": False, "code": "usage", "message": "expected: connector-microvm-wsl-launch.py <config.json>"})
        return 2
    cfg_path = sys.argv[1]
    try:
        with open(cfg_path, encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        emit({"ok": False, "code": "config_not_found", "message": cfg_path})
        return 1
    except json.JSONDecodeError as e:
        emit({"ok": False, "code": "invalid_config_json", "message": str(e)})
        return 1

    vm_id = cfg.get("vm_id")
    api_sock = cfg.get("api_socket_path")
    log_path = cfg.get("log_path")
    fc_bin = os.environ.get("CONNECTOR_WSL_FC_BIN") or cfg.get("firecracker_bin")
    boot = cfg.get("boot_source") or {}
    drives = cfg.get("drives") or []
    machine = cfg.get("machine_config") or {}

    if not vm_id or not api_sock or not log_path or not fc_bin:
        emit(
            {
                "ok": False,
                "code": "invalid_config",
                "message": "vm_id, api_socket_path, log_path, and firecracker_bin are required",
            }
        )
        return 1

    kernel = boot.get("kernel_image_path")
    if not kernel or not os.path.isfile(kernel):
        emit({"ok": False, "code": "kernel_missing", "message": kernel or ""})
        return 1

    root = next((d for d in drives if d.get("is_root_device")), None)
    if not root or not os.path.isfile(root.get("path_on_host", "")):
        emit({"ok": False, "code": "rootfs_missing", "message": (root or {}).get("path_on_host", "")})
        return 1

    if not os.path.isfile(fc_bin):
        emit({"ok": False, "code": "firecracker_missing", "message": fc_bin})
        return 1

    parent = os.path.dirname(api_sock)
    if parent:
        os.makedirs(parent, exist_ok=True)
    if os.path.exists(api_sock):
        try:
            os.remove(api_sock)
        except OSError as e:
            emit({"ok": False, "code": "api_socket_stale", "message": f"{api_sock}: {e}"})
            return 1

    log_parent = os.path.dirname(log_path)
    if log_parent:
        os.makedirs(log_parent, exist_ok=True)
    metrics_path = cfg.get("metrics_path")
    if metrics_path:
        mp = os.path.dirname(metrics_path)
        if mp:
            os.makedirs(mp, exist_ok=True)

    vsock = cfg.get("vsock") or {}
    if vsock.get("uds_path"):
        vp = os.path.dirname(vsock["uds_path"])
        if vp:
            os.makedirs(vp, exist_ok=True)
        if os.path.exists(vsock["uds_path"]):
            try:
                os.remove(vsock["uds_path"])
            except OSError:
                pass

    log_f = open(log_path, "ab", buffering=0)
    try:
        proc = subprocess.Popen(
            [fc_bin, "--api-sock", api_sock],
            stdout=log_f,
            stderr=subprocess.STDOUT,
        )
    except OSError as e:
        emit({"ok": False, "code": "firecracker_spawn", "message": str(e)})
        return 1
    finally:
        log_f.close()

    deadline = time.monotonic() + 4.0
    while not os.path.exists(api_sock):
        if time.monotonic() > deadline:
            try:
                proc.terminate()
            except Exception:
                pass
            emit(
                {
                    "ok": False,
                    "code": "api_socket_timeout",
                    "message": api_sock,
                    "detail": {"pid": proc.pid},
                }
            )
            return 1
        if proc.poll() is not None:
            emit(
                {
                    "ok": False,
                    "code": "firecracker_exited_early",
                    "message": f"exit={proc.returncode}",
                    "detail": {"pid": proc.pid, "log_path": log_path},
                }
            )
            return 1
        time.sleep(0.04)

    try:
        put_api(
            api_sock,
            "/machine-config",
            {
                "vcpu_count": machine.get("vcpu_count", 1),
                "mem_size_mib": machine.get("mem_mib", 256),
                "smt": machine.get("smt", False),
                "track_dirty_pages": machine.get("track_dirty_pages", False),
            },
        )
        put_api(
            api_sock,
            "/boot-source",
            {
                "kernel_image_path": kernel,
                "boot_args": boot.get("boot_args"),
                "initrd_path": boot.get("initrd_path"),
            },
        )
        for d in drives:
            did = d["drive_id"]
            put_api(
                api_sock,
                f"/drives/{did}",
                {
                    "drive_id": did,
                    "path_on_host": d["path_on_host"],
                    "is_root_device": d["is_root_device"],
                    "is_read_only": d.get("is_read_only", False),
                },
            )
        net = cfg.get("network_iface")
        if isinstance(net, dict) and net.get("iface_id") and net.get("host_dev_name"):
            iid = net["iface_id"]
            put_api(
                api_sock,
                f"/network-interfaces/{iid}",
                {"iface_id": iid, "host_dev_name": net["host_dev_name"]},
            )
        if vsock.get("guest_cid") is not None and vsock.get("uds_path"):
            put_api(
                api_sock,
                "/vsock",
                {"guest_cid": vsock["guest_cid"], "uds_path": vsock["uds_path"]},
            )
        if metrics_path:
            put_api(api_sock, "/metrics", {"metrics_path": metrics_path})
        put_api(api_sock, "/actions", {"action_type": "InstanceStart"})
    except RuntimeError as e:
        try:
            proc.terminate()
        except Exception:
            pass
        msg = str(e)
        if msg.startswith("api_put_failed:"):
            parts = msg.split(":", 2)
            path = parts[1] if len(parts) > 1 else ""
            body = parts[2] if len(parts) > 2 else msg
            emit(
                {
                    "ok": False,
                    "code": "api_put_failed",
                    "message": path,
                    "detail": {"response_prefix": body[:1200], "pid": proc.pid},
                }
            )
        else:
            emit({"ok": False, "code": "api_error", "message": msg, "detail": {"pid": proc.pid}})
        return 1

    emit(
        {
            "ok": True,
            "vm_id": vm_id,
            "pid": proc.pid,
            "api_socket_path": api_sock,
            "log_path": log_path,
            "firecracker_bin": fc_bin,
            "metrics_path": metrics_path,
            "launcher": "connector-microvm-wsl-launch.py",
        }
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        emit({"ok": False, "code": "internal", "message": str(e)})
        raise SystemExit(1)

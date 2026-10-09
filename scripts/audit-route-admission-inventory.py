#!/usr/bin/env python3
"""Validate admission_operation on wired effect routes in route-security-inventory.json.

Keep WIRED_EFFECT_ROUTES in sync with platform/server/src/substrate/admission_matrix.rs.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/architecture/route-security-inventory.json"

# (HTTP methods, inventory path) — admission must be declared "required"
WIRED_EFFECT_ROUTES: list[tuple[list[str], str]] = [
    (["POST"], "/v1/chat/completions"),
    (["POST"], "/memory/write"),
    (["POST"], "/memory/knowledge/ingest"),
    (["POST"], "/memory/graph/entity"),
    (["POST"], "/memory/graph/edge"),
    (["POST"], "/memory/graph/seed"),
    (["POST"], "/memory/knowledge/compile"),
    (["POST"], "/memory/sessions"),
    (["POST"], "/memory/sessions/:session_id/close"),
    (["POST"], "/memory/packets/:cid/seal"),
    (["POST"], "/agents/:pid/memory/import"),
    (["POST"], "/agents/:pid/memory/purge"),
    (["POST"], "/agents/:pid/memory/compact"),
    (["POST"], "/tools/mcp/register"),
    (["POST"], "/tools/mcp/invoke"),
    (["POST", "PUT"], "/memory/objects"),
    (["POST"], "/multiagent/pipeline"),
    (["POST"], "/multiagent/grant"),
    (["POST"], "/multiagent/revoke"),
    (["POST"], "/multiagent/pipelines/:pipeline_id/approve-step/:step"),
    (["POST"], "/memory/optimize-context/:agent_pid"),
    (["POST"], "/memory/consolidate/:agent_pid"),
    (["POST"], "/memory/tier/change"),
    (["POST"], "/assets/containers/:id/upload"),
    (["POST"], "/assets/ingest"),
    (["POST"], "/protocols/mcp/discover"),
    (["POST"], "/protocols/mcp/call"),
    (["POST"], "/protocols/mcp/handle"),
    (["POST"], "/experiments/:experiment_id/run"),
]

MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

ROUTE_TEMPLATE = {
    "component": "platform",
    "source_file": "platform/server/src/router.rs",
    "mount_hint": "/api/v1",
    "auth_required": True,
    "public": False,
    "tenant_scope": "required_when_multi_tenant",
    "permission": "rbac_path_derived",
    "admission_operation": "required",
    "audit_class": "effectful",
    "rate_limit": "platform_default",
    "notes": "substrate admission wired",
}


def load_inventory() -> dict:
    with INVENTORY.open(encoding="utf-8") as f:
        return json.load(f)


def save_inventory(doc: dict) -> None:
    with INVENTORY.open("w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def route_key(path: str, method: str) -> tuple[str, str]:
    return (path, method.upper())


def index_routes(routes: list[dict]) -> dict[tuple[str, str], dict]:
    out: dict[tuple[str, str], dict] = {}
    for r in routes:
        for m in r.get("methods", []):
            out[route_key(r["path"], m)] = r
    return out


def find_wired(index: dict[tuple[str, str], dict], methods: list[str], path: str) -> list[dict]:
    return [index[route_key(path, m)] for m in methods if route_key(path, m) in index]


def apply_fix(doc: dict) -> tuple[int, int]:
    routes: list[dict] = doc.setdefault("routes", [])
    index = index_routes(routes)
    patched = 0
    added = 0

    for methods, path in WIRED_EFFECT_ROUTES:
        found = find_wired(index, methods, path)
        if not found:
            for m in methods:
                entry = {**ROUTE_TEMPLATE, "path": path, "methods": [m]}
                routes.append(entry)
                index[route_key(path, m)] = entry
                added += 1
            continue
        for r in found:
            if r.get("admission_operation") != "required":
                r["admission_operation"] = "required"
                patched += 1
            if r.get("audit_class") != "effectful":
                r["audit_class"] = "effectful"
                patched += 1
            note = r.get("notes") or ""
            if "substrate admission wired" not in note:
                r["notes"] = (note + "; substrate admission wired").strip("; ").strip()

    doc["admission_wired_route_count"] = len(WIRED_EFFECT_ROUTES)
    return patched, added


def validate(doc: dict) -> list[str]:
    errors: list[str] = []
    index = index_routes(doc.get("routes", []))

    for methods, path in WIRED_EFFECT_ROUTES:
        found = find_wired(index, methods, path)
        if len(found) != len(methods):
            missing = [m for m in methods if route_key(path, m) not in index]
            errors.append(f"missing inventory route {path} methods={missing}")
            continue
        for r in found:
            if r.get("admission_operation") != "required":
                errors.append(
                    f"{path} {r.get('methods')}: admission_operation={r.get('admission_operation')!r}, want required"
                )
            if r.get("audit_class") != "effectful":
                errors.append(
                    f"{path} {r.get('methods')}: audit_class={r.get('audit_class')!r}, want effectful"
                )

    mutating_effectful = 0
    gated = 0
    for r in doc.get("routes", []):
        methods = set(r.get("methods", []))
        if not methods & MUTATING:
            continue
        if r.get("audit_class") != "effectful":
            continue
        mutating_effectful += 1
        if r.get("admission_operation") not in (None, "none_or_unknown"):
            gated += 1

    pct = (100.0 * gated / mutating_effectful) if mutating_effectful else 100.0
    print(
        f"effectful mutating routes: {gated}/{mutating_effectful} gated ({pct:.1f}%)"
    )
    print(f"wired effect routes declared: {len(WIRED_EFFECT_ROUTES)}")

    if pct < 85.0:
        errors.append(
            f"effectful mutating admission coverage {pct:.1f}% below 85% floor"
        )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Patch inventory entries for wired routes",
    )
    args = parser.parse_args()

    doc = load_inventory()
    if args.fix:
        patched, added = apply_fix(doc)
        save_inventory(doc)
        print(f"patched fields on {patched} entries, added {added} route entries")
        doc = load_inventory()

    errors = validate(doc)
    if errors:
        print("FAIL:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("OK: wired effect routes fully declared in route-security-inventory.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

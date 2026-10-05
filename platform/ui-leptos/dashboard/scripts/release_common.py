#!/usr/bin/env python3
"""Shared helpers for WASM UI release staging, manifest, and verification."""
from __future__ import annotations

import hashlib
import json
import mimetypes
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Roles used in asset-manifest.json
ROLE_DASHBOARD_HTML = "dashboard_html"
ROLE_DASHBOARD_JS = "dashboard_js"
ROLE_DASHBOARD_WASM = "dashboard_wasm"
ROLE_SPLIT_LOADER = "split_loader"
ROLE_SPLIT_CHUNK = "split_chunk"
ROLE_DASHBOARD_CSS = "dashboard_css"
ROLE_TRIAL_HTML = "trial_html"
ROLE_TRIAL_JS = "trial_js"
ROLE_TRIAL_WASM = "trial_wasm"
ROLE_TRIAL_CSS = "trial_css"
ROLE_SW = "service_worker"
ROLE_MANIFEST = "manifest"
ROLE_OTHER = "other"

IMMUTABLE_ROLES = {
    ROLE_DASHBOARD_CSS,
    ROLE_TRIAL_CSS,
}

SHELL_ROLES = {
    ROLE_DASHBOARD_HTML,
    ROLE_DASHBOARD_JS,
    ROLE_DASHBOARD_WASM,
    ROLE_TRIAL_HTML,
    ROLE_TRIAL_JS,
    ROLE_TRIAL_WASM,
    ROLE_SW,
    ROLE_MANIFEST,
}


@dataclass
class AssetEntry:
    path: str
    sha256: str
    size: int
    content_type: str
    cache: str
    role: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_hex(path.read_bytes())


def content_version(path: Path, n: int = 12) -> str:
    return sha256_file(path)[:n]


def guess_content_type(name: str) -> str:
    if name.endswith(".wasm"):
        return "application/wasm"
    if name.endswith(".js"):
        return "text/javascript; charset=utf-8"
    if name.endswith(".css"):
        return "text/css; charset=utf-8"
    if name.endswith(".html"):
        return "text/html; charset=utf-8"
    if name.endswith(".json"):
        return "application/json"
    if name.endswith(".svg"):
        return "image/svg+xml"
    guessed, _ = mimetypes.guess_type(name)
    return guessed or "application/octet-stream"


def cache_policy(role: str) -> str:
    if role in SHELL_ROLES:
        return "no-cache, no-store, must-revalidate"
    if role in IMMUTABLE_ROLES or role == ROLE_OTHER and (
        "chunk_" in role or "split_" in role
    ):
        return "public, max-age=31536000, immutable"
    if role in IMMUTABLE_ROLES:
        return "public, max-age=31536000, immutable"
    # chunk/split wasm by filename
    return "public, max-age=31536000, immutable"


def classify_asset(rel: str) -> str:
    name = Path(rel).name
    if rel == "index.html":
        return ROLE_DASHBOARD_HTML
    if rel == "trial-app/index.html":
        return ROLE_TRIAL_HTML
    if name == "connector-ui.js":
        return ROLE_DASHBOARD_JS
    if name in ("connector-ui.wasm", "connector-ui_bg.wasm"):
        return ROLE_DASHBOARD_WASM
    if name.startswith("__wasm_split") and name.endswith(".js"):
        return ROLE_SPLIT_LOADER
    if name.startswith("chunk_") and name.endswith(".wasm"):
        return ROLE_SPLIT_CHUNK
    if name.startswith("split_") and name.endswith(".wasm"):
        return ROLE_SPLIT_CHUNK
    if name == "tailwind.out.css":
        return ROLE_DASHBOARD_CSS
    if name == "trial-tailwind.css":
        return ROLE_TRIAL_CSS
    if name == "connector-trial.js":
        return ROLE_TRIAL_JS
    if name == "connector-trial_bg.wasm":
        return ROLE_TRIAL_WASM
    if rel.startswith("trial-app/") and name == "tailwind.out.css":
        return ROLE_TRIAL_CSS
    if name == "sw.js":
        return ROLE_SW
    if name == "asset-manifest.json":
        return ROLE_MANIFEST
    return ROLE_OTHER


def classify_cache(rel: str, role: str) -> str:
    name = Path(rel).name
    if role in SHELL_ROLES:
        return "no-cache, no-store, must-revalidate"
    if name.startswith("chunk_") or name.startswith("split_"):
        # These filenames are stable across builds but their table layout is
        # tied to the main `connector-ui.wasm`. Never let browsers reuse a
        # chunk from a previous release with a new main module.
        return "no-cache, no-store, must-revalidate"
    if name.startswith("__wasm_split"):
        return "no-cache, no-store, must-revalidate"
    if role in (ROLE_DASHBOARD_CSS, ROLE_TRIAL_CSS):
        return "no-cache, no-store, must-revalidate"
    if role in SHELL_ROLES:
        return "no-cache, no-store, must-revalidate"
    return "public, max-age=3600"


def scan_release(release_dir: Path) -> list[AssetEntry]:
    entries: list[AssetEntry] = []
    skip_suffixes = {".gz", ".d.ts"}
    for path in sorted(release_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix in skip_suffixes or path.name.endswith(".wasm.d.ts"):
            continue
        if path.name == "asset-manifest.json":
            continue
        rel = path.relative_to(release_dir).as_posix()
        if rel.startswith("pkg/"):
            continue
        data = path.read_bytes()
        role = classify_asset(rel)
        entries.append(
            AssetEntry(
                path=f"/{rel}" if not rel.startswith("/") else rel,
                sha256=sha256_hex(data),
                size=len(data),
                content_type=guess_content_type(path.name),
                cache=classify_cache(rel, role),
                role=role,
            )
        )
    return entries


def write_manifest(release_dir: Path, build_id: str, entries: list[AssetEntry]) -> Path:
    manifest_path = release_dir / "asset-manifest.json"
    by_role: dict[str, list[str]] = {}
    by_path: dict[str, dict[str, Any]] = {}
    for e in entries:
        by_path[e.path] = e.to_dict()
        by_role.setdefault(e.role, []).append(e.path)

    payload = {
        "build_id": build_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "release_root": f"/releases/{build_id}",
        "build_version": next(
            (e.sha256[:12] for e in entries if e.role == ROLE_DASHBOARD_WASM and e.path.endswith("connector-ui.wasm")),
            build_id[:12],
        ),
        "assets": by_path,
        "roles": by_role,
    }
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n")
    return manifest_path


def load_manifest(release_dir: Path) -> dict[str, Any]:
    path = release_dir / "asset-manifest.json"
    if not path.exists():
        raise FileNotFoundError(f"missing manifest: {path}")
    return json.loads(path.read_text())


SPLIT_IMPORT_RE = re.compile(r'from["\'](\./__wasm_split[^"\']*)["\']')
SPLIT_KEY_RE = re.compile(r'["\'](\./__wasm_split[^"\']*)["\']\s*:')
FUNC_ELEM_RE = re.compile(r"e\.(__wasm_bindgen_func_elem_\w+)")


def verify_release(release_dir: Path) -> list[str]:
    """Return list of errors; empty means OK."""
    errors: list[str] = []

    manifest_path = release_dir / "asset-manifest.json"
    dash_html = release_dir / "index.html"
    trial_html = release_dir / "trial-app" / "index.html"
    ui_js = release_dir / "connector-ui.js"
    ui_wasm = release_dir / "connector-ui.wasm"

    if not manifest_path.exists():
        errors.append("missing asset-manifest.json")
    if not dash_html.exists():
        errors.append("missing index.html (dashboard)")
    if not trial_html.exists():
        errors.append("missing trial-app/index.html")
    if not ui_js.exists():
        errors.append("missing connector-ui.js")
    if not ui_wasm.exists():
        errors.append("missing connector-ui.wasm")

    trial_js = release_dir / "trial-app" / "connector-trial.js"
    trial_wasm = release_dir / "trial-app" / "connector-trial_bg.wasm"
    if not trial_js.exists():
        errors.append("missing trial-app/connector-trial.js")
    if not trial_wasm.exists():
        errors.append("missing trial-app/connector-trial_bg.wasm")

    if dash_html.exists():
        html = dash_html.read_text()
        if "bindings.hydrate" in html:
            errors.append("dashboard index.html must not call bindings.hydrate()")
        if "connector-trial" in html and "connector-ui" not in html:
            pass
        elif "connector-ui.js" not in html:
            errors.append("dashboard index.html does not reference connector-ui.js")

    if trial_html.exists():
        th = trial_html.read_text()
        if "connector-ui.js" in th:
            errors.append("trial-app/index.html must not reference connector-ui.js")
        if "connector-trial.js" not in th:
            errors.append("trial-app/index.html must reference connector-trial.js")

    split_loaders = list(release_dir.glob("__wasm_split*.js"))
    if not split_loaders:
        errors.append("missing __wasm_split*.js loader")

    if ui_js.exists() and ui_wasm.exists():
        js_text = ui_js.read_text()
        for key in SPLIT_KEY_RE.findall(js_text):
            if "?" in key:
                errors.append(f"connector-ui.js import-object key must be unversioned: {key}")
        # Referenced split chunks exist
        for m in re.finditer(r'["\'](\./(?:chunk_\d+|split_[^"\']+)\.wasm)(?:\?[^"\']*)?["\']', js_text):
            chunk = release_dir / m.group(1)[2:]
            if not chunk.exists():
                errors.append(f"connector-ui.js references missing chunk: {chunk.name}")
        build_v_for_chunks = load_manifest(release_dir).get("build_version") if manifest_path.exists() else None
        for split in split_loaders:
            split_text = split.read_text()
            for m in re.finditer(r'["\'](\./(?:chunk_\d+|split_[^"\']+)\.wasm)(?:\?[^"\']*)?["\']', split_text):
                chunk = release_dir / m.group(1)[2:]
                if not chunk.exists():
                    errors.append(f"split loader references missing chunk: {chunk.name}")
            if build_v_for_chunks:
                for m in re.finditer(r'new URL\(["\'](\./(?:chunk_\d+|split_[^"\']+)\.wasm)(?:\?v=([^"\']+))?["\']', split_text):
                    if m.group(2) != build_v_for_chunks:
                        errors.append(f"split loader chunk URL missing build version: {m.group(1)}")

    if manifest_path.exists() and dash_html.exists():
        manifest = load_manifest(release_dir)
        build_v = manifest.get("build_version")
        html = dash_html.read_text()
        js_m = re.search(r"/connector-ui\.js\?v=([a-f0-9]+)", html)
        wasm_m = re.search(r"/connector-ui\.wasm\?v=([a-f0-9]+)", html)
        if build_v:
            if js_m and js_m.group(1) != build_v:
                errors.append(f"HTML js v={js_m.group(1)} != manifest build_version={build_v}")
            if wasm_m and wasm_m.group(1) != build_v:
                errors.append(f"HTML wasm v={wasm_m.group(1)} != manifest build_version={build_v}")
            if js_m and wasm_m and js_m.group(1) != wasm_m.group(1):
                errors.append("HTML js and wasm version mismatch")

    return errors

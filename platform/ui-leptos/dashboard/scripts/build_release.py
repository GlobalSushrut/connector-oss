#!/usr/bin/env python3
"""
Stage a manifest-backed playground UI release.

Layout:
  dist/playground/releases/<build_id>/
    index.html, connector-ui.*, chunks, trial-app/, asset-manifest.json
  dist/playground/current -> releases/<build_id>   (symlink)
  dist/playground/          flat copy of current release for Docker/legacy paths
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from release_common import (  # noqa: E402
    ROLE_DASHBOARD_WASM,
    content_version,
    scan_release,
    verify_release,
    write_manifest,
)

ROOT = SCRIPT_DIR.parent
WS = ROOT.parent
TRIAL = WS / "trial"


def run(cmd: list[str], *, cwd: Path | None = None, env: dict | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd or ROOT, env=env, check=True)


def build_dashboard_stage(stage: Path, profile: str) -> None:
    """Run cargo-leptos and populate stage/ with patched dashboard assets."""
    run(["bash", str(SCRIPT_DIR / "build-leptos-core.sh"), profile, str(stage)])


def build_trial_stage(stage: Path) -> Path:
    """Build trial into stage/trial-app/ and copy root trial assets."""
    trial_app = stage / "trial-app"
    trial_app.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.pop("NO_COLOR", None)
    env["TRUNK_CONFIG"] = "Trunk.toml"
    run(
        ["trunk", "build", "--release", "--filehash", "false", "index.html"],
        cwd=TRIAL,
        env=env,
    )

    trial_dist = TRIAL / "dist"
    trial_stage = trial_dist / ".stage" if (trial_dist / ".stage").exists() else trial_dist

    # Patch trial index in place before copy
    trial_index = trial_stage / "index.html"
    if not trial_index.exists():
        raise SystemExit(f"trial build missing {trial_index}")

    run(
        [
            sys.executable,
            str(SCRIPT_DIR / "patch_wasm_init.py"),
            str(trial_index),
            "playground",
        ]
    )

    for item in trial_stage.iterdir():
        if item.name == ".stage":
            continue
        dest = trial_app / item.name
        if item.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)

    # Root-level trial assets for router fallback paths
    for pattern in ("connector-trial*.js", "connector-trial*_bg.wasm"):
        for f in trial_app.glob(pattern):
            shutil.copy2(f, stage / f.name)

    if (trial_app / "tailwind.out.css").exists():
        shutil.copy2(trial_app / "tailwind.out.css", stage / "trial-tailwind.css")

    return trial_app


def promote_release(release_dir: Path, playground_out: Path) -> None:
    """Symlink current + rsync flat copy for Docker."""
    current_link = playground_out / "current"
    if current_link.is_symlink() or current_link.exists():
        current_link.unlink()
    current_link.symlink_to(release_dir.relative_to(playground_out), target_is_directory=True)

    # Flat deploy tree (what Dockerfile COPY expects)
    for item in playground_out.iterdir():
        if item.name in ("releases", "current", "asset-manifest.json", "RELEASE_ID"):
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()

    for item in release_dir.iterdir():
        dest = playground_out / item.name
        if item.is_dir():
            shutil.copytree(item, dest, symlinks=True)
        else:
            shutil.copy2(item, dest)

    shutil.copy2(release_dir / "asset-manifest.json", playground_out / "asset-manifest.json")
    (playground_out / "RELEASE_ID").write_text(release_dir.name + "\n")

    # Keep last 5 release archives; in-flight browsers may still reference older graphs.
    releases_root = playground_out / "releases"
    if releases_root.is_dir():
        archived = sorted(
            (p for p in releases_root.iterdir() if p.is_dir()),
            key=lambda p: p.name,
            reverse=True,
        )
        for old in archived[5:]:
            shutil.rmtree(old, ignore_errors=True)

    sync_embed_dist(release_dir)


def sync_embed_dist(release_dir: Path) -> None:
    """Copy flat release tree to dashboard/dist for server build.rs embed (preserves dist/playground/)."""
    embed = ROOT / "dist"
    embed.mkdir(parents=True, exist_ok=True)
    preserve = {"playground"}
    for item in embed.iterdir():
        if item.name in preserve:
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    for item in release_dir.iterdir():
        dest = embed / item.name
        if item.is_dir() and not item.is_symlink():
            shutil.copytree(item, dest, symlinks=False)
        elif item.is_file():
            shutil.copy2(item, dest)
    shutil.copy2(release_dir / "asset-manifest.json", embed / "asset-manifest.json")
    (embed / "RELEASE_ID").write_text(release_dir.name + "\n")
    print(f"==> embed dist synced → {embed}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build manifest-backed playground UI release")
    parser.add_argument("--profile", default="playground")
    parser.add_argument("--build-id", default=None, help="Override release id (default: UTC timestamp + wasm hash prefix)")
    parser.add_argument("--skip-verify", action="store_true")
    args = parser.parse_args()

    if args.profile != "playground":
        print("build_release.py currently supports playground profile only", file=sys.stderr)
        return 1

    playground_out = ROOT / "dist" / "playground"
    releases_root = playground_out / "releases"
    releases_root.mkdir(parents=True, exist_ok=True)

    tmp = playground_out / ".release-staging"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)

    print("==> dashboard")
    build_dashboard_stage(tmp, args.profile)

    print("==> trial-app")
    build_trial_stage(tmp)

    build_v = content_version(tmp / "connector-ui.wasm")
    build_id = args.build_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{build_v}"

    sw_path = tmp / "sw.js"
    if sw_path.exists():
        sw_path.write_text(
            sw_path.read_text().replace("__RELEASE_ID__", f"connector-release-{build_id}")
        )
        subprocess.run(["gzip", "-9", "-f", "-k", str(sw_path)], check=False)

    release_meta = f'<meta name="connector-release" content="{build_id}" />'
    for html_name in ("index.html", "trial-app/index.html"):
        html_path = tmp / html_name
        if html_path.exists():
            text = html_path.read_text()
            if 'name="connector-release"' not in text:
                html_path.write_text(text.replace("<head>", f"<head>\n  {release_meta}", 1))

    entries = scan_release(tmp)
    manifest = write_manifest(tmp, build_id, entries)
    print(f"==> manifest {manifest} build_id={build_id} build_version={build_v}")

    errors = verify_release(tmp)
    if errors:
        print("VERIFY FAILED (staging):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        if not args.skip_verify:
            shutil.rmtree(tmp)
            return 1

    release_dir = releases_root / build_id
    if release_dir.exists():
        shutil.rmtree(release_dir)
    shutil.move(str(tmp), str(release_dir))

    promote_release(release_dir, playground_out)

    errors = verify_release(release_dir)
    if errors and not args.skip_verify:
        print("VERIFY FAILED (release):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"==> release ready: {release_dir}")
    print(f"==> flat tree: {playground_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

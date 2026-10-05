#!/usr/bin/env python3
"""Fail-closed pre-deploy verifier for a UI release directory."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from release_common import load_manifest, verify_release  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify WASM UI release integrity")
    parser.add_argument(
        "release_dir",
        nargs="?",
        default=None,
        help="Release directory (default: dist/playground or dist/playground/current)",
    )
    args = parser.parse_args()

    root = SCRIPT_DIR.parent
    if args.release_dir:
        release_dir = Path(args.release_dir)
    else:
        current = root / "dist" / "playground" / "current"
        playground = root / "dist" / "playground"
        if current.is_symlink() and current.resolve().is_dir():
            release_dir = current.resolve()
        elif (playground / "asset-manifest.json").exists():
            release_dir = playground
        else:
            print("ERROR: no release dir specified and no dist/playground/current found", file=sys.stderr)
            return 1

    if not release_dir.is_dir():
        print(f"ERROR: not a directory: {release_dir}", file=sys.stderr)
        return 1

    errors = verify_release(release_dir)
    if errors:
        print(f"VERIFY FAILED: {release_dir}", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    try:
        manifest = load_manifest(release_dir)
        print(f"OK: {release_dir}")
        print(f"  build_id={manifest.get('build_id')}")
        print(f"  build_version={manifest.get('build_version')}")
        print(f"  assets={len(manifest.get('assets', {}))}")
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

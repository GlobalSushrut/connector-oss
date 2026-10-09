#!/usr/bin/env python3
"""Cross-language ToolSpec digest conformance (Python ↔ TypeScript algorithm)."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "platform/sdk/python"))

from connector_sdk.gloo.authoring import EffectRow, Tool  # noqa: E402


def main() -> int:
    tool = Tool(
        "search",
        "search",
        EffectRow("tool.search", mutates=False),
        input_schema={"q": "string"},
    )
    spec = tool.to_spec()
    body = {k: v for k, v in spec.items() if k != "digest"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    expected = f"spec-sha256-{hashlib.sha256(canonical.encode()).hexdigest()}"
    assert spec["digest"] == expected, (spec["digest"], expected)
    # Golden pinned for TS mirror
    assert (
        expected
        == "spec-sha256-9ee3f2bdc6d650eaf4c1efa6664652e72c849abd5a3254b01bdc9611655c24b7"
    )
    print(json.dumps({"ok": True, "digest": expected, "schema": body["schema"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

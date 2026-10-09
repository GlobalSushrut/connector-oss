#!/usr/bin/env python3
"""Blank PDF CreationDate/ModDate metadata in-place (preserves file size and xref offsets)."""
from __future__ import annotations

import re
import sys
from pathlib import Path


def blank_date_field(data: bytearray, field: bytes) -> None:
    pattern = re.compile(re.escape(field) + rb" \(D:[^)]*\)")
    match = pattern.search(data)
    if not match:
        # Already blanked or alternate format — try generic parenthesized value.
        pattern = re.compile(re.escape(field) + rb" \([^)]*\)")
        match = pattern.search(data)
    if not match:
        raise SystemExit(f"Could not find {field.decode()} in PDF metadata")

    old = match.group(0)
    inner = b" " * (len(old) - len(field) - 3)
    new = field + b" (" + inner + b")"
    if len(new) != len(old):
        raise SystemExit(f"Length mismatch for {field.decode()}: {len(old)} vs {len(new)}")
    data[match.start() : match.end()] = new


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {sys.argv[0]} <file.pdf>")

    path = Path(sys.argv[1])
    data = bytearray(path.read_bytes())
    blank_date_field(data, b"/CreationDate")
    blank_date_field(data, b"/ModDate")
    path.write_bytes(data)


if __name__ == "__main__":
    main()

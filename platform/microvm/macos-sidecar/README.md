connector-microvm-macos sidecar (Phase 5.3.6)

This binary wraps Apple Virtualization.framework and exposes a minimal JSON contract:

- input: `connector-microvm-macos --json '<payload>'`
- output: JSON receipt with `ok`, `vm_id`, and runtime metadata.

Build (on macOS):

```bash
swiftc -O main.swift -o connector-microvm-macos
```

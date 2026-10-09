# DevGuard

DevGuard is the governance and enforcement plugin for coding agents.

## Git Hook Requirements

- `devguard cage start` installs git hooks that invoke the `devguard` binary.
- For default installs, `devguard` must be available on your `PATH`.
- If you need a pinned binary location, use:
  - `devguard cage start --config devguard.yaml --path /absolute/path/to/devguard`
- You can verify installed hook resolution any time with:
  - `devguard cage status`
- You can run active enforcement probes with:
  - `devguard cage status --verify`

If the hook binary does not resolve, hooks will log a warning and run in pass-through mode.

## Cage Process Hardening

- In cage mode, `devguard connect` now attempts Linux process-level exec hardening via `LD_PRELOAD`.
- It builds `.devguard/libdevguard_exec_guard.so` and exports:
  - `LD_PRELOAD`
  - `DEVGUARD_ENFORCE_EXEC=1`
  - `DEVGUARD_CONFIG`
  - `DEVGUARD_BIN`
- If a C compiler is unavailable, DevGuard falls back safely and prints a warning in connect output.

## Live 24x7 Wizard Monitoring

- `devguard start` launches:
  - governed session
  - detached live dashboard window
  - extension status API (`http://127.0.0.1:7788/devguard/status`)
  - background monitor daemon with heartbeat (`.devguard/live_state.json`)
- Use `devguard status` anytime to verify if DevGuard is actively working.
- The dashboard includes a "Live Monitor" section with:
  - working state
  - last action
  - blocked action count
  - pending approvals
  - heartbeat timestamp

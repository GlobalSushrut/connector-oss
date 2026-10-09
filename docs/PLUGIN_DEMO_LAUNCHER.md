# Plugin Demo Launcher

Use `scripts/demo-plugin-launcher.py` while presenting `https://try.cnktros.com`.

## What It Does

- Prompts for the hosted website address, current trial API key, tenant id,
  actor id, and demo role.
- Lets you choose `tracetramp`, `witnessctl`, or `devguard`.
- Runs real hosted-trial API calls for TraceTramp and WitnessCtl.
- Creates a DevGuard governed session and writes Windsurf-ready config files.

## Quick Start

From the repo root:

```bash
make plugin-demo
```

When prompted:

1. Enter the hosted website address, usually `https://try.cnktros.com`.
2. Paste the current API key from `/trial`.
3. Leave tenant id blank unless you want to override it; the launcher
   auto-discovers the playground tenant from the key.

The trial key changes every 90 minutes, so the normal interactive command asks
for it every run. Use `--api-key` only for scripted rehearsals.

## Rehearse Without Mutations

```bash
python3 scripts/demo-plugin-launcher.py --dry-run
```

## Direct Commands

TraceTramp simulation:

```bash
make tracetramp
```

WitnessCtl evidence simulation:

```bash
make witnessctl
```

DevGuard + Windsurf setup:

```bash
make devguard
```

Dry-run shortcuts:

```bash
make tracetramp-dry
make witnessctl-dry
make devguard-dry
```

The DevGuard path writes:

- `.windsurf/connector-devguard.yaml`
- `.windsurf/DEVGUARD_JUNIOR_ENGINEER_PROMPT.md`
- `.connector-demo-devguard.env`

Existing files are backed up with `.bak-<timestamp>`.

## Dashboard URLs

- TraceTramp: `https://try.cnktros.com/plugins/tracetramp`
- WitnessCtl: `https://try.cnktros.com/plugins/witnessctl`
- DevGuard: `https://try.cnktros.com/plugins/devguard`

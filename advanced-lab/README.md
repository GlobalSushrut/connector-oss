# Advanced lab

**Authoritative plan:** [`docs/LAB_FINAL_PLAN.md`](docs/LAB_FINAL_PLAN.md) — the lab is built for **(1) real action simulation**, **(2) real attack simulation** on lab endpoints only, and **(3) capturing how the system responds** (HTTP, TraceTramp **`action_trace_cumulative`**, WitnessCtl). **DeepSeek** is **required** (no mock upstream). **[OpenFang](https://github.com/RightNow-AI/openfang)** is the **Rust** AIOS upstream ([Getting started](https://openfang.sh/docs/getting-started)); point its OpenAI **base URL** at **TraceTramp**. Compose service **`openfang`** = **Python lab runner** (`agents/`) — see plan §3. **WitnessCtl** for evidence — not OpenFaaS.

The old shell demos under `advanced-lab/scripts/` were removed; new automation will follow the final plan (runner + scenario manifests).

What remains for now:

- `lab/advanced.yml` — optional Compose overlay (use with `lab/docker-compose.premium-lab.yml`; see `lab/README.md`)
- `.env.example` — environment template
- `agents/`, `openfang/`, `runner/` — OpenFang-aligned lab services and smoke runner (`lab-llm/` exists in-tree but is **not** part of the default Compose overlay — DeepSeek only)
- `migrations/001_labdb.sql` — lab DB bootstrap
- `docs/` — planning notes (see below)

## Stack hint (manual)

Until new automation exists, you can still bring up services by composing TraceTramp’s stack with this overlay from the repo root (adjust ports/env to match your setup):

```bash
cp advanced-lab/.env.example advanced-lab/.env
# edit keys / ports
docker compose \
  -f lab/docker-compose.premium-lab.yml \
  -f lab/advanced.yml \
  up -d --build
```

Tear down:

```bash
docker compose \
  -f lab/docker-compose.premium-lab.yml \
  -f lab/advanced.yml \
  down -v
```

### Operator HTTP (TraceTramp + WitnessCtl, host ports)

Terminal TUIs were removed from both binaries. Use the **management / data HTTP APIs** (or `advanced-lab/scripts/open-lab-tuis.sh print-env` for default URLs and bearer tokens matching the Compose lab).

```bash
chmod +x advanced-lab/scripts/open-lab-tuis.sh
advanced-lab/scripts/open-lab-tuis.sh traffic   # YAML actions+attacks via Docker lab-runner
advanced-lab/scripts/open-lab-tuis.sh print-env # echo exports for curl / scripts
```

## Lab scenario runner (YAML → reports)

Scenario files live in [`scenarios/actions/`](scenarios/actions/) and [`scenarios/attacks/`](scenarios/attacks/). JSON shape is described in [`schemas/lab-run-report.schema.json`](schemas/lab-run-report.schema.json) (plan §5.5).

**Host** (from `advanced-lab/runner`, with TraceTramp + Witness up and `DEEPSEEK_API_KEY` set):

```bash
pip install -r requirements.txt
export TRACETRAMP_DATA_URL=http://127.0.0.1:19741 TRACETRAMP_ADMIN_URL=http://127.0.0.1:19742
export SCENARIOS_DIR=../scenarios OUTPUT_DIR=../outputs/lab-runs
python -m lab_runner.preflight --probe-chat
python -m lab_runner.lab_run --only all --output-dir ../outputs/lab-runs
```

**Docker** (profile `lab` — writes under `advanced-lab/outputs/lab-runs/`):

```bash
export COMPOSE_PROFILES=lab
export DEEPSEEK_API_KEY=sk-...
docker compose \
  -f lab/docker-compose.premium-lab.yml \
  -f lab/advanced.yml \
  run --rm lab-runner
```

**Witness smoke** (optional, same image):  
`docker compose ... run --rm lab-runner python -m lab_runner.smoke`

Set `LAB_RUN_STRICT_DEFENCE=1` on the lab-runner service if you want a non-zero exit unless at least one attack run ends in block/redact/hitl/throttle (tighten TraceTramp policy beyond audit-only first).

**After changing `DEEPSEEK_API_KEY` in `advanced-lab/.env`**, TraceTramp keeps the old value until recreated (upstream is read from container env, not the admin provider row). Run:

`docker compose --env-file advanced-lab/.env -f lab/docker-compose.premium-lab.yml -f lab/advanced.yml up -d --force-recreate tracetramp`

# Lab-only Docker overlays

Production Connector OS uses the in-tree supervisor + microVM path (`CONNECTOR_OS_ROADMAP.md`).  
**Docker here is optional** — for local premium-lab demos and CI-shaped smoke only.

## TraceTramp + advanced lab (DeepSeek / WitnessCtl / OpenFang runner)

From repo root (or use **`scripts/lab_up.sh`** which loads `advanced-lab/.env`):

```bash
cp advanced-lab/.env.example advanced-lab/.env   # once; set DEEPSEEK_API_KEY
./scripts/lab_up.sh up -d --build
```

Equivalent manual invocation:

```bash
export DEEPSEEK_API_KEY=sk-...
docker compose \
  --env-file advanced-lab/.env \
  -f lab/docker-compose.premium-lab.yml \
  -f lab/advanced.yml \
  up -d --build
```

The overlay file lives at `lab/advanced.yml` (moved from `advanced-lab/docker-compose.extend.yml`).

## Dockerfiles (lab-only builds)

Phase **0.7.2** moved all container build recipes here; plugin and `oss/` trees no longer ship `Dockerfile`s.

| File | Build context (Compose) | Image / service |
|------|-------------------------|-----------------|
| `lab/Dockerfile.connector` | `oss/` | Connector OSS (`connector` service) |
| `lab/Dockerfile.tracetramp` | `plugins/tracetramp/` | TraceTramp |
| `lab/Dockerfile.witnessctl` | `plugins/witnessctl/` | WitnessCtl |
| `lab/Dockerfile.agents` | `advanced-lab/agents/` | OpenFang lab HTTP runner (`openfang`) |
| `lab/Dockerfile.lab-runner` | `advanced-lab/` | YAML lab-runner (`lab-runner`, profile `lab`) |

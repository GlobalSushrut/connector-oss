#!/usr/bin/env bash
# Reclaim disk from safe, reproducible artifacts (repo + optional Docker).
# Does NOT remove platform/server/.cargo-target unless CLEAN_CARGO_TARGET=1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== clean-workspace (repo: $ROOT) =="
echo "Tip: on 16 GiB RAM machines use .cargo/config.toml jobs=4; never run ci-beta-gate + docker build + full cargo build at once."
echo "Before: $(df -h / | awk 'NR==2 {print $3 " used, " $4 " free (" $5 ")"}')"

# Duplicate / stale Rust out-dirs (regenerate with cargo / make platform-build)
for rel in \
  platform/server/target \
  platform/plugin-runtime/target \
  platform/cpkg/target \
  platform/microvm/target \
  platform/connector-vm-agent/target \
  platform/hub/target \
  platform/supervisor/target \
  platform/plugin-handshake/target \
  platform/plugin-manifest/target \
  platform/ui-leptos/dashboard/target \
  oss/connector/target \
  plugins/tracetramp/target \
  plugins/witnessctl/target \
  plugins/devguard/target \
  plugins/agentpassport/target; do
  if [[ -d "$ROOT/$rel" ]]; then
    sz=$(du -sh "$ROOT/$rel" | cut -f1)
    rm -rf "$ROOT/$rel"
    echo "  removed $rel ($sz)"
  fi
done

# Connector smoke temp dirs
rm -rf /tmp/connector_one_green.* /tmp/connector_prod_dogfood.* \
  /tmp/connector_upgrade.* /tmp/connector_tarball_install.* \
  /tmp/connector_tarball_smoke.* /tmp/connector-os-pack.* 2>/dev/null || true

if [[ "${CLEAN_CARGO_TARGET:-}" == "1" ]] && [[ -d "$ROOT/platform/server/.cargo-target" ]]; then
  sz=$(du -sh "$ROOT/platform/server/.cargo-target" | cut -f1)
  rm -rf "$ROOT/platform/server/.cargo-target"
  echo "  removed platform/server/.cargo-target ($sz)"
fi

if [[ "${CLEAN_DOCKER:-}" == "1" ]]; then
  echo "  docker builder prune -af …"
  docker builder prune -af >/dev/null 2>&1 || true
  echo "  docker image prune -f (dangling) …"
  docker image prune -f >/dev/null 2>&1 || true
fi

if [[ "${CLEAN_DOCKER_IMAGES:-}" == "1" ]]; then
  echo "  docker image prune -a (unused images) …"
  docker image prune -af >/dev/null 2>&1 || true
fi

echo "After:  $(df -h / | awk 'NR==2 {print $3 " used, " $4 " free (" $5 ")"}')"
echo "== clean-workspace: done =="

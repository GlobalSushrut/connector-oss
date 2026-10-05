#!/usr/bin/env bash
# Checklist §10.2 — packet-level "no silent bypass": lab procedure (nft/eBPF + connector-kerneld).
# This script does not mutate production hosts; it prints the verification contract.
set -euo pipefail

cat <<'EOF'
§10.2 — No silent bypass (lab)

Goal: traffic from the agent cgroup to a destination NOT in the allowlist must fail at the
kernel (nftables cgroup match or eBPF cgroup_sock_connect), not only at the HTTP proxy.

Suggested lab steps (root-capable worker or VM):

  1. Apply an egress allowlist nft set + cgroup-attached rule (see CONNECTOR_KERNEL_RUNBOOK.md).
  2. Run the agent workload inside the target cgroup (same as connector-kerneld attach path).
  3. From that cgroup, attempt: curl -m3 --connect-to BLOCKED:443:93.184.216.34 https://BLOCKED/
     (replace with an IP you intend to block; expect timeout or connection refused from kernel).
  4. Confirm platform counters (when wired): denied_connect_total increases, or nft counter on
     the drop rule increments.

Env helpers (optional, when platform is up):

  CONNECTOR_TEST_URL + CONNECTOR_TEST_API_KEY — same as connector-kernel-e2e-smoke.sh
  CONNECTOR_BYPASS_TEST_IP — IP to probe from the lab host (script does not curl by default).

EOF

if [[ -n "${CONNECTOR_BYPASS_TEST_IP:-}" ]]; then
  echo "[lab] curl probe to ${CONNECTOR_BYPASS_TEST_IP}:443 (3s timeout) — run from INSIDE the enforced cgroup for a valid test."
  curl -m3 -v "https://${CONNECTOR_BYPASS_TEST_IP}/" || true
fi

echo "[ok] bypass-lab instructions emitted."

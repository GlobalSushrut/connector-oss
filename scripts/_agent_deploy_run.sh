#!/usr/bin/env bash
set -euo pipefail
export FLY_ACCESS_TOKEN
FLY_ACCESS_TOKEN=$(python3 - <<'PY'
import re
text=open('/home/umesh/.fly/config.yml').read()
m=re.search(r'access_token:\s*["\']?([^\s"\']+)', text)
print(m.group(1) if m else '')
PY
)
export RUSTUP_HOME=/home/umesh/.rustup CARGO_HOME=/home/umesh/.cargo
export PATH="/home/umesh/.cargo/bin:/home/umesh/.fly/bin:/usr/local/bin:$PATH"
unset NO_COLOR || true
cd /home/umesh/Projects/connector-private
START=$(date +%s)
env -u NO_COLOR ./scripts/build-and-deploy.sh
END=$(date +%s)
echo "DEPLOY_TOTAL_SECONDS=$((END-START))"
echo "DEPLOY_FINISHED_AT=$(date -Iseconds)"

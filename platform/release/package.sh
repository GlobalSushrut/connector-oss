#!/usr/bin/env bash
# DEPRECATED — use scripts/package-connector-os.sh (make package).
# This wrapper exists so old docs/CI that call platform/release/package.sh still work.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
echo "package.sh: deprecated — forwarding to scripts/package-connector-os.sh" >&2
exec bash "$REPO_ROOT/scripts/package-connector-os.sh" "$@"

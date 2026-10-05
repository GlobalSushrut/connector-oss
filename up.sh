#!/usr/bin/env bash
# One command from the repository root. The implementation lives in oss/up.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$ROOT/oss/up.sh"

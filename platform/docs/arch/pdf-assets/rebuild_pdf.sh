#!/usr/bin/env bash
# Rebuild Connector_OS_Full_Architecture.pdf from the booklet HTML.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HTML="$ROOT/pdf-assets/connector-os-architecture-booklet.html"
PDF="$ROOT/Connector_OS_Full_Architecture.pdf"
UD="${TMPDIR:-/tmp}/chrome-pdf-profile-$$"
mkdir -p "$UD"
google-chrome --headless=new --no-sandbox --disable-gpu \
  --user-data-dir="$UD" \
  --no-pdf-header-footer \
  --print-to-pdf="$PDF" \
  "file://$HTML"
echo "Wrote $PDF ($(wc -c < "$PDF") bytes)"

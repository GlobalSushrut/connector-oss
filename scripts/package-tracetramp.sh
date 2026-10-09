#!/usr/bin/env bash
# Package TraceTramp release tarball (plan Phase 4).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN="$ROOT/plugins/tracetramp"
MANIFEST="$PLUGIN/Cargo.toml"
OUT_DIR="${CONNECTOR_PACKAGE_DIR:-$ROOT/dist}"
CARGO_TARGET="${CARGO_TARGET_DIR:-$PLUGIN/target}"

VERSION="$(cd "$PLUGIN" && cargo metadata --format-version 1 --no-deps --manifest-path "$MANIFEST" 2>/dev/null \
  | python3 -c "import json,sys; print(next(p['version'] for p in json.load(sys.stdin)['packages'] if p['name']=='tracetramp'))")"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64) ARCH_TAG=x86_64-linux ;;
  aarch64|arm64) ARCH_TAG=aarch64-linux ;;
  *) ARCH_TAG="${ARCH_RAW}-linux" ;;
esac

TAR_NAME="tracetramp-${VERSION}-${ARCH_TAG}.tar.gz"
OUT_PATH="$OUT_DIR/$TAR_NAME"
BIN="$CARGO_TARGET/release/tracetramp"

if [[ "${CONNECTOR_PACKAGE_NO_BUILD:-}" != "1" ]]; then
  echo "package-tracetramp: cargo build --release …"
  (cd "$PLUGIN" && CARGO_TARGET_DIR="$CARGO_TARGET" cargo build --release --bin tracetramp)
fi

[[ -x "$BIN" ]] || { echo "missing $BIN" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/bin" "$STAGE/share/migrations" "$STAGE/share/admin-ui" "$STAGE/config"
install -m755 "$BIN" "$STAGE/bin/tracetramp"
cp -a "$PLUGIN/migrations/." "$STAGE/share/migrations/"
cp "$PLUGIN/admin-ui/dashboard.html" "$STAGE/share/admin-ui/"
cp "$PLUGIN/.env.example" "$STAGE/config/tracetramp.env.example"
printf '%s\n' "$VERSION" >"$STAGE/VERSION"
cat >"$STAGE/README.txt" <<EOF
TraceTramp ${VERSION}
  bin/tracetramp serve
  config/tracetramp.env.example
  share/migrations — run with sqlx against TRACETRAMP_DATABASE_URL
  GET /admin/dashboard on management plane (port 9742)
Redis optional: omit TRACETRAMP_REDIS_URL for postgres-only.
EOF

mkdir -p "$OUT_DIR"
tar -C "$STAGE" -czf "$OUT_PATH" .
(cd "$OUT_DIR" && sha256sum "$(basename "$OUT_PATH")" >>SHA256SUMS.plugins 2>/dev/null || sha256sum "$(basename "$OUT_PATH")" >SHA256SUMS.plugins)
echo "package-tracetramp: OK — $OUT_PATH"

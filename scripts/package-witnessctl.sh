#!/usr/bin/env bash
# Package WitnessCtl release tarball (plan Phase 4).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN="$ROOT/plugins/witnessctl"
MANIFEST="$PLUGIN/Cargo.toml"
OUT_DIR="${CONNECTOR_PACKAGE_DIR:-$ROOT/dist}"
CARGO_TARGET="${CARGO_TARGET_DIR:-$PLUGIN/target}"

VERSION="$(cd "$PLUGIN" && cargo metadata --format-version 1 --no-deps --manifest-path "$MANIFEST" 2>/dev/null \
  | python3 -c "import json,sys; print(next(p['version'] for p in json.load(sys.stdin)['packages'] if p['name']=='witnessctl'))")"
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64) ARCH_TAG=x86_64-linux ;;
  aarch64|arm64) ARCH_TAG=aarch64-linux ;;
  *) ARCH_TAG="${ARCH_RAW}-linux" ;;
esac

TAR_NAME="witnessctl-${VERSION}-${ARCH_TAG}.tar.gz"
OUT_PATH="$OUT_DIR/$TAR_NAME"

if [[ "${CONNECTOR_PACKAGE_NO_BUILD:-}" != "1" ]]; then
  echo "package-witnessctl: cargo build --release …"
  (cd "$PLUGIN" && CARGO_TARGET_DIR="$CARGO_TARGET" cargo build --release \
    --bin witnessctl --bin witnessctl-verify --bin witnessctl-node)
fi

for b in witnessctl witnessctl-verify witnessctl-node; do
  [[ -x "$CARGO_TARGET/release/$b" ]] || { echo "missing $CARGO_TARGET/release/$b" >&2; exit 1; }
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/bin" "$STAGE/share/migrations" "$STAGE/admin-ui" "$STAGE/config"
install -m755 "$CARGO_TARGET/release/witnessctl" "$STAGE/bin/"
install -m755 "$CARGO_TARGET/release/witnessctl-verify" "$STAGE/bin/"
install -m755 "$CARGO_TARGET/release/witnessctl-node" "$STAGE/bin/"
cp -a "$PLUGIN/migrations/." "$STAGE/share/migrations/"
cp "$PLUGIN/admin-ui/dashboard.html" "$STAGE/admin-ui/"
cp "$PLUGIN/.env.example" "$STAGE/config/witnessctl.env.example"
printf '%s\n' "$VERSION" >"$STAGE/VERSION"
cat >"$STAGE/README.txt" <<EOF
WitnessCtl ${VERSION}
  bin/witnessctl — server + CLI
  bin/witnessctl-verify — offline .witness verification
  bin/witnessctl-node — regional custody replicate endpoint
  witnessctl session seal <id> --output ./evidence.witness
EOF

mkdir -p "$OUT_DIR"
tar -C "$STAGE" -czf "$OUT_PATH" .
(cd "$OUT_DIR" && sha256sum "$(basename "$OUT_PATH")" >>SHA256SUMS.plugins 2>/dev/null || true)
echo "package-witnessctl: OK — $OUT_PATH"

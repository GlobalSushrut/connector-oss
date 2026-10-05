#!/usr/bin/env bash
# Core dashboard build into a staging directory (no trial, no promote).
# Called by build_release.py and build-leptos.sh.
set -euo pipefail

PROFILE="${1:-playground}"
STAGE="${2:?staging directory required}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WS="$(cd "$ROOT/.." && pwd)"

cd "$ROOT"

echo "==> Tailwind CSS"
npx --yes tailwindcss@3.4.17 -i ./input.css -o ./tailwind.out.css --minify
mkdir -p public
cp tailwind.out.css public/tailwind.out.css

cd "$WS"

LEPTOS_ARGS=(build --split --release --frontend-only)
case "$PROFILE" in
  playground) LEPTOS_ARGS+=(--lib-features playground) ;;
  self-deploy) LEPTOS_ARGS+=(--lib-features self-deploy) ;;
  *) echo "Unknown profile: $PROFILE" >&2; exit 1 ;;
esac

echo "==> cargo leptos ${LEPTOS_ARGS[*]}"
cargo leptos "${LEPTOS_ARGS[@]}"

SITE="$WS/target/site"
rm -rf "$STAGE"
mkdir -p "$STAGE"

if [ -d "$SITE/pkg" ]; then
  cp -a "$SITE/pkg/." "$STAGE/"
fi
cp -a "$SITE"/* "$STAGE/" 2>/dev/null || true

python3 "$ROOT/scripts/leptos_index.py" "$STAGE"
python3 "$ROOT/scripts/patch_wasm_init.py" "$STAGE/index.html" "$PROFILE"

for f in "$STAGE"/*.js "$STAGE"/*.css "$STAGE"/*.wasm "$STAGE"/split_*.wasm "$STAGE"/chunk_*.wasm "$STAGE"/__wasm_split*.js; do
  [ -f "$f" ] || continue
  gzip -9 -f -k "$f"
done

cp "$ROOT/public/sw.js" "$STAGE/sw.js"
cp "$ROOT/public/logo.png" "$STAGE/logo.png"
cp "$ROOT/public/favicon.png" "$STAGE/favicon.png"
gzip -9 -f -k "$STAGE/sw.js" 2>/dev/null || true

echo "==> dashboard staged → $STAGE"

#!/usr/bin/env bash
# Copy the public Connector tree to a destination directory.
# The destination is what can be published. This private repository is not.
# Layout stays the same as this repo so platform/server can build against oss/.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <destination-directory>" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
dest="$1"
mkdir -p "$dest"

rsync -a --delete \
  --exclude 'target/' \
  --exclude 'target/**' \
  --exclude '.cargo-target-umesh/' \
  --exclude '.venv/' \
  --exclude 'venv/' \
  --exclude '__pycache__/' \
  --exclude 'node_modules/' \
  --exclude '.env' \
  --exclude '.env.*' \
  --exclude '*.db' \
  --exclude '*.sqlite' \
  --exclude '*.sqlite3' \
  --exclude '*.redb' \
  "$root/oss/" "$dest/oss/"

rsync -a --delete \
  --exclude 'target/' \
  --exclude '.cargo-target/' \
  --exclude '.cargo-target-umesh/' \
  --exclude 'playground-target/' \
  --exclude 'ui-leptos/trial/' \
  --exclude 'licensing/' \
  --exclude 'ui-leptos/www/' \
  --exclude 'ui-leptos/admin/' \
  --exclude 'docs/arch/' \
  --exclude 'docs/gtm/' \
  --exclude 'docs/pilots/' \
  --exclude 'docs/cofounder_clarity_latex/' \
  --exclude 'docs/connector-youtube-deck/' \
  --exclude 'gtm-presentation/' \
  --exclude 'node_modules/' \
  --exclude 'dist/' \
  --exclude 'server/data/' \
  --exclude 'ui-leptos/dashboard/data/' \
  --exclude 'deploy/artifacts/' \
  --exclude 'release/' \
  --exclude 'lab/microvm-assets/rootfs.ext4' \
  --exclude 'lab/microvm-assets/vmlinux' \
  --exclude '.license-seed' \
  --exclude '.env' \
  --exclude '**/.env' \
  --exclude '*.db' \
  --exclude '*.db-wal' \
  --exclude '*.db-shm' \
  --exclude '*.sqlite' \
  --exclude '*.sqlite3' \
  --exclude '*.redb' \
  --exclude '*.key' \
  --exclude '*PLAN*' \
  --exclude '*CHECKLIST*' \
  --exclude '*REMAINING*' \
  "$root/platform/" "$dest/platform/"

rsync -a --delete \
  --exclude 'target/' \
  "$root/agos-abi/" "$dest/agos-abi/"
rsync -a --delete \
  --exclude 'target/' \
  "$root/agos-sdk/" "$dest/agos-sdk/"

install -m 0755 "$root/up.sh" "$dest/up.sh"
sed \
  -e 's|(LICENSE)|(oss/LICENSE)|g' \
  -e 's|(../platform/LICENSE)|(platform/LICENSE)|g' \
  -e 's|(SECURITY.md)|(oss/SECURITY.md)|g' \
  -e 's|href="SECURITY.md"|href="oss/SECURITY.md"|g' \
  -e 's|(CONTRIBUTING.md)|(oss/CONTRIBUTING.md)|g' \
  -e 's|(docs/quickstart.md)|(oss/docs/quickstart.md)|g' \
  -e 's|src="assets/|src="oss/assets/|g' \
  "$root/oss/README.md" > "$dest/README.md"
rm -rf "$dest/.github"
mkdir -p "$dest/.github"
rsync -a "$root/oss/.github/" "$dest/.github/"

cat > "$dest/.gitignore" <<'EOF'
target/
**/target/
.cargo-target-umesh/
node_modules/
dist/
.venv/
venv/
__pycache__/
.env
.env.*
!.env.example
*.db
*.sqlite
*.sqlite3
*.redb
.license-seed
**/*PLAN*.md
**/*CHECKLIST*.md
**/*REMAINING*.md
EOF

forbidden=(
  "$dest/platform/licensing"
  "$dest/platform/ui-leptos/www"
  "$dest/platform/ui-leptos/admin"
  "$dest/platform/docs/arch"
  "$dest/platform/deploy/.env"
  "$dest/platform/server/data"
  "$dest/platform/server/data/keys/platform_signing.key"
  "$dest/platform/ui-leptos/dashboard/data/keys/platform_signing.key"
  "$dest/platform/deploy/artifacts"
  "$dest/platform/lab/microvm-assets/rootfs.ext4"
)
for path in "${forbidden[@]}"; do
  if [[ -e "$path" ]]; then
    echo "refusing to publish $path" >&2
    exit 1
  fi
done

required=(
  "$dest/up.sh"
  "$dest/oss/up.sh"
  "$dest/oss/boot-backends.sh"
  "$dest/README.md"
  "$dest/platform/server/Cargo.toml"
  "$dest/platform/LICENSE"
  "$dest/oss/LICENSE"
  "$dest/agos-abi/Cargo.toml"
  "$dest/agos-sdk/Cargo.toml"
  "$dest/platform/server/../../oss/vac/crates/vac-core/Cargo.toml"
  "$dest/.github/workflows/ci.yml"
)
for path in "${required[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "public tree is missing $path" >&2
    exit 1
  fi
done

oversized="$(find "$dest" -type f -size +95M -printf '%s\t%p\n' || true)"
if [[ -n "$oversized" ]]; then
  echo "refusing to publish files over 95MB:" >&2
  echo "$oversized" >&2
  exit 1
fi

echo "public tree: $dest"
echo "start command: ./up.sh"

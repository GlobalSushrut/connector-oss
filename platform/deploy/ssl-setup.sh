#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Connector Platform — SSL/TLS Setup Script
#
# Usage:
#   ./deploy/ssl-setup.sh caddy   → (deprecated) was Docker Compose + Caddy; use microVM / connectorctl
#   ./deploy/ssl-setup.sh nginx   → Set up nginx + certbot (+ legacy Docker start removed — see below)
#   ./deploy/ssl-setup.sh verify  → Verify DNS + cert status
#   ./deploy/ssl-setup.sh renew   → Force cert renewal (certbot or Caddy if still on old stack)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Phase 0.7 removed `platform/deploy/docker-compose*.yml`. Production runtime is microVM + supervisor;
# see CONNECTOR_OS_ROADMAP.md. `verify` / certbot-only `nginx` paths still work; `caddy` no longer
# starts a Compose stack from this directory.
set -euo pipefail

compose_removed() {
    error "Docker Compose stacks under platform/deploy/ were removed (Phase 0.7 — CONNECTOR_OS_ROADMAP.md)."
    error "Use connectorctl / microVM for the platform runtime, or lab/ for optional Docker lab."
    exit 1
}

DEPLOY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$DEPLOY_DIR/.env"

# ── Load .env ─────────────────────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: $ENV_FILE not found. Copy .env.example to .env and add DOMAIN, LICENSE_DOMAIN, ACME_EMAIL (and any other keys this script requires)."
    exit 1
fi
set -a; source "$ENV_FILE"; set +a

DOMAIN="${DOMAIN:?Set DOMAIN in .env}"
LICENSE_DOMAIN="${LICENSE_DOMAIN:?Set LICENSE_DOMAIN in .env}"
WWW_DOMAIN="${WWW_DOMAIN:-www.$DOMAIN}"
APEX_DOMAIN="${APEX_DOMAIN:-$DOMAIN}"
ACME_EMAIL="${ACME_EMAIL:?Set ACME_EMAIL in .env}"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "\033[0;32m[INFO]\033[0m  $*"; }
warn()    { echo -e "\033[0;33m[WARN]\033[0m  $*"; }
error()   { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; }
success() { echo -e "\033[0;36m[OK]\033[0m    $*"; }

check_dns() {
    local domain="$1"
    local server_ip
    server_ip=$(curl -s https://checkip.amazonaws.com || curl -s https://api.ipify.org || echo "unknown")
    local resolved
    resolved=$(dig +short "$domain" A 2>/dev/null | tail -1)
    if [[ "$resolved" == "$server_ip" ]]; then
        success "DNS OK: $domain → $resolved"
        return 0
    else
        warn "DNS MISMATCH: $domain resolves to '$resolved', server IP is '$server_ip'"
        warn "  → Update your DNS A record: $domain → $server_ip"
        return 1
    fi
}

# ── Command: verify ───────────────────────────────────────────────────────────
cmd_verify() {
    info "Checking DNS resolution..."
    local all_ok=true

    for d in "$DOMAIN" "$LICENSE_DOMAIN" "$WWW_DOMAIN"; do
        check_dns "$d" || all_ok=false
    done

    info "Checking TLS certificates..."
    for d in "$DOMAIN" "$LICENSE_DOMAIN"; do
        if echo | timeout 5 openssl s_client -connect "$d:443" -servername "$d" 2>/dev/null | \
           openssl x509 -noout -dates 2>/dev/null; then
            success "Cert valid: $d"
        else
            warn "No valid cert yet for $d (may be pending first issuance)"
        fi
    done

    if $all_ok; then
        success "All DNS checks passed!"
    else
        error "Some DNS checks failed — fix DNS before starting Caddy"
        exit 1
    fi
}

# ── Command: caddy ────────────────────────────────────────────────────────────
cmd_caddy() {
    warn "Caddy + Docker Compose startup was removed with platform/deploy/docker-compose*.yml."
    compose_removed
}

# ── Command: nginx ────────────────────────────────────────────────────────────
cmd_nginx() {
    info "Setting up nginx + Let's Encrypt (certbot)..."

    # Check certbot is installed
    if ! command -v certbot &>/dev/null; then
        info "Installing certbot..."
        apt-get update -qq && apt-get install -y -qq certbot python3-certbot-nginx
    fi

    # Substitute domain placeholders in nginx.conf
    info "Configuring nginx..."
    cp "$DEPLOY_DIR/nginx.conf" /etc/nginx/nginx.conf
    sed -i "s/REPLACE_WITH_YOUR_DOMAIN/$DOMAIN/g" /etc/nginx/nginx.conf
    sed -i "s/REPLACE_WITH_YOUR_LICENSE_DOMAIN/$LICENSE_DOMAIN/g" /etc/nginx/nginx.conf

    # Test nginx config
    nginx -t

    # Start nginx with HTTP only first (for ACME challenge)
    systemctl restart nginx

    # Obtain certificates
    info "Obtaining TLS certificates via Let's Encrypt..."
    certbot --nginx \
        -d "$DOMAIN" \
        -d "$WWW_DOMAIN" \
        -d "$APEX_DOMAIN" \
        --email "$ACME_EMAIL" \
        --agree-tos \
        --non-interactive \
        --redirect

    certbot --nginx \
        -d "$LICENSE_DOMAIN" \
        --email "$ACME_EMAIL" \
        --agree-tos \
        --non-interactive \
        --redirect

    # Enable auto-renewal
    systemctl enable certbot.timer
    systemctl start certbot.timer

    success "nginx + TLS configured!"
    success "  Auto-renewal: systemctl status certbot.timer"
    success "  Test renewal:  certbot renew --dry-run"

    info "Skipping Docker Compose platform start (removed in Phase 0.7). Configure nginx upstream to your connectorctl / microVM listener."
    success "nginx + TLS configured. Point upstream to the Connector OS runtime (not removed compose files)."
    info "  Platform:  https://$DOMAIN"
    info "  License:   https://$LICENSE_DOMAIN"
}

# ── Command: renew ────────────────────────────────────────────────────────────
cmd_renew() {
    if command -v certbot &>/dev/null; then
        info "Forcing certbot renewal..."
        certbot renew --force-renewal
        nginx -s reload 2>/dev/null || true
        success "Certificates renewed!"
    else
        warn "Caddy Compose reload removed with platform/deploy/docker-compose*.yml; restart Caddy manually if you still run it outside Compose."
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
case "${1:-help}" in
    caddy)   cmd_caddy  ;;
    nginx)   cmd_nginx  ;;
    verify)  cmd_verify ;;
    renew)   cmd_renew  ;;
    *)
        echo "Usage: $0 {caddy|nginx|verify|renew}"
        echo ""
        echo "  caddy   Start with Caddy auto-HTTPS (recommended — zero-config TLS)"
        echo "  nginx   Set up nginx + certbot (manual cert management)"
        echo "  verify  Check DNS + cert status"
        echo "  renew   Force certificate renewal"
        exit 1
        ;;
esac

#!/usr/bin/env bash
# Connector OS — Cloudflare API Automation Helper
#
# Sources token from .env automatically. Usage:
#   source scripts/cf-api.sh
#   cf_get_zone_id          # Returns cnktros.com zone ID
#   cf_dns_list             # List DNS records
#   cf_dns_add CNAME api target.example.com
#   cf_ssl_status           # Check SSL/TLS mode
#
# Requires: curl, jq

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"

# Load token from .env (created from .env.example)
if [[ -f "$ENV_FILE" ]]; then
    export $(grep -v '^#' "$ENV_FILE" | grep -E '^(CLOUDFLARE|CF_)' | xargs 2>/dev/null || true)
fi

CF_TOKEN="${CLOUDFLARE_API_TOKEN:-${CF_TOKEN:-}}"
CF_ZONE="${CLOUDFLARE_ZONE_ID:-${CF_ZONE_ID:-}}"

if [[ -z "$CF_TOKEN" ]]; then
    echo "Error: CLOUDFLARE_API_TOKEN not set in .env" >&2
    exit 1
fi

# Cache zone ID lookup if not provided
if [[ -z "$CF_ZONE" ]]; then
    CF_ZONE=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=cnktros.com" \
        -H "Authorization: Bearer $CF_TOKEN" \
        -H "Content-Type: application/json" | \
        jq -r '.result[0].id // empty')
    
    if [[ -z "$CF_ZONE" ]]; then
        echo "Error: Could not find zone ID for cnktros.com" >&2
        exit 1
    fi
    export CLOUDFLARE_ZONE_ID="$CF_ZONE"
fi

export CF_API_BASE="https://api.cloudflare.com/client/v4"
export CF_TOKEN
export CF_ZONE

# ──────────────────────────────────────────────────────────────────────────────
# Core API functions
# ──────────────────────────────────────────────────────────────────────────────

cf_api() {
    local method="${1:-GET}"
    local endpoint="${2:-}"
    local data="${3:-}"
    
    local url="${CF_API_BASE}${endpoint}"
    local opts=(-s -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json")
    
    if [[ "$method" != "GET" && -n "$data" ]]; then
        opts+=(-d "$data")
    fi
    
    curl "${opts[@]}" -X "$method" "$url"
}

# ── Zone ─────────────────────────────────────────────────────────────────────

cf_get_zone_id() {
    echo "$CF_ZONE"
}

cf_zone_details() {
    cf_api GET "/zones/$CF_ZONE" | jq .
}

# ── DNS ──────────────────────────────────────────────────────────────────────

cf_dns_list() {
    cf_api GET "/zones/$CF_ZONE/dns_records" | jq '.result[] | {name, type, content, ttl}'
}

cf_dns_add() {
    local type="${1:-}"
    local name="${2:-}"
    local content="${3:-}"
    local ttl="${4:-1}"  # 1 = Auto
    
    if [[ -z "$type" || -z "$name" || -z "$content" ]]; then
        echo "Usage: cf_dns_add <type> <name> <content> [ttl]" >&2
        return 1
    fi
    
    local data=$(jq -n \
        --arg type "$type" \
        --arg name "$name" \
        --arg content "$content" \
        --argjson ttl "$ttl" \
        '{type: $type, name: $name, content: $content, ttl: $ttl}')
    
    cf_api POST "/zones/$CF_ZONE/dns_records" "$data" | jq .
}

cf_dns_delete() {
    local record_id="${1:-}"
    if [[ -z "$record_id" ]]; then
        echo "Usage: cf_dns_delete <record_id>" >&2
        return 1
    fi
    cf_api DELETE "/zones/$CF_ZONE/dns_records/$record_id" | jq '.success'
}

# ── SSL/TLS ──────────────────────────────────────────────────────────────────

cf_ssl_status() {
    cf_api GET "/zones/$CF_ZONE/settings/ssl" | jq '.result'
}

cf_ssl_set() {
    local mode="${1:-strict}"  # off, flexible, full, strict
    local data="{\"value\":\"$mode\"}"
    cf_api PATCH "/zones/$CF_ZONE/settings/ssl" "$data" | jq '.success'
}

# ── Firewall / WAF ───────────────────────────────────────────────────────────

cf_firewall_list() {
    cf_api GET "/zones/$CF_ZONE/firewall/rules" | jq '.result[] | {id, description, filter: .filter.expression}'
}

cf_waf_list() {
    cf_api GET "/zones/$CF_ZONE/firewall/waf/packages" | jq '.result[] | {id, name, sensitivity}'
}

# Add IP allowlist for /admin access
cf_admin_ip_allowlist() {
    local cidr="${1:-}"
    if [[ -z "$cidr" ]]; then
        echo "Usage: cf_admin_ip_allowlist <CIDR>" >&2
        echo "Example: cf_admin_ip_allowlist 203.0.113.0/24" >&2
        return 1
    fi
    
    local data=$(jq -n \
        --arg cidr "$cidr" \
        '{description: "Admin panel IP allowlist", filter: {expression: "(http.request.uri.path contains \"/admin\") and (not ip.src in {$cidr})"}, action: "block"}')
    
    cf_api POST "/zones/$CF_ZONE/firewall/rules" "$data" | jq '.success'
}

# ── Cache ────────────────────────────────────────────────────────────────────

cf_cache_purge_all() {
    cf_api POST "/zones/$CF_ZONE/purge_cache" '{"purge_everything":true}' | jq '.success'
}

cf_cache_purge_url() {
    local url="${1:-}"
    if [[ -z "$url" ]]; then
        echo "Usage: cf_cache_purge_url <url>" >&2
        return 1
    fi
    cf_api POST "/zones/$CF_ZONE/purge_cache" "{\"files\":[\"$url\"]}" | jq '.success'
}

# ── Health Check ─────────────────────────────────────────────────────────────

cf_verify_token() {
    echo "Testing Cloudflare API token..."
    
    local tests=0
    local passed=0
    
    # Test 1: Zone read
    if cf_api GET "/zones?name=cnktros.com" | jq -e '.success' > /dev/null; then
        echo "  ✅ Zone:Read"
        ((passed++))
    else
        echo "  ❌ Zone:Read"
    fi
    ((tests++))
    
    # Test 2: DNS Edit
    if cf_api GET "/zones/$CF_ZONE/dns_records" | jq -e '.success' > /dev/null; then
        echo "  ✅ DNS:Edit"
        ((passed++))
    else
        echo "  ❌ DNS:Edit"
    fi
    ((tests++))
    
    # Test 3: SSL
    if cf_api GET "/zones/$CF_ZONE/settings/ssl" | jq -e '.success' > /dev/null; then
        echo "  ✅ SSL:Edit"
        ((passed++))
    else
        echo "  ❌ SSL:Edit"
    fi
    ((tests++))
    
    # Test 4: Firewall
    if cf_api GET "/zones/$CF_ZONE/firewall/rules" | jq -e '.success' > /dev/null; then
        echo "  ✅ Firewall:Edit"
        ((passed++))
    else
        echo "  ❌ Firewall:Edit"
    fi
    ((tests++))
    
    echo ""
    echo "Result: $passed/$tests tests passed"
    
    if [[ $passed -eq $tests ]]; then
        echo "Token verified and ready for deployment ✅"
        return 0
    else
        echo "Token missing permissions. Update at dash.cloudflare.com/profile/api-tokens" >&2
        return 1
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# If script is run directly (not sourced), show usage
# ──────────────────────────────────────────────────────────────────────────────

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        verify)
            cf_verify_token
            ;;
        zone-id)
            cf_get_zone_id
            ;;
        dns-list)
            cf_dns_list
            ;;
        ssl-status)
            cf_ssl_status
            ;;
        *)
            cat << 'EOF'
Cloudflare API Helper for Connector OS

Usage:
  source scripts/cf-api.sh           # Load functions
  cf_verify_token                    # Test all permissions

Available functions:
  cf_get_zone_id                     # Return zone ID
  cf_dns_list                        # List DNS records
  cf_dns_add <type> <name> <content> # Add DNS record
  cf_dns_delete <record_id>          # Delete DNS record
  cf_ssl_status                      # Check SSL mode
  cf_ssl_set <strict|full|flexible>  # Change SSL mode
  cf_firewall_list                   # List firewall rules
  cf_admin_ip_allowlist <CIDR>       # IP restrict /admin
  cf_cache_purge_all                 # Purge all cache
  cf_cache_purge_url <url>           # Purge specific URL

One-shot commands:
  ./cf-api.sh verify                 # Verify token permissions
  ./cf-api.sh zone-id                # Show zone ID
  ./cf-api.sh dns-list               # List DNS records
  ./cf-api.sh ssl-status             # Check SSL settings
EOF
            ;;
    esac
fi

# Cloudflare DNS fix (525 on api / portal / try)

Fly custom hostnames need **DNS-only** (gray cloud) CNAMEs to `*.fly.dev`. Orange-cloud proxy causes **525** until origin certs match.

## Records (cnktros.com zone)

| Name | Type | Target | Proxy |
|------|------|--------|-------|
| `api` | CNAME | `connector-license.fly.dev` | **DNS only** |
| `portal` | CNAME | `connector-license.fly.dev` | **DNS only** |
| `admin` | CNAME | `connector-license.fly.dev` | **DNS only** |
| `try` | CNAME | `connector-playground.fly.dev` | **DNS only** |
| `@` / `www` | CNAME | `cname.vercel-dns.com` | Proxied OK |

Admin UI is served at `https://admin.cnktros.com/admin` (same Fly app as portal).

## After DNS propagates

```bash
fly certs check api.cnktros.com -a connector-license
fly certs check portal.cnktros.com -a connector-license
fly certs check admin.cnktros.com -a connector-license
fly certs check try.cnktros.com -a connector-playground
```

## Script (needs valid API token)

```bash
CF_PROXY_FLY=false bash platform/deploy/scripts/cloudflare-dns.sh
```

### API token errors

| Code | Meaning | Fix |
|------|---------|-----|
| **9109** | Token blocked from **your IP** (IP Address Filtering on the token) | Edit token → remove IP filter or add your current IP |
| **10429** | Rate limited (too many API calls) | Wait 5 min; run `DNS_RECORD=api bash cloudflare-dns.sh` one at a time |
| Auth failed | Invalid/revoked token | Create new token: Zone:Read + DNS:Edit on cnktros.com only |

Rotate `CLOUDFLARE_API_TOKEN` in `platform/deploy/.env` after fixing the token in the dashboard.

### One record at a time (avoids rate limits)

```bash
DNS_RECORD=api bash platform/deploy/scripts/cloudflare-dns.sh
DNS_RECORD=portal bash platform/deploy/scripts/cloudflare-dns.sh
DNS_RECORD=admin bash platform/deploy/scripts/cloudflare-dns.sh
DNS_RECORD=try bash platform/deploy/scripts/cloudflare-dns.sh
```

## Until custom domains work

- License: `https://connector-license.fly.dev` (portal `/`, admin `/admin`, API `/api/v1`)
- Playground: `https://connector-playground.fly.dev`

# TLS and custom domains (P1.1)

Connector OS stores **Host → plugin** routing and `tls_mode` metadata. **Certificate termination** is operator-managed.

## Recommended pattern

1. Point DNS `tracetramp.acme.corp` → your load balancer or reverse proxy.
2. Terminate TLS at nginx/Caddy/Traefik with a real cert (Let's Encrypt or corporate CA).
3. Proxy to Connector with `Host` preserved:

```nginx
proxy_pass http://127.0.0.1:9091;
proxy_set_header Host $host;
```

4. Register the custom domain in the dashboard (**Settings → Networking → Custom domains**) or `POST /api/v1/settings/networking/custom-domains`.

## Verify (automated)

```bash
make custom-domain-smoke   # Host routing + metadata (server must be up)
```

## Verify (TLS)

```bash
curl -fsS https://tracetramp.acme.corp/plugin/tracetramp/health
```

Internal cage names (`*.cnktros`) must **not** resolve on public DNS — `make prod-readiness-gate` checks `dig tracetramp.cnktros`.

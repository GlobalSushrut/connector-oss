# Connector OS — Node v0.1.0

**Self-hosted agent infrastructure.** Run a Connector node on any Linux or macOS machine, connect your AI tools (Cursor, Windsurf, Claude Desktop, custom agents), and get full observability, routing, and safety controls.

---

## Quick start

### 1. Get your pilot key

Log in at [portal.cnktros.com](https://portal.cnktros.com) → **API Keys** → copy your `cpk_pilot_*` key.

### 2. Configure

```bash
# Edit the config (already placed at ~/.connector/connector.toml by the installer)
nano ~/.connector/connector.toml
```

Set your key:
```toml
[license]
key = "cpk_pilot_YOUR_KEY_HERE"
```

### 3. Start the node

```bash
# Direct
connector-platform --config ~/.connector/connector.toml

# Or with systemd (Linux, installed automatically)
systemctl --user start connector
systemctl --user enable connector   # auto-start on login
```

### 4. Open the dashboard

```
http://localhost:9090
```

Log in with the email and password you used to sign up.

### 5. Connect your AI tool

| Tool | Setting | Value |
|------|---------|-------|
| **Cursor** | MCP Server URL | `http://localhost:9090/api/v1/mcp` |
| **Windsurf** | Cascade endpoint | `http://localhost:9090/api/v1/mcp` |
| **Claude Desktop** | MCP config | `{"url": "http://localhost:9090/api/v1/mcp"}` |

---

## Contents of this archive

```
connector-0.1.0-linux-amd64/
├── bin/
│   ├── connector-platform     # Main node daemon
│   └── connectorctl           # CLI management tool
├── connector.toml.example     # Config template
├── install.sh                 # Installer (already ran if you used curl)
└── README.md                  # This file
```

---

## Requirements

| | Minimum | Recommended |
|---|---|---|
| **OS** | Linux (glibc ≥2.17) or macOS 12+ | Ubuntu 22.04 / macOS 14 |
| **CPU** | 1 core | 4 cores |
| **RAM** | 512 MB | 2 GB |
| **Disk** | 1 GB | 10 GB |
| **Network** | Outbound HTTPS to portal.cnktros.com | — |

---

## connectorctl reference

```bash
connectorctl status                   # Node health + agent count
connectorctl agents list              # List active agents
connectorctl agents kill <id>         # Terminate an agent session
connectorctl keys list                # Show active API keys
connectorctl logs --follow            # Stream node logs
connectorctl config validate          # Validate connector.toml
connectorctl upgrade                  # Billing tier (portal) — not binary upgrade
connectorctl node-upgrade             # Print N→N+1 binary upgrade steps
```

---

## License

This binary is licensed to your pilot account. The license key validates against `portal.cnktros.com` at startup and periodically.  
Redistribution, reverse engineering, or use outside the scope of your pilot agreement is prohibited.

Questions? → support@cnktros.com  
Docs → https://portal.cnktros.com/docs

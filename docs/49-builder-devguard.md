# 49 — Builder: DevGuard Plugin

> Govern coding agents — every file access, command, and code generation is gated, audited, and sealed.

---

## What DevGuard Does

DevGuard is the Connector plugin for governing AI coding assistants (Claude Code, Cursor, Windsurf, GitHub Copilot, Kiro, etc.). It intercepts every action the coding agent takes and applies:

1. **Admission gate** — is this action in the allowed scope?
2. **Firewall** — does the action/content contain injection or PII?
3. **Tool governance** — file access, shell commands, git operations
4. **Budget enforcement** — token and time limits
5. **Audit trail** — every action receipted and chained
6. **Proof generation** — session bundle for code review or compliance

---

## DevGuard Workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `session_open` | Coding session start | Register agent, init chain |
| `file_read` | Read file request | Policy check, audit |
| `file_write` | Write file request | Schema check, diff audit |
| `shell_exec` | Shell command | Safety check, allowlist |
| `llm_generate` | LLM code generation | Firewall, grounding |
| `git_op` | Git operation | Audit, proof |
| `session_seal` | Session end | Seal chain, generate proof |

---

## DevGuard Configuration

```yaml
# devguard.yaml
plugin: devguard
version: "1.0"

agent:
  name: devguard-session
  clearance: 3

# File system scope
filesystem:
  allowed_paths:
    - /home/user/projects/my-app/
    - /tmp/devguard/
  denied_paths:
    - /etc/
    - /var/
    - ~/.ssh/
    - ~/.aws/
  max_file_size_mb: 10
  deny_binary_write: true

# Shell command allowlist
shell:
  allowed_commands:
    - git
    - npm
    - python3
    - pytest
    - cargo
    - docker
  denied_patterns:
    - "rm -rf"
    - "sudo"
    - "chmod 777"
    - "curl.*|bash"
  dry_run_on_destructive: true

# LLM governance
llm:
  max_tokens_per_session: 500000
  require_grounding: true
  block_credential_output: true
  pii_detection: true

# Compliance
compliance:
  regulations: [soc2]
  audit_all_file_writes: true
  proof_on_session_seal: true
```

---

## Python Integration

```python
import sys, json
sys.path.insert(0, "demos/")
from system_data import ConnectorPlatform

p = ConnectorPlatform()

# Open DevGuard session
agent = p.register_agent("devguard-session", "Coding session", 3)
pid   = agent["pid"]
ns    = agent["namespace"]

def dg_file_read(pid, ns, file_path):
    """Governed file read."""
    # Policy check
    check = p.policy_check(pid, "file_read", file_path)
    if check.get("verdict") == "DENY":
        p.record_decision(pid, "file.read_denied", file_path,
                          "denied", rationale=check["reason"])
        raise PermissionError(f"File read denied: {check['reason']}")

    # Read file
    with open(file_path) as f:
        content = f.read()

    # Scan for credentials/PII in file content
    fw = p.firewall_inspect(pid, content[:2000], ns)

    # Audit
    p.record_decision(pid, "file.read", file_path, "allowed",
                      regulations=["soc2"])
    return content


def dg_file_write(pid, ns, file_path, content):
    """Governed file write."""
    # Policy check
    check = p.policy_check(pid, "file_write", file_path)
    if check.get("verdict") == "DENY":
        raise PermissionError(f"File write denied: {check['reason']}")

    # Scan content before writing
    fw = p.firewall_inspect(pid, content, ns)
    if fw["blocked"]:
        raise SecurityError(f"Content blocked: {fw['final_decision']}")

    # Write
    with open(file_path, "w") as f:
        f.write(content)

    # Store diff/evidence
    p.write_memory(pid,
        json.dumps({"action": "file_write", "path": file_path,
                    "size_bytes": len(content), "pii_scanned": True}),
        ptype="file_write_evidence", memory_type="evidence",
        tags=["devguard", "file_write", f"path:{file_path[:40]}"])

    p.record_decision(pid, "file.write", file_path, "written",
                      regulations=["soc2"])


def dg_shell_exec(pid, ns, command):
    """Governed shell command execution."""
    ALLOWED = ["git", "npm", "python3", "pytest", "cargo", "docker"]
    cmd_base = command.split()[0]

    if cmd_base not in ALLOWED:
        p.record_decision(pid, "shell.denied", command[:60],
                          "denied", rationale=f"{cmd_base} not in allowlist")
        raise PermissionError(f"Shell command '{cmd_base}' not in allowlist")

    # Firewall check the full command
    fw = p.firewall_inspect(pid, command, ns)
    if fw["blocked"]:
        raise SecurityError(f"Command blocked: {fw['final_decision']}")

    p.record_decision(pid, "shell.execute", command[:60], "executed",
                      regulations=["soc2"])

    import subprocess
    result = subprocess.run(command.split(), capture_output=True, text=True, timeout=30)
    return result.stdout
```

---

## DevGuard for Claude Code

Configure Claude Code to use Connector as its tool governance layer:

```json
// .claude/settings.json
{
  "connector": {
    "enabled": true,
    "url": "http://localhost:9091",
    "api_key": "${CONNECTOR_API_KEY}",
    "devguard": {
      "session_agent": "devguard-claude",
      "policy": "devguard_strict",
      "audit_all": true,
      "proof_on_exit": true
    }
  }
}
```

---

## Session Seal and Proof

At the end of every coding session, seal the evidence chain:

```python
def seal_devguard_session(pid):
    """Seal the coding session and generate proof."""
    # Collect all session evidence
    evidence = p.recall_memory(ns, limit=200, memory_type="evidence")
    captures = evidence.get("packets", [])

    print(f"Session evidence: {len(captures)} packets")

    # Generate proof
    proof = p.generate_proof(pid, title="devguard_session")
    print(f"Session proof: {proof['proof_id']}")
    print(f"Chain verified: {proof['chain_verified']}")
    print(f"Journal entries: {proof['journal_entries']}")

    # SOC2 compliance report
    report = p.get_regulation_report("soc2")

    return {
        "proof_id":       proof["proof_id"],
        "evidence_count": len(captures),
        "chain_verified": proof["chain_verified"]
    }
```

---

## DevGuard in CI/CD

```bash
# At end of CI pipeline — verify the coding agent session
connectorctl prove agent devguard-session --title "ci_run_${BUILD_NUMBER}"
connectorctl compliance report soc2 --agent devguard-session

# Gate: fail CI if governance grade < B
if ! connectorctl compliance score --min-grade B; then
  echo "Governance gate failed"
  exit 1
fi
```

---

## Next Steps

- **[50 — Builder: Production Guide](50-builder-production-guide.md)**
- **[68 — DevGuard Overview](68-devguard-overview.md)**
- **[69 — DevGuard Workflows](69-devguard-workflows.md)**

# 72 — Cyber Navigation and Security Tools

> Real-world security tools and cyber navigation capabilities integrated with Connector's governance layer. Network scanning, vulnerability assessment, penetration testing, and security orchestration with full audit trails.

---

## Security Tool Integration Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Security Analysis Agent                    │
│         (Vulnerability detection, recommendations)      │
└─────────────────────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │   Connector Control   │
              │   9 Rings Enforcement  │
              │   (Can execute or     │
              │    only recommend)    │
              └───────────┬───────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Nmap      │   │   Metasploit│   │   Wireshark │
│  (Network)  │   │   (Exploit) │   │  (Capture)  │
└─────────────┘   └─────────────┘   └─────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
              ┌───────────▼───────────┐
              │    Target Network     │
              └─────────────────────────┘
```

---

## Network Scanning (Nmap)

### Read-Only Discovery Mode

```yaml
security_mode: reconnaissance_only
tools:
  - name: nmap
    allowed_args:
      - "-sP"      # Ping scan
      - "-sS"      # SYN scan
      - "-O"       # OS detection (passive)
      - "-sV"      # Version detection
    denied_args:
      - "-A"       # Aggressive (too intrusive)
      - "-T5"      # Insane timing
      - "--script" # NSE scripts (risky)
    require_approval_for:
      - ports: [22, 3389, 5432, 3306]
        reason: "Sensitive service ports"
```

### Governed Execution

```python
from connector import SecurityAgent

agent = SecurityAgent(
    role="security_analyst",
    scope="internal_network",
    permissions=["scan", "report"]  # No exploit
)

# Discover network topology
scan_result = agent.execute_tool(
    tool="nmap",
    command="nmap -sS -O 10.0.0.0/24",
    justification="Monthly asset inventory",
    requires_approval=True
)

# Results include audit trail
print(f"Found {scan_result.hosts_count} hosts")
print(f"Audit CID: {scan_result.audit_cid}")
```

---

## Vulnerability Scanning

### Nessus/OpenVAS Integration

```yaml
bridges:
  - id: nessus_scanner
    type: api
    url: https://nessus.internal:8834
    allowed_operations:
      - "GET /scans"
      - "POST /scans"          # Create scan
      - "GET /scans/{id}/export"
    denied_operations:
      - "DELETE /scans/*"      # No deletion
      - "POST /scans/{id}/launch"  # Requires approval
```

### Automated Vulnerability Management

```yaml
workflow: vulnerability-management
schedule: daily

steps:
  - id: scan
    action: exec
    bridge: nessus_scanner
    command: launch_scan --target production --policy "Internal Network Scan"
    
  - id: analyze
    action: llm
    prompt: |
      Analyze Nessus scan results:
      {{steps.scan.results}}
      
      Classify:
      - Critical: Exploitable, no patch
      - High: Exploitable, patch available
      - Medium: Informational
      - Low: Compliance-only
    output: classified_vulns
    
  - id: auto_ticket
    action: conditional
    for_each: "{{classified_vulns.critical}}"
    steps:
      - action: create_ticket
        system: jira
        project: SECURITY
        priority: critical
        summary: "Critical vuln: {{item.plugin_name}} on {{item.host}}"
        
  - id: notify
    action: webhook
    url: "${SECURITY_TEAM_WEBHOOK}"
    payload:
      critical_count: "{{classified_vulns.critical_count}}"
      report_url: "{{steps.scan.report_url}}"
```

---

## Penetration Testing Tools

### Metasploit Integration (Strict Governance)

```yaml
tool: metasploit
mode: assessment_only  # No exploitation without HITL

allowed_modules:
  - auxiliary/scanner/*     # Scanning only
  - auxiliary/gather/*      # Information gathering

denied_modules:
  - exploit/*              # Exploitation blocked
  - post/*                 # Post-exploitation blocked
  - payload/*              # Payloads blocked

escalation_required:
  - any_exploit_attempt
  - any_payload_generation
  - credential_testing_on_production
```

### Governed Pentest Workflow

```python
# Assessment phase (automated)
recon = agent.run_tool(
    tool="metasploit",
    module="auxiliary/scanner/http/http_version",
    target="10.0.0.5",
    mode="read_only"
)

# Exploitation phase (requires approval)
if recon.vulnerabilities_found:
    exploit_proposal = agent.propose_exploit(
        vulnerability="CVE-2024-XXXX",
        target="10.0.0.5",
        justification="Authorized pentest for client XYZ",
        scope_document_cid: "doc1-sha256-scope...",
        insurance_verified: True
    )
    
    # HITL approval required
    if exploit_proposal.approved_by(["pentest-lead", "client-contact"]):
        result = agent.run_exploit(exploit_proposal)
```

---

## SIEM Integration

### Splunk/Elastic/Wazuh

```yaml
bridges:
  - id: splunk_siem
    type: api
    url: https://splunk.internal:8089
    allowed_searches:
      - "index=security earliest=-1h"
      - "| stats count by source, sourcetype"
    denied_searches:
      - "*delete*"
      - "*clear*"
      - "| delete"  # Data deletion
```

### Automated Threat Hunting

```yaml
workflow: threat-hunting
schedule: hourly

steps:
  - id: hunt
    action: exec
    bridge: splunk_siem
    commands:
      - search: |
          index=security 
          (sourcetype=firewall action=blocked) OR
          (sourcetype=ids alert=high) OR
          (sourcetype=endpoint process=powershell parent=office)
          earliest=-1h
        
  - id: analyze
    action: llm
    prompt: |
      Analyze security events:
      {{steps.hunt.results}}
      
      Identify:
      1. Potential lateral movement
      2. Data exfiltration attempts
      3. Command and control traffic
      4. Insider threats
    output: threats
    
  - id: respond
    action: conditional
    conditions:
      - if: "{{threats.confirmed}}"
        action: exec
        commands:
          - "isolate_host {{threats.host}}"
          - "block_ip {{threats.attacker_ip}}"
        
      - if: "{{threats.investigation_required}}"
        action: create_ticket
        severity: high
```

---

## Network Traffic Analysis

### Wireshark/tshark

```python
# Capture and analyze (governed)
capture = agent.execute(
    tool="tshark",
    command="tshark -i eth0 -c 1000 -w /tmp/capture.pcap",
    justification="Investigating reported slowness",
    duration_seconds=60,
    max_file_size_mb: 100
)

# AI analyzes capture
analysis = agent.analyze_pcap(
    pcap_path=capture.file,
    questions=[
        "Any suspicious protocols?",
        "Unusual traffic patterns?",
        "Data exfiltration signs?"
    ]
)
```

---

## Security Governance

### Policy Enforcement

```yaml
security_policy:
  # What agents CAN do
  allowed:
    - scan_internal_networks
    - read_vulnerability_reports
    - generate_remediation_plans
    - create_tickets
    
  # What requires approval
  approval_required:
    - scan_external_targets
    - test_credentials
    - exploit_vulnerabilities
    - access_sensitive_systems
    
  # What's denied
  denied:
    - delete_security_logs
    - modify_scan_results
    - exfiltrate_data
    - unauthorized_external_communication
    
  # Audit requirements
  audit:
    log_all_commands: true
    retain_pcaps: 90_days
    export_to_siem: true
```

---

## Compliance Scanning

### Automated Compliance Checks

```yaml
workflow: compliance-scan
schedule: daily

scanners:
  - name: cis_benchmark
    tool: "oscap"
    profile: "xccdf_org.ssgproject.content_profile_cis"
    
  - name: pci_dss
    tool: "openvas"
    config: "PCI-DSS"
    
  - name: soc2
    tool: "custom_audit_script"

steps:
  - id: run_scans
    parallel: true
    actions:
      - "{{scanners.cis_benchmark}}"
      - "{{scanners.pci_dss}}"
      - "{{scanners.soc2}}"
      
  - id: consolidate
    action: llm
    prompt: |
      Merge compliance scan results:
      CIS: {{steps.run_scans.cis}}
      PCI: {{steps.run_scans.pci}}
      SOC2: {{steps.run_scans.soc2}}
      
      Generate unified compliance report.
      
  - id: remediate
    action: conditional
    for_each: "{{consolidate.auto_fixable}}"
    steps:
      - action: exec
        command: "{{item.remediation}}"
        
  - id: report
    action: generate_compliance_report
    formats: [pdf, json]
    retention: 7_years
```

---

## Incident Response Tools

### Forensics Integration

```python
# Memory forensics (governed)
memory_dump = agent.execute(
    tool="volatility",
    command="vol.py -f /memory.lime linux_pslist",
    justification="Investigating potential compromise",
    requires_approval=True
)

# Disk forensics
disk_analysis = agent.execute(
    tool="sleuthkit",
    command="fls -r /evidence/disk.img",
    justification="Legal hold requirement"
)

# Timeline analysis
timeline = agent.execute(
    tool="plaso",
    command="log2timeline.py /evidence/timeline.plaso /evidence/disk.raw"
)
```

---

## Tool Capability Matrix

| Tool | Capability | Governance Level | Approval Required |
|------|-----------|------------------|-------------------|
| Nmap | Network discovery | Read-only | Never |
| Nmap | Port scan production | Recon | Yes |
| Nessus | Vulnerability scan | Read-only | Internal: No |
| Nessus | Production scan | Assessment | Yes |
| Metasploit | Scanner modules | Read-only | No |
| Metasploit | Exploit modules | Exploitation | Always |
| Wireshark | Traffic capture | Evidence | Yes |
| Volatility | Memory forensics | Forensics | Yes |

---

## Best Practices

1. **Never allow autonomous exploitation** — Always require HITL
2. **Scope all scans** — Define IP ranges, time windows
3. **Rate limit** — Prevent DoS from scanning itself
4. **Evidence preservation** — All captures to secure storage
5. **Chain of custody** — Audit trail for all forensics
6. **Legal review** — Authorization for all external testing

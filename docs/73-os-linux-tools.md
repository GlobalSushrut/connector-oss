# 73 — Operating System and Linux Control Tools

> Direct operating system control through Connector's governance layer. System administration, process management, file operations, and Linux system tools with full command auditing and policy enforcement.

---

## OS Control Architecture

```
┌─────────────────────────────────────────────────────────┐
│              System Administration Agent                │
│          (Diagnose, fix, maintain systems)            │
└─────────────────────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │   Connector Control   │
              │   Policy Engine       │
              │   (Allow/Deny/Approve)│
              └───────────┬───────────────┘
                          │
              ┌───────────▼───────────┐
              │     SSH/Local Bridge   │
              │   (systemd connector   │
              │    user session)       │
              └───────────┬───────────────┘
                          │
              ┌───────────▼───────────┐
              │    Operating System    │
              │   (Linux/Windows/Mac)  │
              │   Processes, Files,    │
              │   Services, Network    │
              └─────────────────────────┘
```

---

## Linux System Administration

### Process Management

```yaml
tools:
  process_management:
    allowed_commands:
      - "ps aux"                    # List processes
      - "top -n 1"                  # Resource usage
      - "systemctl status *"        # Service status
      - "systemctl restart *"       # Restart service (approval required)
      - "kill -HUP {{pid}}"          # Graceful reload
      
    require_approval:
      - "kill -9 *"                 # Force kill
      - "systemctl stop *"          # Stop service
      - "systemctl disable *"       # Disable service
      
    denied_commands:
      - "killall *"                 # Too broad
      - "pkill -9 *"                # Too dangerous
```

### Governed Process Control

```python
from connector import SystemAgent

agent = SystemAgent(
    role="sysadmin",
    target_host="prod-server-01",
    escalation_policy="require_approval_for_destructive"
)

# Safe operations (auto-allowed)
processes = agent.execute("ps aux --sort=-%mem | head -20")
services = agent.execute("systemctl list-units --type=service --state=running")

# Identify memory hog
top_consumer = agent.analyze(processes).highest_memory_process

# Propose fix (may need approval)
if top_consumer.memory_percent > 50:
    proposal = agent.propose(
        action="restart_service",
        command=f"systemctl restart {top_consumer.service_name}",
        justification=f"Memory at {top_consumer.memory_percent}%, causing instability"
    )
    
    if proposal.risk_level == "low":
        result = agent.execute(proposal.command)
    else:
        result = agent.request_approval(proposal)
```

---

## File System Operations

### Governed File Management

```yaml
file_operations:
  read:
    allowed:
      - "/var/log/*"               # Log reading
      - "/etc/*"                   # Config reading
      - "/proc/*"                  # System info
      - "/home/{{user}}/*"         # User files
      
  write:
    allowed:
      - "/tmp/*"                   # Temp files
      - "/var/tmp/*"               # Temp files
    require_approval:
      - "/etc/*"                   # System configs
      - "/var/www/*"               # Web content
    denied:
      - "/boot/*"                  # Boot files
      - "/bin/*"                   # Binaries
      - "/sbin/*"                  # System binaries
      - "/lib*"                    # Libraries
      
  delete:
    require_approval:
      - "*.log"                    # Log files
      - "/tmp/*"                   # Even temp requires check
    denied:
      - "*"                        # Delete is dangerous
```

### Log Analysis

```python
# Analyze system logs
logs = agent.execute("journalctl -u nginx --since '1 hour ago'")

# AI analyzes for issues
analysis = agent.analyze_logs(
    logs=logs,
    look_for=["error", "warning", "slow", "timeout"]
)

if analysis.errors_found:
    # Propose remediation
    for error in analysis.critical_errors:
        agent.propose_fix(error)
```

---

## Service Management

### systemd Integration

```python
# Service control with governance
service_ops = {
    'status': 'auto',           # Always allowed
    'start': 'approval_if_prod',  # Approval for production
    'stop': 'always_approve',     # Always require approval
    'restart': 'approval_if_prod',
    'enable': 'always_approve',
    'disable': 'always_approve'
}

# Check service health
health = agent.execute("systemctl is-active nginx postgresql redis")

# Restart if needed (with approval)
for service, status in health.items():
    if status == 'failed':
        agent.propose_and_maybe_execute(
            command=f"systemctl restart {service}",
            requires_approval=True,
            approvers=["ops-team"]
        )
```

### Service Health Automation

```yaml
workflow: service-health-check
schedule: every_5_minutes

steps:
  - id: check_services
    action: exec
    command: |
      systemctl is-active nginx
      systemctl is-active postgresql
      systemctl is-active redis
      
  - id: analyze_failures
    action: conditional
    for_each: "{{check_services.failed}}"
    steps:
      - action: exec
        command: "journalctl -u {{item}} -n 50 --no-pager"
        
      - action: llm
        prompt: |
          Why did {{item}} fail?
          Logs: {{steps.journalctl.output}}
          Recommend: restart | investigate | escalate
        output: recommendation
        
      - action: conditional
        conditions:
          - if: "{{recommendation.action}} == 'restart'"
            action: exec
            command: "systemctl restart {{item}}"
            
          - if: "{{recommendation.action}} == 'escalate'"
            action: alert
            severity: critical
```

---

## Package Management

### apt/yum/dnf/pacman

```yaml
package_management:
  read:
    - "dpkg -l"                   # List packages
    - "apt list --installed"       # List installed
    - "apt search *"               # Search
    
  update_metadata:
    - "apt update"                 # Safe
    
  install:
    require_approval:
      - "apt install *"             # Installing packages
      - "pip install *"             # Python packages
      - "npm install *"             # Node packages
      
  upgrade:
    always_require_approval:
      - "apt upgrade"               # System upgrade
      - "apt dist-upgrade"          # Major upgrade
      
  remove:
    denied:
      - "apt remove *"              # Too dangerous
      - "apt purge *"               # Too dangerous
      - "pip uninstall *"
```

### Security Updates

```python
# Check for security updates
updates = agent.execute("apt list --upgradeable 2>/dev/null | grep -i security")

if updates:
    # Analyze impact
    impact = agent.analyze_updates(updates)
    
    # Auto-apply security patches (low risk)
    for update in impact.security_low_risk:
        agent.execute(f"apt install -y {update.package}")
    
    # Request approval for high-impact updates
    for update in impact.security_high_risk:
        agent.propose(
            action=f"install {update.package}",
            impact=update.restart_required,
            testing_recommended=True
        )
```

---

## Network Configuration

### Network Tools

```yaml
network_tools:
  diagnostic:
    allowed:
      - "ping -c 4 *"              # Connectivity
      - "traceroute *"             # Routing
      - "netstat -tuln"            # Listening ports
      - "ss -tuln"                 # Sockets
      - "ip addr"                  # Interfaces
      - "ip route"                 # Routes
      - "dig *"                    # DNS lookup
      - "nslookup *"               # DNS
      
  configuration:
    require_approval:
      - "ip addr add *"            # Add IP
      - "ip link set *"            # Interface config
      - "iptables *"               # Firewall
      - "nft *"                    # Firewall
      
    denied:
      - "iptables -F"              # Flush rules
      - "iptables -P * DROP"       # Default deny
```

### Network Troubleshooting

```python
# Automated network diagnosis
connectivity = agent.execute("ping -c 4 8.8.8.8")

dns = agent.execute("dig example.com +short")

routes = agent.execute("ip route get 8.8.8.8")

ports = agent.execute("ss -tuln | grep :443")

# AI diagnoses
if "100% packet loss" in connectivity:
    diagnosis = agent.analyze(
        connectivity=connectivity,
        routes=routes,
        "Network unreachable - checking gateway and routes"
    )
    
    # Propose fix
    agent.propose_fix(diagnosis)
```

---

## Disk and Storage Management

### Storage Operations

```yaml
storage_management:
  read:
    - "df -h"                     # Disk usage
    - "lsblk"                     # Block devices
    - "du -sh *"                  # Directory sizes
    - "mount"                     # Mounted filesystems
    
  maintenance:
    require_approval:
      - "fsck *"                  # Filesystem check
      - "resize2fs *"             # Resize
      - "lvextend *"              # Extend volume
      
  dangerous:
    denied:
      - "mkfs.*"                  # Format
      - "dd if=/dev/zero*"       # Wipe
      - "parted * rm *"          # Delete partition
```

### Disk Cleanup Automation

```python
# Find disk hogs
disk_usage = agent.execute("du -h /var/log /tmp /var/cache --max-depth=1 | sort -hr")

# Identify safe-to-delete items
cleanup_candidates = agent.analyze(
    disk_usage,
    rules=[
        "logs older than 30 days",
        "tmp files older than 7 days",
        "cache files"
    ]
)

# Safe cleanup (no approval needed)
for item in cleanup_candidates.safe:
    agent.execute(f"find {item.path} -type f -mtime +{item.max_age} -delete")

# Risky cleanup (requires approval)
for item in cleanup_candidates.risky:
    agent.propose(
        action=f"clean {item.path}",
        space_to_free=item.size,
        requires_approval=True
    )
```

---

## User and Permission Management

### Account Operations

```yaml
user_management:
  read:
    - "id *"                       # User info
    - "getent passwd"              # User list
    - "getent group"               # Group list
    - "last"                       # Login history
    - "w"                          # Active users
    
  write:
    require_approval:
      - "useradd *"                # Add user
      - "usermod *"                # Modify user
      - "passwd *"                 # Change password
      - "groupadd *"               # Add group
      
  dangerous:
    denied:
      - "userdel *"                # Delete user
      - "deluser *"                # Delete user
      - "chmod 777 *"              # World writable
      - "chown root:root *"        # Take ownership
```

---

## Monitoring and Metrics

### System Metrics Collection

```python
# Collect system metrics
metrics = {
    'cpu': agent.execute("top -bn1 | grep 'Cpu(s)'"),
    'memory': agent.execute("free -m"),
    'disk': agent.execute("df -h / /var /tmp"),
    'load': agent.execute("uptime"),
    'io': agent.execute("iostat -x 1 3"),
    'network': agent.execute("cat /proc/net/dev")
}

# AI analysis
trends = agent.analyze_trends(metrics, history_hours=24)

if trends.predict_disk_full_within(days=7):
    agent.propose_cleanup()

if trends.memory_pressure_detected:
    agent.propose_restart_or_scale_up()
```

---

## Command Safety Matrix

| Command Category | Examples | Approval Required | Risk Level |
|-----------------|----------|------------------|------------|
| Read-only info | ps, df, top, netstat | Never | None |
| Safe maintenance | apt update, systemctl status | Never | Low |
| Service restart | systemctl restart | If production | Medium |
| File modification | edit config, rm | Yes | Medium |
| Package install | apt install, pip install | Yes | Medium |
| Destructive | rm -rf, mkfs, userdel | Always + 2 approvers | Critical |
| System changes | iptables, network config | Yes | High |

---

## Best Practices

1. **Least privilege** — Agent runs as non-root with sudo for specific commands
2. **Dry run first** — Test destructive commands with `--dry-run`
3. **Approval chains** — Sensitive ops need multiple approvers
4. **Time windows** — Restrict maintenance to business hours
5. **Rollback ready** — Always have undo plan
6. **Audit everything** — Every command logged with 9 chains

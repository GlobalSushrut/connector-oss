# 69 — DevGuard Workflows: Building Real Execution Pipelines

> Building complete execution workflows on top of DevGuard. Safe dependency updates, automated refactoring, CI/CD integration, and multi-stage approval pipelines.

---

## Workflow 1: Safe Dependency Update

Automatically update dependencies with verification gates.

```yaml
# workflows/dependency_update.yaml
name: safe-dependency-update
description: "Update npm dependencies with tests and rollback"
triggers:
  - schedule: "0 2 * * 1"  # Mondays at 2 AM
  - webhook: "/hooks/dep-check"

steps:
  - id: check_updates
    action: exec
    command: "npm outdated --json"
    capture_output: true
    
  - id: analyze_risk
    action: llm
    model: claude-3-5-sonnet
    prompt: |
      Analyze these dependency updates for breaking changes:
      {{steps.check_updates.stdout}}
      
      Flag any major version changes or known risky packages.
    output: risk_analysis
    
  - id: approval_gate_major
    action: hitl
    condition: "{{risk_analysis.contains_major}}"
    approvers: ["tech-lead", "security-team"]
    timeout_minutes: 1440  # 24 hours
    
  - id: update_deps
    action: exec
    commands:
      - "npm update {{risk_analysis.safe_updates}}"
      - "npm audit fix"
    
  - id: verify_tests
    action: exec
    commands:
      - "npm run build"
      - "npm test"
      - "npm run lint"
    timeout_minutes: 30
    on_failure: rollback
    
  - id: commit_changes
    action: git
    commit_message: "chore(deps): update dependencies"
    branch: "deps/update-{{timestamp}}"
    
  - id: create_pr
    action: github
    create_pull_request:
      title: "Automated dependency updates"
      body: |
        Updates applied: {{steps.update_deps.packages}}
        Risk analysis: {{steps.analyze_risk.output}}
        
        Verification:
        - Build: {{steps.verify_tests.build_status}}
        - Tests: {{steps.verify_tests.test_status}}
        - Audit: {{steps.verify_tests.audit_status}}
      
governance:
  max_cost_usd: 10.0
  max_duration_minutes: 60
  required_approvers: 1
  audit_retention_days: 2555
```

---

## Workflow 2: Automated Refactoring

Large-scale code changes with safety checks.

```yaml
# workflows/refactor.yaml
name: automated-refactor
description: "Apply refactoring patterns across codebase"

parameters:
  - name: target_pattern
    type: string
    description: "Pattern to find (regex)"
    required: true
    
  - name: replacement
    type: string
    description: "Replacement pattern"
    required: true
    
  - name: test_pattern
    type: string
    description: "Test pattern to verify"
    default: "*.test.ts"

steps:
  - id: find_occurrences
    action: search
    pattern: "{{target_pattern}}"
    output: matches
    
  - id: analyze_impact
    action: llm
    model: claude-3-opus
    prompt: |
      Analyze the impact of replacing "{{target_pattern}}" with "{{replacement}}"
      in these files: {{steps.find_occurrences.matches}}
      
      Identify:
      1. Breaking changes
      2. Test files that need updating
      3. Edge cases
    output: impact_analysis
    
  - id: approval_required
    action: hitl
    condition: "{{impact_analysis.risk_level}} == 'high'"
    approvers: ["architect"]
    
  - id: apply_changes
    action: refactor
    pattern: "{{target_pattern}}"
    replacement: "{{replacement}}"
    files: "{{steps.find_occurrences.matches}}"
    dry_run: false
    
  - id: verify_compile
    action: exec
    command: "{{language.build_command}}"
    on_failure: stop
    
  - id: run_affected_tests
    action: exec
    command: "{{language.test_command}} {{test_pattern}}"
    
  - id: verify_no_regressions
    action: exec
    command: "{{language.test_command}}"
    on_failure: rollback
    
  - id: commit
    action: git
    commit_message: |
      refactor: replace {{target_pattern}} with {{replacement}}
      
      Files changed: {{steps.apply_changes.files_modified}}
      Tests updated: {{steps.apply_changes.tests_updated}}
governance:
  max_files_changed: 50
  require_tests_pass: true
  rollback_on_failure: true
```

---

## Workflow 3: Security Audit and Fix

Automated security scanning with governed remediation.

```yaml
# workflows/security_audit.yaml
name: security-audit-fix
description: "Scan and fix security issues"

triggers:
  - schedule: "0 0 * * *"  # Daily
  - event: "dependabot_alert"

steps:
  - id: scan_secrets
    action: exec
    command: "trufflehog filesystem . --json"
    continue_on_failure: true
    
  - id: scan_dependencies
    action: exec
    command: "npm audit --json"
    continue_on_failure: true
    
  - id: scan_vulnerabilities
    action: exec
    command: "snyk test --json"
    continue_on_failure: true
    
  - id: analyze_findings
    action: llm
    model: claude-3-5-sonnet
    prompt: |
      Analyze these security findings:
      Secrets: {{steps.scan_secrets.output}}
      Dependencies: {{steps.scan_dependencies.output}}
      Vulnerabilities: {{steps.scan_vulnerabilities.output}}
      
      For each finding:
      1. Severity (critical/high/medium/low)
      2. Can auto-fix?
      3. Recommended action
      4. Files to modify
    output: security_report
    
  - id: approval_critical
    action: hitl
    condition: "{{security_report.has_critical}}"
    approvers: ["security-team", "cto"]
    priority: p0
    
  - id: auto_fix_medium_low
    action: conditional
    condition: "{{security_report.fixable_auto}}"
    steps:
      - action: exec
        command: "npm audit fix"
        
      - action: llm
        prompt: |
          Apply these security fixes to the code:
          {{security_report.fixes}}
        
      - action: git
        commit_message: "security: auto-fix vulnerabilities"
        
  - id: notify_team
    action: webhook
    url: "${SECURITY_SLACK_WEBHOOK}"
    payload:
      text: "Security scan complete"
      findings: "{{security_report.summary}}"
      pr_url: "{{steps.create_pr.url}}"
```

---

## Workflow 4: Documentation Sync

Keep documentation in sync with code changes.

```yaml
# workflows/doc_sync.yaml
name: documentation-sync
description: "Update docs when code changes"

triggers:
  - event: "push"
    paths: ["src/**/*.ts", "!src/**/*.test.ts"]

steps:
  - id: get_changed_files
    action: git
    get_changed_files:
      since: "HEAD~1"
      
  - id: analyze_api_changes
    action: llm
    model: claude-3-5-sonnet
    prompt: |
      Analyze these changed files for API changes:
      {{steps.get_changed_files.ts_files}}
      
      Identify:
      1. New exported functions/classes
      2. Changed signatures
      3. Deprecated items
      4. Documentation needs
    output: api_changes
    
  - id: update_api_docs
    action: llm
    condition: "{{api_changes.has_api_changes}}"
    prompt: |
      Update API documentation at docs/api.md:
      
      Current docs: {{files.read('docs/api.md')}}
      API changes: {{api_changes}}
      
      Add/update entries for changed items.
    
  - id: update_changelog
    action: llm
    prompt: |
      Add entry to CHANGELOG.md for:
      {{api_changes.summary}}
      
  - id: verify_docs
    action: exec
    commands:
      - "npm run docs:build"
      - "npm run docs:check-links"
      
  - id: commit_docs
    action: git
    commit_message: "docs: sync with code changes"
    branch: "docs/sync-{{timestamp}}"
```

---

## CI/CD Integration

```yaml
# .github/workflows/connector-governed-ci.yaml
name: Connector Governed CI

on: [push, pull_request]

jobs:
  governed-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Start DevGuard Session
        id: devguard
        run: |
          SESSION=$(connectorctl guard start \
            --role ci \
            --workspace . \
            --json)
          echo "session_id=$(echo $SESSION | jq -r '.session_id')" >> $GITHUB_OUTPUT
          echo "agent_pid=$(echo $SESSION | jq -r '.agent_pid')" >> $GITHUB_OUTPUT
          
      - name: Run Governed Build
        env:
          CONNECTOR_SESSION: ${{ steps.devguard.outputs.session_id }}
        run: |
          connectorctl exec \
            --session ${{ steps.devguard.outputs.session_id }} \
            --command "npm ci"
            
          connectorctl exec \
            --session ${{ steps.devguard.outputs.session_id }} \
            --command "npm run build"
            
      - name: Run Governed Tests
        run: |
          connectorctl exec \
            --session ${{ steps.devguard.outputs.session_id }} \
            --command "npm test" \
            --timeout 600
            
      - name: Generate Compliance Proof
        if: always()
        run: |
          connectorctl guard proof \
            --session ${{ steps.devguard.outputs.session_id }} \
            --output proof-bundle.json
            
      - name: Upload Proof
        uses: actions/upload-artifact@v4
        with:
          name: compliance-proof
          path: proof-bundle.json
```

---

## Multi-Stage Approval Pipeline

```yaml
# workflows/multi-stage-deployment.yaml
name: production-deployment
description: "Deploy to production with approvals"

stages:
  - name: build
    steps:
      - action: exec
        command: "npm ci && npm run build"
        
  - name: test
    steps:
      - action: exec
        command: "npm test"
      - action: exec
        command: "npm run integration-test"
      - action: exec
        command: "npm run e2e-test"
        
  - name: security-scan
    steps:
      - action: exec
        command: "npm audit"
      - action: exec
        command: "snyk test"
      - action: exec
        command: "trivy fs ."
      
  - name: staging-deploy
    approval:
      required: false
    steps:
      - action: exec
        command: "deploy-to-staging.sh"
      - action: wait
        duration_minutes: 5
      - action: exec
        command: "smoke-tests-staging.sh"
      
  - name: production-approval
    approval:
      required: true
      approvers: ["tech-lead", "product-owner"]
      timeout_hours: 48
      reminder_hours: [12, 24, 36]
      
  - name: production-deploy
    steps:
      - action: exec
        command: "deploy-to-production.sh"
      - action: wait
        duration_minutes: 10
      - action: exec
        command: "smoke-tests-production.sh"
      - action: exec
        command: "verify-canaries.sh"
      
  - name: verify-deployment
    steps:
      - action: wait
        duration_minutes: 30
      - action: exec
        command: "verify-metrics.sh"
      - action: rollback
        condition: "{{metrics.error_rate}} > 0.01"
        target: staging
```

---

## Workflow Execution API

```bash
# Submit workflow
POST /api/v1/workflows/submit
{
  "workflow": "safe-dependency-update",
  "parameters": {
    "dry_run": false
  }
}

# Check status
GET /api/v1/workflows/exec_a3f7b2/status
Response:
{
  "status": "running",
  "current_step": "verify_tests",
  "completed_steps": ["check_updates", "analyze_risk", "update_deps"],
  "start_time": "2026-04-14T01:00:00Z",
  "estimated_completion": "2026-04-14T01:15:00Z"
}

# Get results
GET /api/v1/workflows/exec_a3f7b2/result
Response:
{
  "status": "completed",
  "success": true,
  "steps": [
    {
      "id": "check_updates",
      "status": "completed",
      "output": {"packages": 12}
    },
    {
      "id": "verify_tests",
      "status": "completed",
      "output": {"passed": 142, "failed": 0}
    }
  ],
  "audit_cid": "mem1-sha256-d4e8f1...",
  "proof_bundle": "soe1-sha256-..."
}

# List workflow runs
GET /api/v1/workflows?workflow=safe-dependency-update&limit=10
```

---

## Workflow Best Practices

### 1. Always Verify Before Commit

```yaml
steps:
  - id: make_changes
    action: exec
    commands: [...]
    
  - id: verify
    action: exec
    commands:
      - "npm test"
      - "npm run lint"
      - "npm run build"
    on_failure: rollback  # Critical: undo changes if verify fails
```

### 2. Progressive Approval

```yaml
# Low risk: auto
# Medium risk: team lead
# High risk: architect + security
approval:
  levels:
    - condition: "{{risk_score}} < 30"
      auto_approve: true
    - condition: "{{risk_score}} < 70"
      approvers: ["team-lead"]
    - condition: "{{risk_score}} >= 70"
      approvers: ["architect", "security-team"]
```

### 3. Rollback Strategy

```yaml
rollback:
  enabled: true
  trigger_conditions:
    - "tests_failed"
    - "error_rate > 0.01"
    - "manual_request"
  steps:
    - action: git
      command: "git revert HEAD"
    - action: exec
      command: "deploy-rollback.sh"
```

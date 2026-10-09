#!/bin/bash
# Demo 3 — 7 Most Dangerous Attacks Demo Runner
# Security demonstration proving why agents need Connector

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_env() {
    log_info "Checking Demo 3 environment..."
    [[ -z "${CONNECTOR_URL:-}" ]] && export CONNECTOR_URL="http://localhost:9091"
    [[ -z "${CONNECTOR_API_KEY:-}" ]] && { export CONNECTOR_API_KEY="dev-token"; export CONNECTOR_DEV_MODE=1; }
    export DEMO3_NAMESPACE="${DEMO3_NAMESPACE:-demo3/security}"
    log_success "Environment configured"
}

show_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    DEMO 3 — 7 MOST DANGEROUS ATTACKS                         ║"
    echo "║                    Security Proof Demonstration                              ║"
    echo "║                    \"Why You Cannot Run Agents Without Connector\"             ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  The 7 Attacks:"
    echo "    1. Prompt Injection → Tool Hijack"
    echo "    2. Memory Poisoning"
    echo "    3. Tool Escalation"
    echo "    4. Cost Explosion"
    echo "    5. Hallucinated Action"
    echo "    6. PII Exfiltration"
    echo "    7. Instruction Drift"
    echo ""
}

run_bootstrap() {
    log_info "Bootstrapping Demo 3 security agent..."
    cd "$DEMO_DIR/demo3"
    python3 attack_demo.py bootstrap
    log_success "Bootstrap complete"
}

run_preflight() {
    log_info "Running Demo 3 preflight..."
    cd "$DEMO_DIR/demo3"
    python3 attack_demo.py preflight
    log_success "Preflight complete"
}

run_demo() {
    log_info "Starting Demo 3 attack scenarios..."
    log_warn "⚠️  This demo sends real attack payloads to test defenses"
    echo ""
    
    cd "$DEMO_DIR/demo3"
    if [[ "${1:-}" == "--no-wait" ]]; then
        python3 attack_demo.py --no-wait
    else
        python3 attack_demo.py
    fi
}

export_evidence() {
    local export_dir="${DEMO3_EXPORT_DIR:-$DEMO_DIR/demo3/evidence}"
    mkdir -p "$export_dir"
    
    cat > "$export_dir/demo3_metadata.json" << EOF
{
  "demo_id": "demo3",
  "demo_name": "7 Most Dangerous Attacks",
  "run_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "namespace": "$DEMO3_NAMESPACE",
  "attacks": [
    {
      "id": 1,
      "name": "Prompt Injection → Tool Hijack",
      "defense": ["AgentFirewall", "SemanticInjectionDetector", "ContentGuard"]
    },
    {
      "id": 2,
      "name": "Memory Poisoning",
      "defense": ["Firewall memory write scoring", "HMAC chain", "CID integrity"]
    },
    {
      "id": 3,
      "name": "Tool Escalation",
      "defense": ["blocked_tools list", "PolicyEngine", "MAC guard"]
    },
    {
      "id": 4,
      "name": "Cost Explosion",
      "defense": ["Token budget enforcement", "BudgetGate", "kill switch"]
    },
    {
      "id": 5,
      "name": "Hallucinated Action",
      "defense": ["Receipt chain — no receipt = no truth"]
    },
    {
      "id": 6,
      "name": "PII Exfiltration",
      "defense": ["ContentGuard PII detector", "HIPAA compliance report"]
    },
    {
      "id": 7,
      "name": "Instruction Drift",
      "defense": ["BehaviorAnalyzer", "InstructionPlane schema validation"]
    }
  ],
  "evidence_layers": [
    "Exact payload sent",
    "Raw HTTP response",
    "Raw firewall inspect",
    "Raw journal entries",
    "Raw receipts / cost / compliance"
  ]
}
EOF
    log_success "Evidence exported to: $export_dir"
}

main() {
    show_header
    check_env
    
    case "${1:-run}" in
        bootstrap)
            run_bootstrap
            ;;
        preflight)
            run_preflight
            ;;
        run)
            run_preflight
            run_bootstrap
            run_demo "${2:-}"
            export_evidence
            ;;
        status)
            if [[ -f "$DEMO_DIR/demo3/.demo3-node.pid" ]]; then
                local pid=$(cat "$DEMO_DIR/demo3/.demo3-node.pid")
                if kill -0 "$pid" 2>/dev/null; then
                    log_success "Demo 3 node running (PID: $pid)"
                else
                    log_warn "PID file exists but process not running"
                fi
            else
                log_info "No Demo 3 PID file"
            fi
            ;;
        stop)
            if [[ -f "$DEMO_DIR/demo3/.demo3-node.pid" ]]; then
                local pid=$(cat "$DEMO_DIR/demo3/.demo3-node.pid")
                kill "$pid" 2>/dev/null || true
                rm -f "$DEMO_DIR/demo3/.demo3-node.pid"
                log_success "Stopped"
            fi
            ;;
        export)
            export_evidence
            ;;
        help|--help|-h)
            cat << 'HELP'
Demo 3 — 7 Most Dangerous Attacks

Usage: run_demo3.sh [command] [options]

Commands:
  bootstrap    - Bootstrap security agent
  preflight    - Run preflight checks  
  run          - Run full attack demo (default)
  status       - Check status
  stop         - Stop demo node
  export       - Export evidence
  help         - Show this help

Options:
  --no-wait    - Don't pause between attacks

Environment:
  DEEPSEEK_API_KEY     - LLM API key
  CONNECTOR_URL        - Connector endpoint
  DEMO3_NAMESPACE      - Namespace (default: demo3/security)
  DEMO3_EXPORT_DIR     - Evidence path

Attack Flow:
  1. Truth preamble
  2. Bootstrap + Preflight
  3. Attacks 1-3 → "Evidence, not logs"
  4. Attacks 4-5 → "Cost governance"
  5. Attacks 6-7 → Comparison table
  6. Forensic Proof
  7. Evidence bundle
HELP
            ;;
        *)
            log_error "Unknown command: $1"
            exit 1
            ;;
    esac
}

main "$@"

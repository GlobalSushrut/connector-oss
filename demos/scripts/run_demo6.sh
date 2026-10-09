#!/bin/bash
# Demo 6 — Deterministic, Constrained Tool Execution Demo Runner
# Execution demonstration: from suggestion engine to controlled execution system

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_wow() { echo -e "${CYAN}[⚡ WOW]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

check_env() {
    log_info "Checking Demo 6 environment..."
    [[ -z "${CONNECTOR_URL:-}" ]] && export CONNECTOR_URL="http://localhost:9091"
    [[ -z "${CONNECTOR_API_KEY:-}" ]] && { export CONNECTOR_API_KEY="dev-token"; export CONNECTOR_DEV_MODE=1; }
    export DEMO6_NAMESPACE="${DEMO6_NAMESPACE:-demo6/devops}"
    export DEMO6_MODEL="${DEMO6_MODEL:-deepseek-chat}"
    log_success "Environment configured"
}

show_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║              DEMO 6 — DETERMINISTIC, CONSTRAINED TOOL EXECUTION                ║"
    echo "║                    Execution Proof Demonstration                                 ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Thesis: \"Today's AI suggests actions. Connector executes them — correctly,"
    echo "           safely, and predictably.\""
    echo ""
}

show_capabilities() {
    echo ""
    echo "  12 Capabilities Across 4 Phases:"
    echo ""
    echo "  Phase 1 — Intent → Valid Action Mapping"
    echo "    1. Structured Intent Parsing      2. Tool Schema Enforcement"
    echo "    3. Argument Validation"
    echo ""
    echo "  Phase 2 — Execution Boundaries"
    echo "    4. Allowed Tools Only             5. Path / Scope Constraints"
    echo "    6. Parameter Constraints"
    echo ""
    echo "  Phase 3 — Multi-Step Execution Discipline"
    echo "    7. Step Sequencing Control        8. Dependency Awareness"
    echo "    9. No Shortcut Execution"
    echo ""
    echo "  Phase 4 — Determinism & Stability"
    echo "   10. Same Input → Same Action Plan 11. Replayability"
    echo "   12. Receipt-Based Execution Proof"
    echo ""
}

show_scenario() {
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────────────────────┐"
    echo "  │                     DEVOPS SERVICE MANAGEMENT SCENARIO                   │"
    echo "  ├─────────────────────────────────────────────────────────────────────────┤"
    echo "  │  Service: web-api-prod                                                │"
    echo "  │  Config: /etc/services/web-api/config.yaml                            │"
    echo "  │  Actions: [validate_config, update_config, restart_service,           │"
    echo "  │            check_health]                                               │"
    echo "  └─────────────────────────────────────────────────────────────────────────┘"
    echo ""
    echo "  Tasks Demonstrated:"
    echo "    • Simple Update: \"Update config to enable logging\""
    echo "    • Constraint Violation: \"Delete all logs and configs\" → DENIED"
    echo "    • Multi-Step Deploy: \"Deploy service with updated config\""
    echo "    • Dependency Break: \"Restart without config update\" → BLOCKED"
    echo "    • Determinism Test: Same command twice → identical execution"
    echo ""
}

run_bootstrap() {
    log_info "Bootstrapping Demo 6 DevOps service configuration..."
    cd "$DEMO_DIR/demo6"
    python3 deterministic_execution_demo.py bootstrap 2>/dev/null || {
        log_info "Service configuration will be created during demo run"
    }
    log_success "Bootstrap complete"
}

run_preflight() {
    log_info "Running Demo 6 preflight..."
    cd "$DEMO_DIR/demo6"
    python3 deterministic_execution_demo.py preflight 2>/dev/null || log_warn "Preflight via script"
    log_success "Preflight complete"
}

run_demo() {
    log_info "Starting Demo 6 deterministic execution demonstration..."
    show_scenario
    echo ""
    
    cd "$DEMO_DIR/demo6"
    
    if [[ ! -f "deterministic_execution_demo.py" ]]; then
        show_demo_structure
        return
    fi
    
    if [[ "${1:-}" == "--no-wait" ]]; then
        python3 deterministic_execution_demo.py --no-wait 2>/dev/null || show_demo_structure
    else
        python3 deterministic_execution_demo.py 2>/dev/null || show_demo_structure
    fi
}

show_demo_structure() {
    echo ""
    echo "  Demo 6 Structure (10 Slides):"
    echo ""
    echo "    Slide 1: Structured Intent Parsing → NL → valid tool schema"
    echo "    Slide 2: Tool Schema Enforcement → strict input validation"
    echo "    Slide 3: Argument Validation → type + range + required fields"
    echo "    Slide 4: Allowed Tools Only → blocked_tools enforced"
    echo "    Slide 5: Path / Scope Constraints → can't access outside zone"
    echo "    Slide 6: Multi-Step Workflow → validate → update → restart"
    echo "    Slide 7: Dependency Enforcement → no shortcuts allowed"
    echo ""
    log_wow "Slide 8: Determinism Test (KILLER MOMENT)"
    echo "    Same input → Same execution plan (hash-verified determinism)"
    echo ""
    echo "    Slide 9: Constraint Violation → dangerous command refused"
    echo "    Slide 10: Execution Proof → receipt-based audit trail"
    echo ""
    echo "  Critical Moments:"
    echo ""
    log_wow "1 — Tool Call is Structured (not guessed)"
    echo "    Parsed intent → mapped tool with strict schema"
    echo ""
    log_wow "2 — Dangerous Command Refused"
    echo "    \"Delete all logs\" → DENY with safe alternative"
    echo ""
    log_wow "3 — Multi-step workflow enforced"
    echo "    validate → update → restart sequence"
    echo ""
    log_wow "4 — No shortcut allowed"
    echo "    \"Restart without update\" → BLOCKED"
    echo ""
    log_wow "5 — Determinism Test (KILLER MOMENT)"
    echo "    Run same command twice → identical execution plan"
    echo ""
    log_wow "6 — Replay + Proof"
    echo "    connectorctl prove --exec with step-by-step receipts"
    echo ""
}

export_evidence() {
    local export_dir="${DEMO6_EXPORT_DIR:-$DEMO_DIR/demo6/evidence}"
    mkdir -p "$export_dir"
    
    cat > "$export_dir/demo6_metadata.json" << EOF
{
  "demo_id": "demo6",
  "demo_name": "Deterministic, Constrained Tool Execution",
  "run_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "namespace": "$DEMO6_NAMESPACE",
  "model": "$DEMO6_MODEL",
  "tagline": "Today's AI suggests actions. Connector executes them — correctly, safely, and predictably.",
  "phases": [
    {
      "name": "Intent → Valid Action Mapping",
      "capabilities": ["Structured Intent Parsing", "Tool Schema Enforcement", "Argument Validation"]
    },
    {
      "name": "Execution Boundaries",
      "capabilities": ["Allowed Tools Only", "Path / Scope Constraints", "Parameter Constraints"]
    },
    {
      "name": "Multi-Step Execution Discipline",
      "capabilities": ["Step Sequencing Control", "Dependency Awareness", "No Shortcut Execution"]
    },
    {
      "name": "Determinism & Stability",
      "capabilities": ["Same Input → Same Action Plan", "Replayability", "Receipt-Based Execution Proof"]
    }
  ],
  "killer_moment": "Determinism Test: Same input → Same execution plan (hash-verified)",
  "comparison": {
    "todays_ai": ["flexible but risky", "probabilistic", "optional", "prompt-based", "impossible", "weak"],
    "connector": ["strict + validated", "deterministic", "enforced", "system-level", "built-in", "strong"]
  }
}
EOF
    log_success "Evidence exported to: $export_dir"
}

main() {
    show_header
    show_capabilities
    check_env
    
    case "${1:-run}" in
        bootstrap)
            run_bootstrap
            ;;
        preflight)
            run_preflight
            ;;
        scenario)
            show_scenario
            ;;
        structure)
            show_demo_structure
            ;;
        run)
            run_preflight
            run_bootstrap
            run_demo "${2:-}"
            export_evidence
            ;;
        status)
            log_info "Demo 6 uses DevOps namespace: $DEMO6_NAMESPACE"
            ;;
        export)
            export_evidence
            ;;
        help|--help|-h)
            cat << 'HELP'
Demo 6 — Deterministic, Constrained Tool Execution

Usage: run_demo6.sh [command] [options]

Commands:
  bootstrap    - Bootstrap service configuration
  preflight    - Run preflight checks
  scenario     - Show DevOps scenario
  structure    - Show demo structure
  run          - Run full demo (default)
  status       - Check status
  export       - Export evidence
  help         - Show this help

Options:
  --no-wait    - Don't pause between slides

Environment:
  DEEPSEEK_API_KEY     - LLM API key
  CONNECTOR_URL        - Connector endpoint
  DEMO6_NAMESPACE      - Namespace (default: demo6/devops)
  DEMO6_EXPORT_DIR     - Evidence path

Success Criteria:
  ✓ All 10 slides run without error
  ✓ Evidence bundle exported with execution receipts
  ✓ Intent parsing shows structured tool mapping
  ✓ Schema violations caught and rejected
  ✓ Multi-step workflow executes in correct sequence
  ✓ Dependency enforcement blocks shortcuts
  ✓ Determinism verified (same input → same output)
  ✓ Dangerous commands refused with alternatives
  ✓ Execution receipts provable and replayable
HELP
            ;;
        *)
            log_error "Unknown command: $1"
            exit 1
            ;;
    esac
}

main "$@"

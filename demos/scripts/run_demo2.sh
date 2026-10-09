#!/bin/bash
# Demo 2 — Governed Coding Workflow Demo Runner
# Agent control plane demonstration with Claude Code + DeepSeek

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEMO_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Environment check
check_env() {
    log_info "Checking Demo 2 environment..."
    
    [[ -z "${CONNECTOR_URL:-}" ]] && export CONNECTOR_URL="http://localhost:9091"
    [[ -z "${CONNECTOR_API_KEY:-}" ]] && { export CONNECTOR_API_KEY="dev-token"; export CONNECTOR_DEV_MODE=1; }
    
    # Check for DeepSeek API key
    if [[ -z "${DEEPSEEK_API_KEY:-}" && -z "${CONNECTOR_LLM_API_KEY:-}" ]]; then
        log_warn "No LLM API key found. Set DEEPSEEK_API_KEY or CONNECTOR_LLM_API_KEY"
    fi
    
    # Default settings
    export DEMO2_PROVIDER="${DEMO2_PROVIDER:-deepseek}"
    export DEMO2_UPSTREAM="${DEMO2_UPSTREAM:-deepseek}"
    export DEMO2_MODEL="${DEMO2_MODEL:-deepseek-chat}"
    
    log_success "Environment configured"
    log_info "Provider: $DEMO2_PROVIDER"
    log_info "Model: $DEMO2_MODEL"
}

show_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                     DEMO 2 — GOVERNED CODING WORKFLOW                        ║"
    echo "║                    Agent Control Plane Demonstration                         ║"
    echo "║                      (Claude Code + Connector + DeepSeek)                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
}

run_bootstrap() {
    log_info "Bootstrapping Demo 2 agent and namespace..."
    cd "$DEMO_DIR/demo2"
    
    # Run bootstrap and capture exports
    local bootstrap_output
    bootstrap_output=$(python3 workflow_demo.py bootstrap 2>&1)
    echo "$bootstrap_output"
    
    # Extract and export key variables
    if echo "$bootstrap_output" | grep -q "DEMO2_AGENT_PID"; then
        export DEMO2_AGENT_PID=$(echo "$bootstrap_output" | grep "DEMO2_AGENT_PID=" | tail -1 | cut -d'=' -f2 | tr -d '"')
        export DEMO2_NAMESPACE=$(echo "$bootstrap_output" | grep "DEMO2_NAMESPACE=" | tail -1 | cut -d'=' -f2 | tr -d '"')
        log_success "Agent PID: $DEMO2_AGENT_PID"
        log_success "Namespace: $DEMO2_NAMESPACE"
    fi
}

run_preflight() {
    log_info "Running Demo 2 preflight..."
    cd "$DEMO_DIR/demo2"
    python3 workflow_demo.py preflight
    log_success "Preflight complete"
}

run_demo() {
    log_info "Starting Demo 2 workflow demonstration..."
    cd "$DEMO_DIR/demo2"
    
    if [[ "${1:-}" == "--no-wait" ]]; then
        python3 workflow_demo.py --no-wait
    else
        python3 workflow_demo.py
    fi
}

export_evidence() {
    local export_dir="${DEMO2_EXPORT_DIR:-$DEMO_DIR/demo2/evidence}"
    mkdir -p "$export_dir"
    
    cat > "$export_dir/demo2_metadata.json" << EOF
{
  "demo_id": "demo2",
  "demo_name": "Governed Coding Workflow",
  "run_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "provider": "$DEMO2_PROVIDER",
  "model": "$DEMO2_MODEL",
  "workflow_moments": [
    "Preflight + Claude Code Shell Posture",
    "Safe Governed Success",
    "Boundary Deny + Safe Alternative",
    "Conditional Review Path",
    "Operator Proof Retrieval"
  ],
  "live_api": [
    "health",
    "gateway models",
    "CLS compile",
    "agent + memory",
    "governed chat completions",
    "decision recording",
    "audit receipts",
    "traces",
    "surfaces",
    "recall"
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
            if [[ -f "$DEMO_DIR/demo2/.demo2-node.pid" ]]; then
                local pid=$(cat "$DEMO_DIR/demo2/.demo2-node.pid")
                if kill -0 "$pid" 2>/dev/null; then
                    log_success "Demo 2 node running (PID: $pid)"
                else
                    log_warn "Demo 2 node PID file exists but process not running"
                fi
            else
                log_info "No Demo 2 PID file found"
            fi
            ;;
        stop)
            if [[ -f "$DEMO_DIR/demo2/.demo2-node.pid" ]]; then
                local pid=$(cat "$DEMO_DIR/demo2/.demo2-node.pid")
                log_info "Stopping Demo 2 node (PID: $pid)..."
                kill "$pid" 2>/dev/null || true
                rm -f "$DEMO_DIR/demo2/.demo2-node.pid"
                log_success "Demo 2 node stopped"
            fi
            ;;
        export)
            export_evidence
            ;;
        help|--help|-h)
            echo "Demo 2 — Governed Coding Workflow"
            echo ""
            echo "Usage: $0 [command] [options]"
            echo ""
            echo "Commands:"
            echo "  bootstrap    - Bootstrap agent and namespace"
            echo "  preflight    - Run preflight checks"
            echo "  run          - Run full demo (default)"
            echo "  status       - Check demo status"
            echo "  stop         - Stop demo node"
            echo "  export       - Export evidence"
            echo "  help         - Show this help"
            echo ""
            echo "Environment Variables:"
            echo "  DEEPSEEK_API_KEY        - Required for LLM calls"
            echo "  CONNECTOR_URL           - Connector API endpoint"
            echo "  DEMO2_PROVIDER          - LLM provider (default: deepseek)"
            echo "  DEMO2_MODEL             - Model name (default: deepseek-chat)"
            echo "  DEMO2_EXPORT_DIR        - Evidence export path"
            ;;
        *)
            log_error "Unknown command: $1"
            exit 1
            ;;
    esac
}

main "$@"

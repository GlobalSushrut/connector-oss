#!/bin/bash
# Demo 1 — Enterprise Governance Demo Runner
# Live runtime proof of Connector's enterprise governance capabilities

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEMO_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check environment
check_env() {
    log_info "Checking Demo 1 environment..."
    
    if [[ -z "${CONNECTOR_URL:-}" ]]; then
        export CONNECTOR_URL="http://localhost:9091"
        log_warn "CONNECTOR_URL not set, using default: $CONNECTOR_URL"
    fi
    
    if [[ -z "${CONNECTOR_API_KEY:-}" ]]; then
        export CONNECTOR_API_KEY="dev-token"
        export CONNECTOR_DEV_MODE=1
        log_warn "CONNECTOR_API_KEY not set, using dev mode"
    fi
    
    log_success "Environment check passed"
}

# Show demo header
show_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        DEMO 1 — ENTERPRISE GOVERNANCE                        ║"
    echo "║                         Live Runtime Proof Demo                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    log_info "Connector URL: $CONNECTOR_URL"
    log_info "Demo Directory: $DEMO_DIR"
    echo ""
}

# Run bootstrap
run_bootstrap() {
    log_info "Bootstrapping Demo 1 state..."
    cd "$DEMO_DIR"
    python3 demo.py bootstrap
    log_success "Bootstrap complete"
}

# Run the demo
run_demo() {
    log_info "Starting Demo 1 interactive slide deck..."
    log_info "Press Enter to advance between slides"
    echo ""
    
    cd "$DEMO_DIR"
    if [[ "${1:-}" == "--no-wait" ]]; then
        python3 demo.py --no-wait
    else
        python3 demo.py
    fi
}

# Export evidence
export_evidence() {
    log_info "Exporting Demo 1 evidence bundle..."
    
    local export_dir="${DEMO1_EXPORT_DIR:-$DEMO_DIR/evidence}"
    mkdir -p "$export_dir"
    
    # Create evidence bundle metadata
    cat > "$export_dir/demo1_metadata.json" << EOF
{
  "demo_id": "demo1",
  "demo_name": "Enterprise Governance",
  "run_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "connector_url": "$CONNECTOR_URL",
  "version": "1.0.0",
  "slides": [
    "Live Runtime Contract",
    "Buyer Boundary",
    "Claim Posture",
    "Live Decision Path",
    "Boundary Enforcement",
    "Tool Governance",
    "Operator Explain + Trace",
    "Evidence + Proof",
    "Cost + Compliance",
    "Failure + Recovery + HITL",
    "Pilot Close"
  ]
}
EOF
    
    log_success "Evidence exported to: $export_dir"
}

# Main execution
main() {
    show_header
    check_env
    
    case "${1:-run}" in
        bootstrap)
            run_bootstrap
            ;;
        run)
            run_bootstrap
            run_demo "${2:-}"
            export_evidence
            ;;
        preflight)
            log_info "Running Demo 1 preflight checks..."
            cd "$DEMO_DIR"
            python3 -c "from system_data import ConnectorPlatform; p = ConnectorPlatform(); print('Health:', p.health_check())"
            log_success "Preflight complete"
            ;;
        status)
            log_info "Demo 1 status: $(date)"
            cd "$DEMO_DIR"
            python3 -c "from system_data import ConnectorPlatform; p = ConnectorPlatform(); print('Agents:', len(p.list_agents().get('agents', [])))"
            ;;
        export)
            export_evidence
            ;;
        help|--help|-h)
            echo "Usage: $0 [command] [options]"
            echo ""
            echo "Commands:"
            echo "  bootstrap    - Seed live agent and memory state"
            echo "  run          - Run full interactive demo (default)"
            echo "  preflight    - Check environment and connectivity"
            echo "  status       - Show demo status"
            echo "  export       - Export evidence bundle"
            echo "  help         - Show this help"
            echo ""
            echo "Options:"
            echo "  --no-wait    - Run without pausing between slides"
            echo ""
            ;;
        *)
            log_error "Unknown command: $1"
            echo "Run '$0 help' for usage"
            exit 1
            ;;
    esac
}

main "$@"

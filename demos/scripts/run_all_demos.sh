#!/bin/bash
# Master script to run all Connector demos (Demo 1-6)
# Usage: ./run_all_demos.sh [command] [demo_number]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEMO_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() { echo -e "\n${BOLD}${CYAN}$1${NC}\n"; }

# Demo definitions
DEMOS=(
    "1:Enterprise Governance:demo1:Enterprise governance live runtime proof"
    "2:Governed Coding Workflow:demo2:Agent control plane (Claude Code + DeepSeek)"
    "3:7 Most Dangerous Attacks:demo3:Security proof - why agents need Connector"
    "4:Stable Thinking Engine:demo4:Cognitive governance and reasoning stability"
    "5:Selective Context:demo5:Privacy - precision without exposure"
    "6:Deterministic Execution:demo6:From suggestion engine to controlled execution"
)

show_header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    CONNECTOR DEMO SUITE — ALL 6 DEMOS                        ║"
    echo "║                    Run, Export & Document Demonstrations                     ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Available Demos:"
    for demo in "${DEMOS[@]}"; do
        IFS=':' read -r num name slug desc <<< "$demo"
        printf "  Demo %-2s │ %-30s │ %s\n" "$num" "$name" "$desc"
    done
    echo ""
}

show_help() {
    cat << 'HELP'
Usage: run_all_demos.sh [command] [demo_number] [options]

Commands:
  list              - List all available demos
  run [n]           - Run demo(s) - all demos or specific demo number
  preflight [n]     - Run preflight checks
  bootstrap [n]     - Bootstrap demo state
  export [n]        - Export evidence bundles
  status            - Check status of all demos
  stop              - Stop all demo nodes
  summary           - Show demo portfolio summary
  help              - Show this help

Examples:
  ./run_all_demos.sh list                    # List demos
  ./run_all_demos.sh run                     # Run all demos
  ./run_all_demos.sh run 3                   # Run Demo 3 only
  ./run_all_demos.sh preflight               # Preflight all demos
  ./run_all_demos.sh export                  # Export all evidence
  ./run_all_demos.sh run 5 --no-wait         # Run Demo 5 without pauses

Environment:
  CONNECTOR_URL          - Connector API endpoint (default: http://localhost:9091)
  CONNECTOR_API_KEY      - API key (default: dev-token in dev mode)
  DEEPSEEK_API_KEY       - Required for demos using LLM calls
  CONNECTOR_DEV_MODE     - Enable dev mode (skips some validations)

Demo Portfolio:
  Safe (Demo 3) → Stable (Demo 4) → Private (Demo 5) → Executable (Demo 6)
HELP
}

list_demos() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                         CONNECTOR DEMO PORTFOLIO                             ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    printf "│ %-4s │ %-30s │ %-50s │\n" "Demo" "Name" "Focus"
    echo "├──────┼────────────────────────────────┼────────────────────────────────────────────────────┤"
    
    printf "│ %-4s │ %-30s │ %-50s │\n" \
        "1" "Enterprise Governance" "Live runtime proof of enterprise capabilities"
    printf "│ %-4s │ %-30s │ %-50s │\n" \
        "2" "Governed Coding Workflow" "Agent control plane with Claude Code + DeepSeek"
    printf "│ %-4s │ %-30s │ %-50s │\n" \
        "3" "7 Most Dangerous Attacks" "Security: why you cannot run agents without Connector"
    printf "│ %-4s │ %-30s │ %-50s │\n" \
        "4" "Stable Thinking Engine" "Cognitive governance: memory stability, reasoning"
    printf "│ %-4s │ %-30s │ %-50s │\n" \
        "5" "Selective Context" "Privacy: precision without exposure"
    printf "│ %-4s │ %-30s │ %-50s │\n" \
        "6" "Deterministic Execution" "From suggestion engine to controlled execution"
    
    echo ""
    echo "Full Picture: Safe → Stable → Private → Executable"
    echo ""
}

run_demo() {
    local num=$1
    local extra_args="${2:-}"
    local script="$SCRIPT_DIR/run_demo${num}.sh"
    
    if [[ ! -f "$script" ]]; then
        log_error "Demo $num script not found: $script"
        return 1
    fi
    
    log_section "Running Demo $num"
    chmod +x "$script"
    "$script" run "$extra_args" || log_warn "Demo $num completed with warnings"
}

run_all() {
    local extra_args="${1:-}"
    log_section "Running All Demos"
    
    for i in {1..6}; do
        run_demo "$i" "$extra_args" || true
        echo ""
        echo "────────────────────────────────────────────────────────────────────────────────"
        echo ""
    done
    
    log_success "All demos completed!"
}

run_preflight() {
    local target="${1:-all}"
    log_section "Running Preflight Checks"
    
    if [[ "$target" == "all" ]]; then
        for i in {1..6}; do
            local script="$SCRIPT_DIR/run_demo${i}.sh"
            [[ -f "$script" ]] && { chmod +x "$script"; "$script" preflight || true; }
        done
    else
        local script="$SCRIPT_DIR/run_demo${target}.sh"
        [[ -f "$script" ]] && { chmod +x "$script"; "$script" preflight; }
    fi
}

run_bootstrap() {
    local target="${1:-all}"
    log_section "Running Bootstrap"
    
    if [[ "$target" == "all" ]]; then
        for i in {1..6}; do
            local script="$SCRIPT_DIR/run_demo${i}.sh"
            [[ -f "$script" ]] && { chmod +x "$script"; "$script" bootstrap || true; }
        done
    else
        local script="$SCRIPT_DIR/run_demo${target}.sh"
        [[ -f "$script" ]] && { chmod +x "$script"; "$script" bootstrap; }
    fi
}

export_all() {
    local target="${1:-all}"
    log_section "Exporting Evidence Bundles"
    
    if [[ "$target" == "all" ]]; then
        for i in {1..6}; do
            local script="$SCRIPT_DIR/run_demo${i}.sh"
            [[ -f "$script" ]] && { chmod +x "$script"; "$script" export || true; }
        done
    else
        local script="$SCRIPT_DIR/run_demo${target}.sh"
        [[ -f "$script" ]] && { chmod +x "$script"; "$script" export; }
    fi
    
    log_success "Evidence exported to demo*/evidence/ directories"
}

show_status() {
    log_section "Demo Status Summary"
    
    for i in {1..6}; do
        local demo_dir="$DEMO_DIR/demo$i"
        local pid_file="$demo_dir/.demo${i}-node.pid"
        local evidence_dir="$demo_dir/evidence"
        
        printf "Demo %d: " "$i"
        
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file" 2>/dev/null || echo "unknown")
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "${GREEN}Running${NC} (PID: $pid)"
            else
                echo -e "${YELLOW}Stopped${NC} (stale PID file)"
            fi
        else
            echo -e "${YELLOW}Not started${NC}"
        fi
        
        if [[ -d "$evidence_dir" ]]; then
            local count=$(find "$evidence_dir" -name "*.json" 2>/dev/null | wc -l)
            echo "        Evidence files: $count"
        fi
    done
}

stop_all() {
    log_section "Stopping All Demo Nodes"
    
    for i in {1..6}; do
        local pid_file="$DEMO_DIR/demo$i/.demo${i}-node.pid"
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file" 2>/dev/null || true)
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                log_info "Stopping Demo $i node (PID: $pid)..."
                kill "$pid" 2>/dev/null || true
                rm -f "$pid_file"
                log_success "Demo $i stopped"
            else
                rm -f "$pid_file"
            fi
        fi
    done
    
    log_success "All demo nodes stopped"
}

show_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    CONNECTOR DEMO SUITE SUMMARY                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Each demo proves a different aspect of the Connector platform:"
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────────────────────┐"
    echo "  │ Demo 1: Enterprise Governance                                            │"
    echo "  │   • 11-slide enterprise demo                                             │"
    echo "  │   • Live runtime contract, buyer boundary, claim posture                 │"
    echo "  │   • Dual-proof: buyer-facing + operator-facing                           │"
    echo "  ├─────────────────────────────────────────────────────────────────────────┤"
    echo "  │ Demo 2: Governed Coding Workflow                                         │"
    echo "  │   • Claude Code + Connector + DeepSeek                                   │"
    echo "  │   • 5 workflow moments: safe allow, deny + substitute, review pause       │"
    echo "  │   • Proto Agent OS / control plane narrative                             │"
    echo "  ├─────────────────────────────────────────────────────────────────────────┤"
    echo "  │ Demo 3: 7 Most Dangerous Attacks                                         │"
    echo "  │   • Prompt injection, memory poisoning, tool escalation                  │"
    echo "  │   • Cost explosion, hallucinated action, PII exfiltration                │"
    echo "  │   • Instruction drift + forensic proof                                     │"
    echo "  ├─────────────────────────────────────────────────────────────────────────┤"
    echo "  │ Demo 4: Stable Thinking Engine                                           │"
    echo "  │   • Memory stability (30+ packets), contradiction detection              │"
    echo "  │   • Instruction fidelity, reasoning consistency                          │"
    echo "  │   • Dehallucination, deterministic behavior                            │"
    echo "  ├─────────────────────────────────────────────────────────────────────────┤"
    echo "  │ Demo 5: Selective Context + Identity-Aware Execution                     │"
    echo "  │   • Zero PHI in LLM context, provable data minimization                  │"
    echo "  │   • RAW LLM payload proof with cryptographic verification                │"
    echo "  │   • Identity-aware execution: LLM never knew WHO, system knew WHAT     │"
    echo "  ├─────────────────────────────────────────────────────────────────────────┤"
    echo "  │ Demo 6: Deterministic, Constrained Tool Execution                        │"
    echo "  │   • 12 capabilities across 4 phases                                      │"
    echo "  │   • Intent parsing, execution boundaries, multi-step discipline          │"
    echo "  │   • Determinism: same input → same execution plan (hash-verified)        │"
    echo "  └─────────────────────────────────────────────────────────────────────────┘"
    echo ""
    echo "  Full Picture: Safe → Stable → Private → Executable"
    echo ""
    echo "  Quick Start:"
    echo "    make demo1          # Run enterprise governance demo"
    echo "    make demo2          # Run coding workflow demo"
    echo "    make demo3          # Run security attacks demo"
    echo "    make demo4          # Run stability demo"
    echo "    make demo5          # Run privacy demo"
    echo "    make demo6          # Run execution demo"
    echo ""
}

# Main execution
main() {
    show_header
    
    # Make all scripts executable
    chmod +x "$SCRIPT_DIR"/run_demo*.sh 2>/dev/null || true
    
    local cmd="${1:-help}"
    local target="${2:-all}"
    local extra_args="${3:-}"
    
    case "$cmd" in
        list)
            list_demos
            ;;
        run)
            if [[ "$target" == "all" ]]; then
                run_all "$extra_args"
            else
                run_demo "$target" "$extra_args"
            fi
            ;;
        preflight)
            run_preflight "$target"
            ;;
        bootstrap)
            run_bootstrap "$target"
            ;;
        export)
            export_all "$target"
            ;;
        status)
            show_status
            ;;
        stop)
            stop_all
            ;;
        summary)
            show_summary
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $cmd"
            show_help
            exit 1
            ;;
    esac
}

main "$@"

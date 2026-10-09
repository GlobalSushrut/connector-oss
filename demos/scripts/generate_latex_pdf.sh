#!/bin/bash
# Generate LaTeX PDF documentation for all 6 Connector demos

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$DEMO_DIR")"
LATEX_DIR="$DEMO_DIR/latex"
OUTPUT_DIR="$DEMO_DIR/docs"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check for LaTeX installation
check_latex() {
    if ! command -v pdflatex &> /dev/null; then
        log_error "pdflatex not found. Please install TeX Live:"
        log_info "  sudo apt-get install texlive-full"
        log_info "  or: sudo apt-get install texlive-latex-extra texlive-fonts-recommended"
        exit 1
    fi
    
    log_success "LaTeX installation found"
}

# Create directory structure
setup_dirs() {
    mkdir -p "$LATEX_DIR"
    mkdir -p "$OUTPUT_DIR"
    log_success "Created directories: $LATEX_DIR, $OUTPUT_DIR"
}

# Generate the main LaTeX document
generate_latex() {
    log_info "Generating LaTeX document..."
    
    cat > "$LATEX_DIR/connector_demos.tex" << 'EOF'
\documentclass[11pt,a4paper]{article}

% Packages
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{lmodern}
\usepackage[margin=1in]{geometry}
\usepackage{graphicx}
\usepackage{xcolor}
\usepackage{tikz}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{multirow}
\usepackage{enumitem}
\usepackage{fancyhdr}
\usepackage{titlesec}
\usepackage{hyperref}
\usepackage{listings}
\usepackage{fancybox}
\usepackage{colortbl}

% Define colors
\definecolor{connectorgreen}{RGB}{0, 128, 128}
\definecolor{connectoryellow}{RGB}{255, 193, 7}
\definecolor{connectorred}{RGB}{220, 53, 69}
\definecolor{connectorblue}{RGB}{0, 123, 255}
\definecolor{lightgray}{RGB}{248, 249, 250}
\definecolor{darkgray}{RGB}{52, 58, 64}

% Hyperref setup
\hypersetup{
    colorlinks=true,
    linkcolor=connectorgreen,
    urlcolor=connectorblue,
    citecolor=darkgray
}

% Header/Footer
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\textcolor{connectorgreen}{\textbf{Connector Demo Suite}}}
\fancyhead[R]{\textcolor{darkgray}{Demos 1--6}}
\fancyfoot[C]{\thepage}
\renewcommand{\headrulewidth}{0.5pt}
\renewcommand{\footrulewidth}{0.3pt}

% Section formatting
\titleformat{\section}
    {\Large\bfseries\color{connectorgreen}}
    {Demo \thesection:}{0.5em}{}
\titleformat{\subsection}
    {\large\bfseries\color{darkgray}}
    {\thesubsection}{0.5em}{}

% Custom box
\newcommand{\demobox}[2]{%
    \begin{center}
    \fcolorbox{connectorgreen}{lightgray}{%
        \parbox{0.9\textwidth}{%
            \vspace{0.5em}
            \textbf{\textcolor{connectorgreen}{#1}}\\[0.5em]
            #2
            \vspace{0.5em}
        }%
    }
    \end{center}
}

\newcommand{\wowmoment}[1]{%
    \begin{center}
    \fcolorbox{connectoryellow}{white}{%
        \parbox{0.9\textwidth}{%
            \vspace{0.3em}
            \centering
            \textbf{\textcolor{connectoryellow}{⚡ WOW Moment}}\\[0.3em]
            #1
            \vspace{0.3em}
        }%
    }
    \end{center}
}

\newcommand{\killerline}[1]{%
    \begin{center}
    \fcolorbox{connectorred}{white}{%
        \parbox{0.9\textwidth}{%
            \vspace{0.3em}
            \centering
            \textbf{\textcolor{connectorred}{★ KILLER MOMENT}}\\[0.3em]
            #1
            \vspace{0.3em}
        }%
    }
    \end{center}
}

% Listings style
\lstset{
    basicstyle=\ttfamily\small,
    backgroundcolor=\color{lightgray},
    frame=single,
    framerule=0pt,
    breaklines=true,
    showstringspaces=false
}

\begin{document}

% Title Page
\begin{titlepage}
\centering
\vspace*{2cm}

{\Huge\bfseries\textcolor{connectorgreen}{Connector}}\\[0.5cm]
{\LARGE Demo Suite Documentation}\\[2cm]

\begin{tikzpicture}
    \draw[connectorgreen, line width=2pt] (0,0) -- (10,0);
\end{tikzpicture}

\vspace{1.5cm}

{\Large\textbf{Six Demonstrations of Enterprise AI Governance}}\\[1cm]

\begin{tabular}{cl}
\toprule
\textbf{Demo} & \textbf{Focus} \\
\midrule
1 & Enterprise Governance \\
2 & Governed Coding Workflow \\
3 & 7 Most Dangerous Attacks \\
4 & Stable Thinking Engine \\
5 & Selective Context + Identity-Aware \\
6 & Deterministic Tool Execution \\
\bottomrule
\end{tabular}

\vspace{2cm}

\demobox{Narrative Arc}{%
\textbf{Safe} (Demo 3) $\rightarrow$ \textbf{Stable} (Demo 4) \\
$\rightarrow$ \textbf{Private} (Demo 5) $\rightarrow$ \textbf{Executable} (Demo 6)
}

\vfill

{\large Version 1.0}\\
{\large \today}

\end{titlepage}

% Table of Contents
\tableofcontents
\newpage

% Introduction
\section*{Introduction}
\addcontentsline{toc}{section}{Introduction}

The Connector Demo Suite comprises six interconnected demonstrations that showcase the full capabilities of the Connector platform for enterprise AI governance. Each demo focuses on a specific aspect while building upon the narrative of safe, stable, private, and executable AI systems.

\demobox{Demo Contract}{%
Every demo follows strict integrity rules:
\begin{itemize}[nosep]
    \item No fake IDs
    \item No fake receipts
    \item No mocked journal chains
    \item No silent fallback on missing auth
    \item Stop immediately if health/receipts/runtime IDs are missing
    \item Every claim marked: proven\_live, partial\_live, not\_proven\_live, or stub\_mode
\end{itemize}
}

\newpage

% Demo 1
\section{Enterprise Governance}

\subsection{Overview}
\textbf{Thesis:} Live runtime proof of Connector's enterprise governance capabilities.

The canonical enterprise demo is a \textbf{dual-proof demonstration} that shows both buyer-facing and operator-facing evidence. It proves where Connector sits, what remains unchanged, what Connector governs, and which product claims are proven live.

\subsection{11-Slide Structure}

\begin{enumerate}
    \item \textbf{Live Runtime Contract} -- What the running node guarantees
    \item \textbf{Buyer Boundary} -- Where Connector sits in the stack
    \item \textbf{Claim Posture} -- Explicit proven/unproven claims
    \item \textbf{Live Decision Path} -- End-to-end governed decision flow
    \item \textbf{Boundary Enforcement} -- Policy-driven allow/deny
    \item \textbf{Tool Governance} -- Blocked/allowed tools enforcement
    \item \textbf{Operator Explain + Trace} -- Evidence retrieval commands
    \item \textbf{Evidence + Proof} -- HMAC-chained audit trail
    \item \textbf{Cost + Compliance} -- Token budgets, HIPAA tracking
    \item \textbf{Failure + Recovery + HITL} -- Escalation and review queues
    \item \textbf{Pilot Close} -- Summary and next steps
\end{enumerate}

\subsection{Key Claims Proven}

\begin{itemize}
    \item \textbf{Governance:} Policy engine with deny-overrides
    \item \textbf{Audit:} HMAC-chained receipts with CID references
    \item \textbf{Cost Control:} Token budgets with kill switches
    \item \textbf{Compliance:} HIPAA/GDPR framework support
    \item \textbf{Human-in-the-Loop:} Review queues for low-confidence decisions
\end{itemize}

\newpage

% Demo 2
\section{Governed Coding Workflow}

\subsection{Overview}
\textbf{Thesis:} Claude Code + Connector gateway + DeepSeek in an agentic control plane narrative.

This demo presents a calm, bounded, operator-led workflow instead of a freeform live-agent show. It demonstrates the proto Agent OS / control plane architecture that enterprise teams require.

\subsection{Workflow Moments}

\begin{enumerate}
    \item \textbf{Preflight + Claude Code Shell Posture} -- Establish governed environment
    \item \textbf{Safe Governed Success} -- Normal operation through Connector gateway
    \item \textbf{Boundary Deny + Safe Alternative} -- Policy blocks with substitutes
    \item \textbf{Conditional Review Path} -- Human-in-the-loop for edge cases
    \item \textbf{Operator Proof Retrieval} -- Evidence commands and traces
\end{enumerate}

\subsection{Live vs Orchestrated}

\begin{tabular}{lll}
\toprule
\textbf{Component} & \textbf{Type} & \textbf{Description} \\
\midrule
Health, Gateway & LIVE & Connector API endpoints \\
CLS Compile & LIVE & Contract language compilation \\
Agent + Memory & LIVE & Runtime lifecycle \\
Governed Completions & LIVE & Firewall + guard pipeline \\
Decision Recording & LIVE & Audit receipts \\
Path Allow/Deny & ORCHESTRATED & Demo policy evaluation \\
Safe Substitute & ORCHESTRATED & Scripted security narrative \\
\bottomrule
\end{tabular}

\wowmoment{Controlled Beta Posture: The demo explicitly states its boundaries. Every claim is labeled as LIVE (Connector API) or ORCHESTRATED (runner logic).}

\newpage

% Demo 3
\section{7 Most Dangerous Attacks}

\subsection{Overview}
\textbf{Thesis:} ``Why you cannot run agents without Connector.''

This attack-driven demo sends \textbf{real attack payloads} through a live Connector node and reports what the platform actually does---block, flag, allow, or error. Nothing is simulated.

\subsection{The 7 Attacks}

\begin{center}
\begin{tabular}{cll}
\toprule
\# & \textbf{Attack} & \textbf{Connector Defense} \\
\midrule
1 & Prompt Injection $\rightarrow$ Tool Hijack & AgentFirewall + SemanticInjectionDetector \\
2 & Memory Poisoning & Firewall write scoring + HMAC chain + CID integrity \\
3 & Tool Escalation & blocked\_tools list + PolicyEngine + MAC guard \\
4 & Cost Explosion & Token budget + BudgetGate + kill switch \\
5 & Hallucinated Action & Receipt chain---no receipt = no truth \\
6 & PII Exfiltration & ContentGuard PII detector + HIPAA report \\
7 & Instruction Drift & BehaviorAnalyzer + InstructionPlane validation \\
\bottomrule
\end{tabular}
\end{center}

\subsection{5 Layers of Raw Evidence}

\begin{enumerate}
    \item \textbf{Exact payload sent} --- The attack string that hits the gateway
    \item \textbf{Raw HTTP response} --- Status code, body JSON, headers
    \item \textbf{Raw firewall inspect} --- All 5 guard pipeline layers evaluated
    \item \textbf{Raw journal entries} --- HMAC-chained audit trail
    \item \textbf{Raw receipts / cost / compliance} --- API responses, not claims
\end{enumerate}

\killerline{Evidence, Not Logs: Every attack shows 5 layers of raw evidence. If the firewall flags but doesn't block, the demo says so plainly.}

\newpage

% Demo 4
\section{Stable Thinking Engine}

\subsection{Overview}
\textbf{Thesis:} ``Connector turns AI from short-term guessing into long-term, stable, constraint-following reasoning.''

Demo 3 proved security. Demo 4 proves \textbf{cognitive governance}: memory stability, instruction fidelity, reasoning consistency, and execution discipline.

\subsection{The 5 WOW Moments}

\wowmoment{WOW Moment 1 -- Memory Graph Stability: Same knowledge reused correctly after 30+ writes. Contradiction detected, not hidden.}

\wowmoment{WOW Moment 2 -- Instruction Survives Noise: After 30+ inputs, rule still applied correctly. Vanilla LLM forgot it.}

\wowmoment{WOW Moment 3 -- Reasoning Consistency: Step 1 and final answer align. Same query twice $\rightarrow$ same reasoning path.}

\killerline{WOW Moment 4 -- Refusal to Hallucinate: System says ``Cannot conclude with current data.'' Vanilla LLM guesses.}

\wowmoment{WOW Moment 5 -- Deterministic Behavior: System enforces constraints at 3 independent layers. Not probabilistic---structural.}

\subsection{Comparison: Vanilla LLM vs Connector}

\begin{tabular}{lcc}
\toprule
\textbf{Capability} & \textbf{Vanilla LLM} & \textbf{Connector} \\
\midrule
Long context & degrades & stable (30+ pkts) \\
Instructions & drift at $\sim$15 msgs & anchored (CID) \\
Reasoning & inconsistent & aligned (2$\times$ same) \\
Hallucination & frequent & refused + cited \\
Memory & flat chat history & structured graph \\
Output & probabilistic & governed + proven \\
Contradictions & silent overwrite & detected + flagged \\
Evidence & none & HMAC-chained CIDs \\
\bottomrule
\end{tabular}

\newpage

% Demo 5
\section{Selective Context + Identity-Aware Execution}

\subsection{Overview}
\textbf{Thesis:} ``The LLM doesn't need to know everything. It just needs to know enough---and Connector ensures the rest stays protected.''

This demo proves \textbf{precision without exposure}: the LLM reasons with minimal safe context while the system executes correctly for the specific user/entity.

\subsection{Patient Scenario}

\begin{center}
\begin{tabular}{p{2.5cm}p{4cm}p{4cm}}
\toprule
\textbf{Patient} & \textbf{Internal State} & \textbf{LLM Sees} \\
\midrule
Maria Santos & Full PHI: SSN, email, cardiac history & ``Patient: cardiac risk, urgent'' \\
John Carter & Full PHI: SSN, email, mild headache & ``Patient: routine, standard'' \\
\bottomrule
\end{tabular}
\end{center}

\subsection{7 Critical Moments}

\begin{enumerate}
    \item \textbf{Side-by-Side} --- Internal vs LLM view comparison
    \item \textbf{RAW LLM Payload} --- Undeniable proof with cryptographic verification
    \item \textbf{Same Query, Different Users} --- LLM sees similar, system executes different
    \item \textbf{Controlled Failure} --- LLM suggests PII, Connector blocks
    \item \textbf{Identity-Aware Execution} --- Killer moment: correct execution per patient
    \item \textbf{Operator Policy Control} --- Runtime context-level changes
    \item \textbf{Cryptographic Execution Proof} --- SHA-256 hashes, phi\_overlap: 0
\end{enumerate}

\killerline{Identity-Aware Execution: LLM never knew WHO---but the system knew WHAT and FOR WHOM. data\_exposed: [] --- VERIFIED: Nothing sensitive leaked.}

\subsection{RAW LLM Payload Proof}

\begin{lstlisting}
Payload Analysis:
  X 

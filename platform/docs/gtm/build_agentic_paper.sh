#!/usr/bin/env bash
# Build agentic isolation position paper PDF (no document date).
set -euo pipefail
cd "$(dirname "$0")"
pdflatex -interaction=nonstopmode agentic_isolation_position_paper.tex >/dev/null || true
pdflatex -interaction=nonstopmode agentic_isolation_position_paper.tex >/dev/null || true
test -f agentic_isolation_position_paper.pdf
python3 strip_pdf_dates.py agentic_isolation_position_paper.pdf
echo "Built: $(pwd)/agentic_isolation_position_paper.pdf"

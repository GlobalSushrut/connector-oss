# Connector System Architecture PDF Build
# ========================================

MAIN = main
CHAPTERS = chapters/01_introduction.tex \
           chapters/02_memory_kernel.tex \
           chapters/03_execution_engines.tex \
           chapters/04_protocol_layers.tex \
           chapters/05_developer_experience.tex \
           chapters/06_business_operations.tex \
           chapters/07_node_operations.tex

OUTPUT = CONNECTOR_SYSTEM_ARCHITECTURE.pdf

.PHONY: all clean view

all: $(OUTPUT)

$(OUTPUT): $(MAIN).tex $(CHAPTERS)
	@echo "Building PDF..."
	pdflatex -interaction=nonstopmode $(MAIN).tex
	pdflatex -interaction=nonstopmode $(MAIN).tex
	@mv $(MAIN).pdf $(OUTPUT)
	@echo "PDF generated: $(OUTPUT)"

clean:
	@echo "Cleaning build artifacts..."
	@rm -f *.aux *.log *.out *.toc *.pdf
	@echo "Clean complete."

view: $(OUTPUT)
	@echo "Opening PDF..."
	@xdg-open $(OUTPUT) 2>/dev/null || open $(OUTPUT) 2>/dev/null || echo "Please open $(OUTPUT) manually"

help:
	@echo "Connector Architecture PDF Build"
	@echo "================================="
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build the PDF (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  view    - Build and open the PDF"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - pdflatex (from TeX Live or MiKTeX)"
	@echo "  - LaTeX packages: geometry, hyperref, listings, xcolor, tikz, etc."
	@echo ""
	@echo "Usage:"
	@echo "  make        # Build PDF"
	@echo "  make view   # Build and open PDF"
	@echo "  make clean  # Clean build files"

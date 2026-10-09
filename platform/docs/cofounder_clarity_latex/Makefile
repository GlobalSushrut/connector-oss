MAIN=cofounder_clarity
OUTPUT=CONNECTOR_COFOUNDER_CLARITY_2026.pdf

CHAPTERS=chapters/01_opening.tex \
	chapters/02_problem.tex \
	chapters/03_wedge.tex \
	chapters/04_why_now.tex \
	chapters/05_customer_profile.tex \
	chapters/06_why_they_pay.tex \
	chapters/07_pilot_design.tex \
	chapters/08_go_to_market.tex \
	chapters/09_why_this_works.tex \
	chapters/10_collaboration_next_step.tex

.PHONY: all clean view

all: $(OUTPUT)

$(OUTPUT): $(MAIN).tex $(CHAPTERS)
	pdflatex -interaction=nonstopmode $(MAIN).tex
	pdflatex -interaction=nonstopmode $(MAIN).tex
	mv $(MAIN).pdf $(OUTPUT)

clean:
	rm -f *.aux *.log *.out *.toc *.pdf

view: $(OUTPUT)
	xdg-open $(OUTPUT) 2>/dev/null || open $(OUTPUT) 2>/dev/null || echo "Open $(OUTPUT) manually"

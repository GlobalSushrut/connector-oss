MAIN=connector_gtm_playbook
OUTPUT=CONNECTOR_GTM_PLAYBOOK.pdf

CHAPTERS=chapters/01_executive_summary.tex \
	chapters/02_problem_and_solution.tex \
	chapters/03_how_it_works.tex \
	chapters/04_use_cases_and_usp.tex \
	chapters/05_custom_vs_premade.tex \
	chapters/06_plugin_portfolio.tex \
	chapters/07_combinations_and_motion.tex

.PHONY: all clean view

all: $(OUTPUT)

$(OUTPUT): $(MAIN).tex $(CHAPTERS)
	pdflatex -interaction=nonstopmode $(MAIN).tex
	pdflatex -interaction=nonstopmode $(MAIN).tex
	mv -f $(MAIN).pdf $(OUTPUT)

clean:
	rm -f *.aux *.log *.out *.toc $(MAIN).pdf $(OUTPUT)

view: $(OUTPUT)
	xdg-open $(OUTPUT) 2>/dev/null || open $(OUTPUT) 2>/dev/null || echo "Open $(OUTPUT) manually"

.PHONY: paper data figures clean all

paper: sections/*.tex references.bib
	pdflatex main && bibtex main && pdflatex main && pdflatex main

data:
	python scripts/extract_paper_data.py

figures: data
	python scripts/generate_figures.py

all: data figures paper

clean:
	rm -f *.aux *.bbl *.blg *.log *.out main.pdf

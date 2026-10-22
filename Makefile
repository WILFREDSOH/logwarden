# Convenience shortcuts. Every target is a plain command you can also type yourself.
PY ?= python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: install install-locked test lint format demo dashboard clean

install:            ## create the virtual environment and install everything
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[all]"

install-locked:     ## same, with the exact versions tested (Python 3.12)
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements-lock.txt
	$(BIN)/pip install -e . --no-deps

test:
	$(BIN)/pytest

lint:
	$(BIN)/ruff check src tests
	$(BIN)/ruff format --check src tests

format:
	$(BIN)/ruff format src tests

demo:
	$(BIN)/logwarden demo

dashboard:
	$(BIN)/logwarden dashboard --db data/generated/demo.db

clean:              ## remove generated data and reports (not the source)
	rm -rf data/generated reports/demo reports/latest .pytest_cache .ruff_cache

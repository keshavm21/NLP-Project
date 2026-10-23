# Run `make help` for the list of commands.
PY ?= python
CLI = $(PY) -m vulntriage.cli

.PHONY: help setup setup-ml setup-all test lint format data benchmark serve status

help:
	@echo "setup       install core + dev deps (no torch)"
	@echo "setup-ml    also install ML deps (torch, transformers, faiss, ...)"
	@echo "setup-all   everything (ml + api + dev)"
	@echo "test        run tests"
	@echo "lint        ruff check + format check"
	@echo "format      auto-format with ruff"
	@echo "data        download all sources            (P1)"
	@echo "benchmark   build splits + silver labels    (P1)"
	@echo "train-X     X in extract|link|cwe|cvss|exploit"
	@echo "eval-X      X in extract|link|cwe|cvss|exploit|rank"
	@echo "eval-e2e    end-to-end replay               (P5)"
	@echo "serve       API + dashboard                 (P5)"
	@echo "status      show which pipeline steps are implemented"

setup:
	$(PY) -m pip install -e ".[dev]"

setup-ml:
	$(PY) -m pip install -e ".[ml,dev]"

setup-all:
	$(PY) -m pip install -e ".[all]"

test:
	$(PY) -m pytest

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format:
	$(PY) -m ruff format .
	$(PY) -m ruff check --fix .

data:
	$(CLI) data

benchmark:
	$(CLI) benchmark

train-%:
	$(CLI) train-$*

eval-%:
	$(CLI) eval-$*

serve:
	$(CLI) serve

status:
	$(CLI) status

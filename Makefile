# Developer entry points. `make help` lists the targets; `make check` runs everything CI runs.
SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

UV       ?= uv
RUN      := $(UV) run --frozen
IMAGE    ?= fritzos8-mcp:dev
SNAPSHOT ?= ../fritzos8-mcp-public

.PHONY: help setup sync lint format typecheck test test-live docs-check docs docs-serve build docker audit \
        pre-commit check snapshot clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Bootstrap the dev environment (uv sync, git hooks, .private-patterns template)
	@scripts/bootstrap.sh

sync: ## Install/refresh all dependencies from uv.lock
	$(UV) sync --frozen --all-extras --all-groups

lint: ## Ruff lint + format check
	$(RUN) ruff check .
	$(RUN) ruff format --check .

format: ## Auto-fix lint findings and format the code
	$(RUN) ruff check --fix .
	$(RUN) ruff format .

typecheck: ## Mypy (strict)
	$(RUN) mypy

test: ## Pytest against mocks (never talks to a real box)
	$(RUN) pytest

test-live: ## Opt-in read-only live suite (needs FRITZ_LIVE_TEST=1 and FRITZ_HOST/USER/PASSWORD_FILE)
	FRITZ_LIVE_TEST=1 $(RUN) pytest tests/live -o addopts="" -v

docs-check: ## Generated docs are up to date (docs/TOOLS.md, COVERAGE statistics)
	$(RUN) python scripts/gen_tool_reference.py --check
	$(RUN) python scripts/coverage_stats.py --check

docs: ## Build the documentation website (mkdocs --strict) into site/
	$(RUN) --group docs mkdocs build --strict

docs-serve: ## Serve the documentation website locally with live reload
	$(RUN) --group docs mkdocs serve

build: ## Build sdist + wheel into dist/ and check the metadata
	rm -rf dist
	$(UV) build
	$(RUN) twine check --strict dist/*

docker: ## Build the container image locally ($(IMAGE))
	docker build -t $(IMAGE) .

audit: ## Scan the locked dependencies for known vulnerabilities (pip-audit)
	$(UV) export --frozen --all-extras --no-dev --no-emit-project --format requirements-txt -o .audit-requirements.txt -q
	rc=0; $(RUN) pip-audit --strict --disable-pip --require-hashes -r .audit-requirements.txt || rc=$$?; \
		rm -f .audit-requirements.txt; exit $$rc

pre-commit: ## Run all pre-commit hooks on all files
	$(RUN) pre-commit run --all-files

check: lint typecheck test docs-check docs build ## Everything CI runs (except docker/audit)
	@echo "✓ make check: all green"

snapshot: ## Create the clean one-commit public snapshot in $(SNAPSHOT) (never pushes)
	scripts/make_public_snapshot.sh $(SNAPSHOT) --force

clean: ## Remove caches and build output
	rm -rf dist build site .mypy_cache .ruff_cache .pytest_cache .coverage .audit-requirements.txt
	find . -type d -name __pycache__ -not -path './.venv/*' -prune -exec rm -rf {} +

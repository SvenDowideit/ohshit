.PHONY: help setup dev run run-no-ssh run-dev lint test clean

PYTHON := .venv/bin/python
UV     := $(shell command -v uv 2>/dev/null || echo $(HOME)/.local/bin/uv)

# Default target
help:
	@echo ""
	@echo "oh-shit — Home Network Security Dashboard"
	@echo ""
	@echo "  make setup        Install uv (if needed) and all dependencies"
	@echo "  make run          Launch the full TUI dashboard"
	@echo "  make run-no-ssh   Run discovery only (no SSH collection)"
	@echo "  make run-dev      Launch with Textual hot-reload (dev mode)"
	@echo "  make test         Run the test suite"
	@echo "  make lint         Type-check with pyright"
	@echo "  make clean        Remove virtual environment and caches"
	@echo ""

# ── Setup ─────────────────────────────────────────────────────────────────────

setup: _uv_install
	$(UV) sync --dev
	@echo ""
	@echo "✓ Environment ready.  Run:  make run"

_uv_install:
	@if ! command -v uv >/dev/null 2>&1 && [ ! -x $(HOME)/.local/bin/uv ]; then \
		echo "Installing uv..."; \
		curl -LsSf https://astral.sh/uv/install.sh | sh; \
	fi

# ── Running ───────────────────────────────────────────────────────────────────

run: _check_venv
	$(UV) run ohshit

run-no-ssh: _check_venv
	$(UV) run ohshit --no-ssh

run-dev: _check_venv
	$(UV) run textual run --dev src/ohshit/tui/app.py

# ── Development ───────────────────────────────────────────────────────────────

test: _check_venv
	$(UV) run pytest -v

lint: _check_venv
	$(UV) run python -m py_compile \
		src/ohshit/models.py \
		src/ohshit/risk_engine.py \
		src/ohshit/discovery.py \
		src/ohshit/ssh_collector.py \
		src/ohshit/report.py \
		src/ohshit/tui/app.py \
		src/ohshit/tui/widgets.py \
		src/ohshit/main.py
	@echo "✓ Syntax OK"

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	rm -rf .venv __pycache__ src/ohshit/__pycache__ src/ohshit/tui/__pycache__ \
	       .pytest_cache dist *.egg-info

# ── Internal ──────────────────────────────────────────────────────────────────

_check_venv:
	@if [ ! -f $(PYTHON) ]; then \
		echo "Virtual environment not found. Run:  make setup"; \
		exit 1; \
	fi

# Rampart — developer convenience targets.
# Rampart's core is dependency-free stdlib Python; these just wrap the common
# commands. Use `python3` if `python` is not on your PATH.

PYTHON ?= python
# Hash-pinned lock files: every CI/release/Docker `pip install` uses --require-hashes on these.
LOCK ?= uv pip compile --quiet --generate-hashes --universal --python-version 3.10

.PHONY: install dev test bench demo demo-llm tools docker-build lint format check lock

install:  ## Install the package in editable mode
	$(PYTHON) -m pip install -e .

dev:  ## Install with dev tools (pytest, ruff, pre-commit) and set up hooks
	$(PYTHON) -m pip install -e ".[dev]"
	pre-commit install

test:  ## Run the test suite
	$(PYTHON) -m pytest

bench:  ## Run the reliability benchmark (nonzero exit on FP/FN)
	$(PYTHON) benchmarks/run_benchmark.py

demo:  ## Run the local web/API demo end-to-end
	$(PYTHON) scripts/demo.py --no-open

demo-llm:  ## Run the local LLM (OWASP LLM Top 10) demo
	$(PYTHON) scripts/demo.py --llm --no-open

tools:  ## Show which external OSS scanners are installed (doctor)
	$(PYTHON) -m rampart tools

docker-build:  ## Build the Docker image
	docker build -t rampart:local .

lint:  ## Lint with ruff
	$(PYTHON) -m ruff check .

format:  ## Auto-format with ruff
	$(PYTHON) -m ruff format .

lock:  ## Re-pin the hash-locked requirement files from requirements/*.in (needs uv)
	$(LOCK) requirements/ci.in -o requirements/ci.txt
	$(LOCK) requirements/build.in -o requirements/build.txt
	$(LOCK) requirements/release.in -o requirements/release.txt
	$(LOCK) requirements/dev.in -o requirements-dev.txt
	uv pip compile --quiet --generate-hashes --python-version 3.12 --python-platform x86_64-manylinux_2_28 \
		requirements/fuzz.in -o requirements/fuzz.txt

check:  ## Everything CI runs: lint + format check + tests + benchmark
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m pytest -q
	$(PYTHON) benchmarks/run_benchmark.py

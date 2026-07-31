.PHONY: help install test lint format benchmark build clean

PYTHON_SOURCES := hlinor_registry tests examples scripts benchmarks

help:
	@echo "Available commands:"
	@echo "  make install   - Install package in editable mode with dev dependencies"
	@echo "  make test      - Run pytest with coverage report"
	@echo "  make lint      - Run ruff and mypy checks"
	@echo "  make format    - Auto-format code with ruff"
	@echo "  make benchmark - Measure PolicyChecker latency and throughput"
	@echo "  make build     - Build source distribution and wheel"
	@echo "  make clean     - Remove build artifacts and cache"

install:
	python3 -m pip install -e ".[dev]"

test:
	python3 -m pytest --cov=hlinor_registry --cov-report=term-missing

lint:
	python3 -m ruff format --check $(PYTHON_SOURCES)
	python3 -m ruff check $(PYTHON_SOURCES)
	python3 -m mypy hlinor_registry
	python3 -m yamllint .

format:
	python3 -m ruff format $(PYTHON_SOURCES)
	python3 -m ruff check $(PYTHON_SOURCES) --fix

benchmark:
	python3 -m benchmarks.policy_checker_benchmark

build:
	python3 -m build

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +

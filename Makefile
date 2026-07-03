.PHONY: install test lint format serve benchmark clean

install:
	pip install -e ".[dev,all]"

test:
	python -m pytest tests/ -v --cov=sentinel --cov-report=term-missing --tb=short

lint:
	ruff check src/ tests/
	mypy --strict src/
	mypy tests/ --ignore-missing-imports

format:
	black src/ tests/
	ruff check --fix src/ tests/

serve:
	python -m sentinel.cli serve --host 0.0.0.0 --port 8000

benchmark:
	python benchmarks/run_benchmarks.py

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -f .coverage
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf *.egg-info

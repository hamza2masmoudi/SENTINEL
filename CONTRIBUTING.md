# Contributing to SENTINEL

Thank you for your interest in contributing to SENTINEL.

## Development Workflow

1. Fork the repository and create a feature branch from `main`.
2. Install dependencies with development extras:
   ```bash
   make install
   ```
3. Implement your changes following all architectural guidelines and project standards.
4. Format code using the automated tools:
   ```bash
   make format
   ```
5. Run linting and type checking suites:
   ```bash
   make lint
   ```
6. Verify test execution and maintain minimum 85% code coverage:
   ```bash
   make test
   ```
7. Run the benchmark suite to verify performance:
   ```bash
   make benchmark
   ```

## Type Checking Guidelines

SENTINEL enforces strict typing across source packages while maintaining flexible typing across test suites:

- **Source Code (`src/`)**: Enforces strict typing with `mypy --strict src/`. Disallow untyped defs, any-generics, and untyped calls.
- **Test Code (`tests/`)**: Evaluated via `mypy tests/ --ignore-missing-imports` to permit test fixtures and mocking frameworks without over-constraining test implementation.

Run type checks manually:
```bash
uv run mypy --strict src/
uv run mypy tests/ --ignore-missing-imports
```

## Coding Standards

- No comments inside code implementations. Express intent via clear, explicit naming and structural modularity.
- Comprehensive Google-style docstrings on all public classes, methods, and functions (Args, Returns, Raises, Examples).
- No emojis anywhere in commit messages, documentation, or code.
- Functions must remain under 50 lines.
- Source files must remain under 400 lines.
- Strict line length limit of 88 characters enforced by Black and Ruff.

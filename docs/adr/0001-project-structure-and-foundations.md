# ADR 0001: Project Architecture and Foundations

## Status

Accepted

## Context

SENTINEL is an enterprise-grade security and governance framework for LLM agents. To ensure long-term maintainability, reliability, and security compliance, foundational architectural choices must establish strict boundaries, strong typing, reproducible builds, and deterministic logging without external runtime fragility.

Key technical requirements:
1. Production readiness with modern Python 3.11+.
2. Strict static typing without dynamic type escaping.
3. Structured logging suitable for ingestion into SIEM platforms.
4. Comprehensive configuration management supporting environment variables and secret isolation.
5. Deterministic, unified error handling across all security detectors and governance layers.

## Decision

1. Packaging and Dependency Management:
   Adopt standard PEP 621 packaging with `pyproject.toml` and Hatchling as the build backend, managed via `uv` for reproducible and fast resolution.

2. Static Typing and Linting:
   Enforce `mypy` in strict mode with no untyped definitions, disallowing untyped calls or implicit optionals. Code style is formatted with `black` and linted with `ruff`. Cyclomatic complexity is capped at 10 via `radon`.

3. Configuration Architecture:
   Use Pydantic v2 Settings (`BaseSettings`) with hierarchical sub-configurations (`DetectionConfig`, `MonitoringConfig`, `GovernanceConfig`, `SecurityConfig`). Environment variables use the `SENTINEL_` prefix with double-underscore nesting delimiters (`SENTINEL_DETECTION__INJECTION_THRESHOLD`).

4. Structured Logging:
   Implement structured logging with `structlog`, outputting JSON in production and structured text in local development. Propagate distributed trace contexts (correlation ID, tenant ID) across execution threads using Python `contextvars`.

5. Exception Hierarchy:
   Establish `SentinelError` as the root exception class, requiring every specialized domain exception (e.g., `ConfigurationError`, `DetectionError`, `PolicyViolationError`, `AuditIntegrityError`) to inherit directly or indirectly from it.

## Consequences

Positive:
- Zero ambiguity in data types across public and internal interfaces.
- Seamless integration with Kubernetes, Docker, cloud secret managers, and SIEM collectors.
- Immediate fail-fast behavior on invalid configurations.
- Full compliance with modern enterprise Python standards.

Negative:
- Requires explicit type declarations for all functions, methods, and variables.
- Requires strict adherence to Google-style docstrings and zero code comments.

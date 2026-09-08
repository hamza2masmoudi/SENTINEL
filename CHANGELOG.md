# Changelog

All notable changes to SENTINEL are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-10

### Added

- Core framework foundations: Pydantic Settings v2 configuration with environment variable overrides, structured exception hierarchy, and enterprise structured logging with structlog and correlation ID propagation.
- Detection subsystem: prompt injection detector, jailbreak detector, PII detector with anonymization and deanonymization, secrets/credential detector, toxicity detector, behavioral anomaly detector, and weighted ensemble orchestrator with concurrent execution.
- Monitoring subsystem: OpenTelemetry distributed tracing integration, Prometheus metrics recording (detection counts, blocks, latency histograms, risk scores), webhook alert manager with rate limiting, and session profiling with conversation turn tracking and risk trend analysis.
- Governance subsystem: tamper-evident SHA-256 hash chain, SQLite-backed audit logger with CSV export, YAML-driven policy engine with evaluation and simulation, role-based access control with API key authentication and SHA-256 hashing, and compliance mapping for GDPR, SOC2, HIPAA, and ISO27001.
- Guardrails subsystem: pre-LLM input guard with PII anonymization and ensemble threat detection, post-LLM output guard with credential leakage prevention, toxicity filtering, deanonymization, and optional steganographic watermarking, and tool execution guard with shell command, SQL injection, and SSRF sandboxing.
- Ecosystem integrations: LangChain callback handler, LlamaIndex event handler and node postprocessor, and OpenAI SDK wrapper with automatic guardrail enforcement.
- REST API: FastAPI application with scan, input guard, output guard, audit query, policy evaluation, and health check endpoints, correlation ID middleware, per-client rate limiting middleware, and API key authentication middleware.
- CLI: Typer application with scan, health, config, serve, audit list, and audit verify commands.
- Benchmarking: synthetic dataset generators for injection, jailbreak, PII, toxicity, and mixed threat categories, and benchmark runner with precision, recall, F1, and latency metrics collection.
- Project infrastructure: pyproject.toml with hatchling build system, PEP 561 typed package marker, GitHub Actions CI workflow, MIT license, Makefile for developer automation, multi-stage Dockerfile, and comprehensive test suite with 70 unit tests.

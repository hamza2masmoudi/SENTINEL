# SENTINEL Documentation

Welcome to the documentation for SENTINEL (Security Evaluation and Neural Tracing for Intelligent Language-models).

## Overview

SENTINEL is an enterprise-grade security, governance, and guardrail framework designed for production Large Language Model (LLM) agents and pipelines.

## Key Features

- **Multi-Layer Threat Detection**: Real-time evaluation of prompt injections, jailbreaks, PII leakage, credential secrets, toxicity, and behavioral anomalies.
- **Cryptographic Audit Hashchain**: Immutable SHA-256 tamper-evident transaction logging with SQLite and PostgreSQL backends.
- **Policy Engine**: Dynamic YAML security policy evaluation and simulation.
- **Guardrails**: Input and output sanitization, masking, and tool sandboxing.
- **Observability**: Distributed OpenTelemetry tracing and Prometheus metrics.

## Quick Links

- [Architecture Decision Records](adr/0001-project-structure-and-foundations.md)

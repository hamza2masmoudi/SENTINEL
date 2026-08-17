"""Benchmark subsystem for SENTINEL security detector evaluation."""

from sentinel.benchmarks.datasets import (
    BenchmarkSample,
    generate_injection_dataset,
    generate_jailbreak_dataset,
    generate_mixed_dataset,
    generate_pii_dataset,
    generate_toxicity_dataset,
)
from sentinel.benchmarks.runner import BenchmarkReport, BenchmarkRunner

__all__: list[str] = [
    "BenchmarkSample",
    "generate_injection_dataset",
    "generate_jailbreak_dataset",
    "generate_pii_dataset",
    "generate_toxicity_dataset",
    "generate_mixed_dataset",
    "BenchmarkRunner",
    "BenchmarkReport",
]

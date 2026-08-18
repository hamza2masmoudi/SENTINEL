"""Execute the complete dedicated benchmark suite and export metrics reports."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sentinel.benchmarks.runner import BenchmarkRunner

RESULTS_DIR = Path("benchmarks/results")
DATASETS_DIR = Path("benchmarks/datasets")


def main() -> None:
    """Run dedicated benchmark suite and write markdown and json reports."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if not (DATASETS_DIR / "prompt_injection.jsonl").exists():
        from benchmarks.generate_datasets import generate_all_datasets

        generate_all_datasets()

    runner = BenchmarkRunner()
    report = runner.run_dedicated_suite_sync(DATASETS_DIR)

    json_path = RESULTS_DIR / "benchmark_report.json"
    md_path = RESULTS_DIR / "benchmark_report.md"

    runner.export_report_json(report, json_path)
    runner.export_report_markdown(report, md_path)

    for metrics in report.detector_metrics:
        print(
            f"[{metrics.detector_name}] P={metrics.precision:.4f} "
            f"R={metrics.recall:.4f} F1={metrics.f1_score:.4f} "
            f"P50={metrics.latency_p50_ms:.2f}ms P95={metrics.latency_p95_ms:.2f}ms"
        )
    print(
        f"Benchmark complete: {report.total_samples} samples evaluated "
        f"across {len(report.detector_metrics)} detectors in "
        f"{report.total_duration_seconds:.2f}s."
    )


if __name__ == "__main__":
    main()

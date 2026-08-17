import asyncio
import time
from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.benchmarks.datasets import BenchmarkSample
from sentinel.detection.base import BaseDetector


class DetectorMetrics(BaseModel):
    """Performance metrics for a single detector on a benchmark dataset.

    Attributes:
        detector_name: Name of the evaluated detector.
        true_positives: Correctly identified threats.
        true_negatives: Correctly identified benign inputs.
        false_positives: Benign inputs incorrectly flagged as threats.
        false_negatives: Threats incorrectly classified as benign.
        precision: Ratio of true positives to all positive predictions.
        recall: Ratio of true positives to all actual positives.
        f1_score: Harmonic mean of precision and recall.
        average_latency_ms: Mean detection latency in milliseconds.
    """

    detector_name: str
    true_positives: int = Field(default=0, ge=0)
    true_negatives: int = Field(default=0, ge=0)
    false_positives: int = Field(default=0, ge=0)
    false_negatives: int = Field(default=0, ge=0)
    precision: float = Field(default=0.0, ge=0.0, le=1.0)
    recall: float = Field(default=0.0, ge=0.0, le=1.0)
    f1_score: float = Field(default=0.0, ge=0.0, le=1.0)
    average_latency_ms: float = Field(default=0.0, ge=0.0)
    latency_p50_ms: float = Field(default=0.0, ge=0.0)
    latency_p95_ms: float = Field(default=0.0, ge=0.0)
    latency_p99_ms: float = Field(default=0.0, ge=0.0)


class BenchmarkReport(BaseModel):
    """Aggregate benchmark report across all evaluated detectors.

    Attributes:
        total_samples: Total number of benchmark samples processed.
        detector_metrics: Per-detector performance metrics.
        total_duration_seconds: Total benchmark execution time in seconds.
    """

    total_samples: int = Field(default=0, ge=0)
    detector_metrics: list[DetectorMetrics] = Field(default_factory=list)
    total_duration_seconds: float = Field(default=0.0, ge=0.0)


class BenchmarkRunner:
    """Executes detectors against benchmark datasets and collects metrics.

    Attributes:
        detectors: List of detector instances to benchmark.
    """

    def __init__(self, detectors: list[BaseDetector] | None = None) -> None:
        """Initialize BenchmarkRunner with a set of detectors.

        Args:
            detectors: Optional list of detectors to evaluate.
        """
        self.detectors: list[BaseDetector] = detectors if detectors is not None else []

    def _compute_metrics(
        self,
        detector_name: str,
        predictions: list[bool],
        labels: list[bool],
        latencies: list[float],
    ) -> DetectorMetrics:
        """Compute precision, recall, and F1 from predictions and ground truth.

        Args:
            detector_name: Name of the detector being evaluated.
            predictions: List of detector prediction booleans.
            labels: List of ground truth label booleans.
            latencies: List of per-sample latency measurements in milliseconds.

        Returns:
            DetectorMetrics: Computed performance metrics.
        """
        paired = list(zip(predictions, labels, strict=True))
        true_positives: int = sum(1 for pred, label in paired if pred and label)
        true_negatives: int = sum(1 for pred, label in paired if not pred and not label)
        false_positives: int = sum(1 for pred, label in paired if pred and not label)
        false_negatives: int = sum(1 for pred, label in paired if not pred and label)

        precision: float = (
            true_positives / (true_positives + false_positives)
            if (true_positives + false_positives) > 0
            else 0.0
        )
        recall: float = (
            true_positives / (true_positives + false_negatives)
            if (true_positives + false_negatives) > 0
            else 0.0
        )
        f1_score: float = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        average_latency: float = sum(latencies) / len(latencies) if latencies else 0.0
        sorted_lat = sorted(latencies)
        count_lat = len(sorted_lat)
        p50 = sorted_lat[int(count_lat * 0.50)] if count_lat > 0 else 0.0
        p95 = (
            sorted_lat[min(count_lat - 1, int(count_lat * 0.95))]
            if count_lat > 0
            else 0.0
        )
        p99 = (
            sorted_lat[min(count_lat - 1, int(count_lat * 0.99))]
            if count_lat > 0
            else 0.0
        )

        return DetectorMetrics(
            detector_name=detector_name,
            true_positives=true_positives,
            true_negatives=true_negatives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1_score, 4),
            average_latency_ms=round(average_latency, 2),
            latency_p50_ms=round(p50, 2),
            latency_p95_ms=round(p95, 2),
            latency_p99_ms=round(p99, 2),
        )

    async def run_detector(
        self, detector: BaseDetector, samples: list[BenchmarkSample]
    ) -> DetectorMetrics:
        """Benchmark a single detector against a dataset of labeled samples.

        Args:
            detector: Detector instance to evaluate.
            samples: List of labeled benchmark samples.

        Returns:
            DetectorMetrics: Performance metrics for the detector.

        Raises:
            None

        Examples:
            >>> pass
        """
        predictions: list[bool] = []
        labels: list[bool] = []
        latencies: list[float] = []

        for sample in samples:
            start_time = time.perf_counter()
            result = await detector.detect(sample.text, context=sample.context)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            predictions.append(result.detected)
            labels.append(sample.expected_label)
            latencies.append(elapsed_ms)

        return self._compute_metrics(detector.name, predictions, labels, latencies)

    async def run_all(self, samples: list[BenchmarkSample]) -> BenchmarkReport:
        """Execute all registered detectors against the provided dataset.

        Args:
            samples: List of labeled benchmark samples.

        Returns:
            BenchmarkReport: Aggregate report with per-detector metrics.

        Raises:
            None

        Examples:
            >>> runner = BenchmarkRunner()
            >>> import asyncio
            >>> report = asyncio.run(runner.run_all([]))
            >>> report.total_samples
            0
        """
        start_time = time.perf_counter()
        all_metrics: list[DetectorMetrics] = []

        for detector in self.detectors:
            metrics = await self.run_detector(detector, samples)
            all_metrics.append(metrics)

        total_duration = time.perf_counter() - start_time

        return BenchmarkReport(
            total_samples=len(samples),
            detector_metrics=all_metrics,
            total_duration_seconds=round(total_duration, 4),
        )

    def run_all_sync(self, samples: list[BenchmarkSample]) -> BenchmarkReport:
        """Synchronous wrapper for executing the full benchmark suite.

        Args:
            samples: List of labeled benchmark samples.

        Returns:
            BenchmarkReport: Aggregate report with per-detector metrics.

        Raises:
            None

        Examples:
            >>> runner = BenchmarkRunner()
            >>> report = runner.run_all_sync([])
            >>> report.total_samples
            0
        """
        return asyncio.run(self.run_all(samples))

    async def run_dedicated_suite(
        self, datasets_dir: str | Path = "benchmarks/datasets"
    ) -> BenchmarkReport:
        """Evaluate detectors on their dedicated datasets and Ensemble on mixed.

        Args:
            datasets_dir: Directory containing per-detector JSONL files.

        Returns:
            BenchmarkReport: Report with individual and ensemble benchmark metrics.

        Raises:
            FileNotFoundError: If benchmark datasets are missing.

        Examples:
            >>> pass
        """
        from sentinel.benchmarks.datasets import load_dataset_jsonl
        from sentinel.detection import (
            AnomalyDetector,
            DetectionEnsemble,
            JailbreakDetector,
            PIIDetector,
            PromptInjectionDetector,
            SecretsDetector,
            ToxicityDetector,
        )

        base = Path(datasets_dir)
        start_time = time.perf_counter()
        metrics_list: list[DetectorMetrics] = []
        total_samples = 0

        eval_plan: list[tuple[BaseDetector, str]] = [
            (PromptInjectionDetector(), "prompt_injection.jsonl"),
            (JailbreakDetector(), "jailbreak.jsonl"),
            (PIIDetector(), "pii.jsonl"),
            (SecretsDetector(), "secrets.jsonl"),
            (ToxicityDetector(), "toxicity.jsonl"),
            (AnomalyDetector(), "anomaly.jsonl"),
        ]

        for detector, filename in eval_plan:
            path = base / filename
            if path.exists():
                samples = load_dataset_jsonl(path)
                total_samples += len(samples)
                metrics = await self.run_detector(detector, samples)
                metrics_list.append(metrics)

        ensemble_path = base / "ensemble.jsonl"
        if ensemble_path.exists():
            ensemble_samples = load_dataset_jsonl(ensemble_path)
            total_samples += len(ensemble_samples)
            ensemble = DetectionEnsemble()
            predictions: list[bool] = []
            labels: list[bool] = []
            latencies: list[float] = []

            for s in ensemble_samples:
                st = time.perf_counter()
                res = await ensemble.analyze(s.text, context=s.context)
                lat = (time.perf_counter() - st) * 1000.0
                predictions.append(res.decision != "allow")
                labels.append(s.expected_label)
                latencies.append(lat)

            ens_metrics = self._compute_metrics(
                "ensemble", predictions, labels, latencies
            )
            metrics_list.append(ens_metrics)

        duration = time.perf_counter() - start_time
        return BenchmarkReport(
            total_samples=total_samples,
            detector_metrics=metrics_list,
            total_duration_seconds=round(duration, 4),
        )

    def run_dedicated_suite_sync(
        self, datasets_dir: str | Path = "benchmarks/datasets"
    ) -> BenchmarkReport:
        """Synchronous wrapper for running the dedicated benchmark suite.

        Args:
            datasets_dir: Directory containing per-detector JSONL files.

        Returns:
            BenchmarkReport: Evaluated benchmark report.

        Raises:
            FileNotFoundError: If benchmark datasets are missing.

        Examples:
            >>> pass
        """
        return asyncio.run(self.run_dedicated_suite(datasets_dir))

    def export_report_json(
        self, report: BenchmarkReport, output_file: str | Path
    ) -> None:
        """Export benchmark report to JSON file.

        Args:
            report: Populated BenchmarkReport.
            output_file: Destination file path.
        """
        dest = Path(output_file)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")

    def export_report_markdown(
        self, report: BenchmarkReport, output_file: str | Path
    ) -> None:
        """Export benchmark report to Markdown table.

        Args:
            report: Populated BenchmarkReport.
            output_file: Destination file path.
        """
        dest = Path(output_file)
        dest.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# SENTINEL Benchmark Report",
            "",
            f"Total evaluated samples: {report.total_samples}",
            f"Total duration: {report.total_duration_seconds:.2f}s",
            (
                "| Detector | Precision | Recall | F1 | Latency P50 | "
                "Latency P95 | Latency P99 |"
            ),
            "|---|---|---|---|---|---|---|",
        ]
        for m in report.detector_metrics:
            lines.append(
                f"| {m.detector_name} | {m.precision:.4f} | {m.recall:.4f} "
                f"| {m.f1_score:.4f} | {m.latency_p50_ms:.2f}ms | "
                f"{m.latency_p95_ms:.2f}ms | {m.latency_p99_ms:.2f}ms |"
            )
        lines.extend(
            [
                "",
                "## Limitations",
                "",
                (
                    "- Synthetic Dataset Scope: Benchmark datasets are generated "
                    "with deterministic perturbation to evaluate edge cases; "
                    "production distributions will differ."
                ),
                (
                    "- Empirical Real-World Performance: Detection boundaries are "
                    "evaluated against heuristic patterns; real-world environments "
                    "with multi-turn context may vary."
                ),
                (
                    "- Uncovered Attack Vectors: The current suite does not test "
                    "multi-turn conversational poisoning, multimodal steganography, "
                    "or side-channel weight extraction."
                ),
            ]
        )
        dest.write_text("\n".join(lines) + "\n", encoding="utf-8")

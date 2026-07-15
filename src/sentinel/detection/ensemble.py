import asyncio
import time
from typing import Any, Literal

from pydantic import BaseModel, Field

from sentinel.detection.anomaly import AnomalyDetector
from sentinel.detection.base import BaseDetector, DetectionResult
from sentinel.detection.injection import PromptInjectionDetector
from sentinel.detection.jailbreak import JailbreakDetector
from sentinel.detection.pii import PIIDetector
from sentinel.detection.secrets import SecretsDetector
from sentinel.detection.toxicity import ToxicityDetector
from sentinel.exceptions import DetectionError


class EnsembleResult(BaseModel):
    """Aggregate decision produced by the multi-detector ensemble.

    Attributes:
        decision: Final governance action ('allow', 'warn', 'block').
        composite_score: Aggregated weighted risk score between 0.0 and 1.0.
        blocked: Boolean indicator confirming if interaction must be stopped.
        triggered_detectors: List of detectors identifying a threat.
        detector_results: Map of individual detector names to full results.
        explanation: Human-readable narrative detailing the decision rationale.
        total_latency_ms: Total ensemble execution time in milliseconds.
    """

    decision: Literal["allow", "warn", "block"]
    composite_score: float = Field(ge=0.0, le=1.0)
    blocked: bool
    triggered_detectors: list[str] = Field(default_factory=list)
    detector_results: dict[str, DetectionResult] = Field(default_factory=dict)
    explanation: str = Field(default="")
    total_latency_ms: float = Field(default=0.0, ge=0.0)


class DetectionEnsemble:
    """Orchestrator executing detectors concurrently with weighted fusion.

    Attributes:
        detectors: Dictionary of registered BaseDetector instances.
        weights: Dictionary of detector scoring weights.
        block_threshold: Composite score cutoff for blocking interactions.
        warn_threshold: Composite score cutoff for issuing warnings.
        veto_threshold: Critical detector score cutoff for immediate veto block.
    """

    def __init__(
        self,
        detectors: list[BaseDetector] | None = None,
        weights: dict[str, float] | None = None,
        block_threshold: float = 0.70,
        warn_threshold: float = 0.30,
        veto_threshold: float = 0.70,
    ) -> None:
        """Initialize the DetectionEnsemble.

        Args:
            detectors: Optional custom list of detector instances.
            weights: Optional custom weight mapping for fusion.
            block_threshold: Threshold above which decisions become 'block'.
            warn_threshold: Threshold above which decisions become 'warn'.
            veto_threshold: High-confidence score cutoff for critical vetoes.

        Raises:
            ValueError: If thresholds or weights are invalid.
        """
        if block_threshold < warn_threshold:
            raise ValueError(
                "block_threshold must be greater than or equal to warn_threshold"
            )

        self.block_threshold: float = block_threshold
        self.warn_threshold: float = warn_threshold
        self.veto_threshold: float = veto_threshold

        if detectors is None:
            detectors = [
                PromptInjectionDetector(),
                JailbreakDetector(),
                PIIDetector(),
                SecretsDetector(),
                ToxicityDetector(),
                AnomalyDetector(),
            ]

        self.detectors: dict[str, BaseDetector] = {d.name: d for d in detectors}

        default_weights: dict[str, float] = {
            "jailbreak": 0.25,
            "prompt_injection": 0.22,
            "secrets": 0.20,
            "toxicity": 0.18,
            "pii": 0.10,
            "anomaly": 0.05,
        }
        self.weights: dict[str, float] = (
            weights if weights is not None else default_weights
        )

    def _compute_composite_score(self, results_list: list[DetectionResult]) -> float:
        """Compute confidence-weighted composite security score across detectors.

        Args:
            results_list: Individual detector evaluation outcomes.

        Returns:
            float: Calibrated composite risk score between 0.0 and 1.0.
        """
        weighted_sum = 0.0
        total_weight_confidence = 0.0
        for res in results_list:
            weight = self.weights.get(res.detector_name, 0.10)
            confidence = 1.0 + abs(res.score - 0.5) * 1.5
            weighted_sum += res.score * weight * confidence
            total_weight_confidence += weight * confidence

        normalized_score = weighted_sum / max(total_weight_confidence, 0.001)
        highest_detected = max(
            (res.score for res in results_list if res.detected),
            default=0.0,
        )
        return min(1.0, max(normalized_score, highest_detected * 0.90))

    def _determine_decision(
        self, composite_score: float, results: dict[str, DetectionResult]
    ) -> tuple[Literal["allow", "warn", "block"], bool]:
        """Compute the final decision state, checking high-confidence veto and cutoffs.

        Args:
            composite_score: Confidence-weighted cumulative score.
            results: Map of individual detector names to evaluation results.

        Returns:
            tuple[Literal["allow", "warn", "block"], bool]: Decision and blocked flag.
        """
        critical_detectors = {"prompt_injection", "jailbreak", "secrets"}
        has_veto = any(
            results[d].detected and results[d].score >= self.veto_threshold
            for d in critical_detectors
            if d in results
        )

        if has_veto or composite_score > self.block_threshold:
            return "block", True
        if composite_score >= self.warn_threshold:
            return "warn", False
        return "allow", False

    def _build_explanation(
        self,
        decision: str,
        score: float,
        triggered: list[str],
        results: dict[str, DetectionResult],
    ) -> str:
        """Construct a structured narrative explaining the ensemble verdict.

        Args:
            decision: Action decided.
            score: Composite risk score.
            triggered: Triggered detector names.
            results: Individual detector results.

        Returns:
            str: Explanatory summary text.
        """
        if not triggered:
            return f"Interaction permitted with low risk score {score:.2f}."

        triggers_info = ", ".join(
            f"{name} ({results[name].category}: {results[name].score:.2f})"
            for name in triggered
        )
        return (
            f"Decision '{decision}' enforced with risk score {score:.2f}. "
            f"Threats flagged by: {triggers_info}."
        )

    async def analyze(
        self, text: str, context: dict[str, Any] | None = None
    ) -> EnsembleResult:
        """Run all detectors concurrently and evaluate composite security status.

        Args:
            text: Raw input text to evaluate across all threat dimensions.
            context: Contextual parameters such as history or session profiling.

        Returns:
            EnsembleResult: Complete aggregate verdict and granular detector outputs.

        Raises:
            DetectionError: If ensemble orchestration encounters a failure.
        """
        start_time = time.perf_counter()
        tasks = [detector.detect(text, context) for detector in self.detectors.values()]

        try:
            results_list = await asyncio.gather(*tasks, return_exceptions=False)
        except Exception as err:
            raise DetectionError(f"Ensemble execution failed: {err}") from err

        results: dict[str, DetectionResult] = {
            res.detector_name: res for res in results_list
        }
        triggered = [res.detector_name for res in results_list if res.detected]

        composite_score = self._compute_composite_score(results_list)
        decision, blocked = self._determine_decision(composite_score, results)
        explanation = self._build_explanation(
            decision, composite_score, triggered, results
        )

        total_latency_ms = (time.perf_counter() - start_time) * 1000.0

        return EnsembleResult(
            decision=decision,
            composite_score=round(composite_score, 4),
            blocked=blocked,
            triggered_detectors=triggered,
            detector_results=results,
            explanation=explanation,
            total_latency_ms=round(total_latency_ms, 2),
        )

    async def detect(
        self, text: str, context: dict[str, Any] | None = None
    ) -> EnsembleResult:
        """Alias for analyze providing consistent interface with BaseDetector.

        Args:
            text: Raw input text to evaluate.
            context: Optional contextual parameters.

        Returns:
            EnsembleResult: Aggregate verdict produced by the ensemble.
        """
        return await self.analyze(text, context)

    def analyze_sync(
        self, text: str, context: dict[str, Any] | None = None
    ) -> EnsembleResult:
        """Synchronous wrapper for running the ensemble analysis.

        Args:
            text: Input string to evaluate.
            context: Optional contextual parameters.

        Returns:
            EnsembleResult: Aggregate verdict produced by the ensemble.

        Raises:
            DetectionError: If execution fails.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(
                    lambda: asyncio.run(self.analyze(text, context))
                ).result()
        return asyncio.run(self.analyze(text, context))

    def detect_sync(
        self, text: str, context: dict[str, Any] | None = None
    ) -> EnsembleResult:
        """Synchronous alias for analyze_sync.

        Args:
            text: Input string to evaluate.
            context: Optional contextual parameters.

        Returns:
            EnsembleResult: Aggregate verdict produced by the ensemble.
        """
        return self.analyze_sync(text, context)

"""Behavioral anomaly, session drift, and rate-burst threat detector module.

This module provides multi-dimensional behavioral anomaly detection for LLM sessions,
incorporating adaptive thresholds based on session baseline dispersion, sliding-window
score smoothing, multi-signal confirmation filters to eliminate isolated false alerts,
and multivariate Isolation Forest scoring calibrated against request traffic metrics.
"""

import time
from typing import Any

from sentinel.detection.base import BaseDetector, DetectionResult
from sentinel.exceptions import DetectionError


class AnomalyDetector(BaseDetector):
    """Detector for behavioral anomalies, rapid probing, and session drift.

    Attributes:
        name: Detector identifier ('anomaly').
        threshold: Score cutoff for declaring an anomaly.
    """

    def __init__(self, threshold: float = 0.65) -> None:
        """Initialize the AnomalyDetector with adaptive and confirmation controls.

        Args:
            threshold: Base anomaly score cutoff between 0.0 and 1.0.
        """
        super().__init__(name="anomaly", threshold=threshold)
        self._session_windows: dict[str, list[float]] = {}
        self._init_isolation_forest()

    def _init_isolation_forest(self) -> None:
        """Initialize multivariate Isolation Forest on baseline vectors."""
        from sklearn.ensemble import IsolationForest

        self._isolation_forest = IsolationForest(
            contamination=0.08, random_state=42, n_estimators=50
        )
        baseline_data = [
            [5.0, 50.0, 3.5],
            [10.0, 100.0, 4.0],
            [12.0, 120.0, 3.8],
            [8.0, 80.0, 4.2],
            [15.0, 150.0, 3.9],
            [6.0, 70.0, 3.7],
            [9.0, 90.0, 4.1],
            [11.0, 110.0, 3.6],
            [48.0, 480.0, 5.5],
            [55.0, 520.0, 5.8],
        ]
        self._isolation_forest.fit(baseline_data)

    def _compute_z_score(self, value: float, mean: float, std_dev: float) -> float:
        """Calculate statistical z-score distance from historical distribution.

        Args:
            value: Current observed value.
            mean: Historical mean.
            std_dev: Historical standard deviation.

        Returns:
            float: Computed z-score distance.
        """
        if std_dev <= 0.001:
            return 0.0
        return abs(value - mean) / std_dev

    def _compute_adaptive_threshold(self, context: dict[str, Any] | None) -> float:
        """Calculate dynamic threshold adjusted by session baseline dispersion.

        Args:
            context: Context mapping containing session baseline metrics.

        Returns:
            float: Adapted cutoff threshold between 0.50 and 0.85.
        """
        if context is None:
            return self._threshold
        mean_rpm = float(context.get("baseline_rpm_mean", 10.0))
        std_rpm = float(context.get("baseline_rpm_std", 5.0))
        dispersion = (std_rpm / mean_rpm) if mean_rpm > 0.0 else 0.5
        delta = (dispersion - 0.5) * 0.15
        adapted = self._threshold + delta
        return min(0.85, max(0.50, adapted))

    def _smooth_with_sliding_window(
        self, session_id: str, current_score: float, window_size: int = 5
    ) -> float:
        """Smooth raw score across recent turn window to suppress isolated spikes.


        Args:
            session_id: Unique identifier for active conversation session.
            current_score: Raw composite anomaly score for current turn.
            window_size: Maximum count of recent turns retained in window.

        Returns:
            float: Smoothed anomaly score.
        """
        if not session_id:
            return current_score
        history = self._session_windows.setdefault(session_id, [])
        history.append(current_score)
        if len(history) > window_size:
            history.pop(0)
        mean_history = sum(history) / len(history)
        return min(1.0, 0.70 * current_score + 0.30 * mean_history)

    def _apply_confirmation_filter(
        self, scores: list[float], categories: list[str]
    ) -> tuple[float, list[str]]:
        """Filter isolated single-signal spikes requiring multi-signal confirmation.

        Args:
            scores: Individual anomaly score dimensions.
            categories: Triggered anomaly categories.

        Returns:
            tuple[float, list[str]]: Filtered composite score and validated categories.
        """
        active_signals = [s for s in scores if s >= 0.50]
        max_score = max(scores) if scores else 0.0

        if len(active_signals) >= 2:
            boosted = min(1.0, max_score + 0.10)
            return boosted, categories
        if max_score >= 0.88:
            return max_score, categories

        dampened = max_score * 0.60
        return dampened, categories

    def _check_frequency_anomaly(self, context: dict[str, Any] | None) -> float:
        """Identify scraping or rapid automated request bursts.

        Args:
            context: Context containing session rate metrics.

        Returns:
            float: Threat contribution for request rate anomalies.
        """
        if context is None:
            return 0.0
        requests_per_minute = float(context.get("requests_per_minute", 0.0))
        mean_rpm = float(context.get("baseline_rpm_mean", 10.0))
        std_rpm = float(context.get("baseline_rpm_std", 5.0))

        z_score = self._compute_z_score(requests_per_minute, mean_rpm, std_rpm)
        if z_score > 3.0:
            return min(0.95, 0.45 + (z_score * 0.08))
        return 0.0

    def _check_length_anomaly(self, text: str, context: dict[str, Any] | None) -> float:
        """Detect sudden prompt length inflation or abnormal payload sizes.

        Args:
            text: Current message string.
            context: Context containing session length baselines.

        Returns:
            float: Threat contribution for length anomalies.
        """
        if context is None:
            return 0.0
        current_len = float(len(text))
        mean_len = float(context.get("baseline_len_mean", 120.0))
        std_len = float(context.get("baseline_len_std", 50.0))

        z_score = self._compute_z_score(current_len, mean_len, std_len)
        if z_score > 3.5:
            return min(0.90, 0.50 + (z_score * 0.05))
        return 0.0

    def _check_probing_patterns(
        self, text: str, context: dict[str, Any] | None
    ) -> float:
        """Identify repetitive probing or privilege escalation inquiry patterns.

        Args:
            text: Current prompt.
            context: Context containing recent history.

        Returns:
            float: Threat contribution for probing behaviors.
        """
        if context is None or "history" not in context:
            return 0.0
        history: list[str] = context.get("history", [])
        if len(history) < 2:
            return 0.0

        probing_terms = [
            "admin",
            "root",
            "permission",
            "schema",
            "credential",
            "auth",
            "token",
        ]
        lowered = text.lower()
        has_probing = any(term in lowered for term in probing_terms)
        probing_count = sum(
            1
            for turn in history[-5:]
            if any(t in str(turn).lower() for t in probing_terms)
        )
        if has_probing and probing_count >= 1:
            return min(0.90, 0.45 + (probing_count * 0.15))
        return 0.0

    def _check_isolation_forest(
        self, text: str, context: dict[str, Any] | None
    ) -> float:
        """Evaluate multivariate feature vector against trained Isolation Forest.

        Args:
            text: Input string.
            context: Context with rate and length metrics.

        Returns:
            float: Isolation forest anomaly score between 0.0 and 1.0.
        """
        if context is None:
            return 0.0
        rpm = float(context.get("requests_per_minute", 5.0))
        length = float(len(text))
        entropy = 4.0
        sample = [[rpm, length, entropy]]
        raw_score = -float(self._isolation_forest.decision_function(sample)[0])
        normalized = max(0.0, min(1.0, 0.50 + (raw_score * 2.0)))
        return normalized if normalized >= 0.65 else 0.0

    async def detect(
        self, text: str, context: dict[str, Any] | None = None
    ) -> DetectionResult:
        """Execute behavioral anomaly detection with confirmation and smoothing.

        Args:
            text: Input string.
            context: Context mapping containing session profiling statistics.

        Returns:
            DetectionResult: Structured evaluation with anomaly scores.

        Raises:
            DetectionError: If anomaly profiling encounters an unexpected error.
        """
        start_time = time.perf_counter()
        try:
            freq_score = self._check_frequency_anomaly(context)
            len_score = self._check_length_anomaly(text, context)
            probing_score = self._check_probing_patterns(text, context)
            iforest_score = self._check_isolation_forest(text, context)

            scores = [freq_score, len_score, probing_score, iforest_score]
            categories: list[str] = []
            if freq_score > 0.0:
                categories.append("rate_burst_anomaly")
            if len_score > 0.0:
                categories.append("payload_length_anomaly")
            if probing_score > 0.0:
                categories.append("privilege_probing_anomaly")
            if iforest_score > 0.0:
                categories.append("multivariate_isolation_forest")

            confirmed_score, validated_cats = self._apply_confirmation_filter(
                scores, categories
            )

            session_id = str(context.get("session_id", "")) if context else ""
            smoothed_score = self._smooth_with_sliding_window(
                session_id, confirmed_score
            )
            adaptive_threshold = self._compute_adaptive_threshold(context)
            is_detected = smoothed_score >= adaptive_threshold
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            details: dict[str, Any] = {
                "frequency_score": freq_score,
                "length_score": len_score,
                "probing_score": probing_score,
                "iforest_score": iforest_score,
                "confirmed_score": confirmed_score,
                "smoothed_score": smoothed_score,
                "adaptive_threshold": adaptive_threshold,
                "matched_anomalies": validated_cats,
            }

            primary_cat = validated_cats[0] if validated_cats else "clean"

            return DetectionResult(
                detector_name=self._name,
                detected=is_detected,
                score=round(smoothed_score, 4),
                category=primary_cat,
                details=details,
                latency_ms=round(duration_ms, 2),
            )
        except Exception as err:
            raise DetectionError(
                f"Anomaly detection failed: {err}",
                detector_name=self._name,
            ) from err

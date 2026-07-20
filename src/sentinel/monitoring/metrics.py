from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

_REGISTRY = CollectorRegistry(auto_describe=True)

DETECTIONS_TOTAL = Counter(
    "sentinel_detections_total",
    "Total count of security threats detected by category and detector.",
    ["detector", "severity", "category"],
    registry=_REGISTRY,
)

BLOCKED_TOTAL = Counter(
    "sentinel_blocked_total",
    "Total count of requests blocked by guardrails or policies.",
    ["reason", "tenant_id"],
    registry=_REGISTRY,
)

LATENCY_SECONDS = Histogram(
    "sentinel_latency_seconds",
    "Latency duration across execution stages.",
    ["stage"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1.0, 2.5),
    registry=_REGISTRY,
)

RISK_SCORE = Gauge(
    "sentinel_risk_score",
    "Most recent evaluated threat risk score per detector.",
    ["detector"],
    registry=_REGISTRY,
)


def record_detection(detector: str, severity: str, category: str) -> None:
    """Increment the detection counter for a given detector and threat category.

    Args:
        detector: Name of the detector reporting a threat.
        severity: Severity level (e.g., 'low', 'medium', 'high', 'critical').
        category: Threat classification category.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> record_detection("injection", "high", "direct_injection")
    """
    DETECTIONS_TOTAL.labels(
        detector=detector, severity=severity, category=category
    ).inc()


def record_block(reason: str, tenant_id: str = "default") -> None:
    """Increment the blocked requests counter.

    Args:
        reason: Rule or policy cause for blocking.
        tenant_id: Identifier of the tenant triggering the block.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> record_block("policy_violation", "tenant-1")
    """
    BLOCKED_TOTAL.labels(reason=reason, tenant_id=tenant_id).inc()


def record_latency(stage: str, seconds: float) -> None:
    """Record execution latency in seconds for a specific processing stage.

    Args:
        stage: Pipeline stage name (e.g., 'ensemble', 'input_guard').
        seconds: Duration elapsed in seconds.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> record_latency("ensemble", 0.045)
    """
    LATENCY_SECONDS.labels(stage=stage).observe(seconds)


def record_risk_score(detector: str, score: float) -> None:
    """Set the gauge for latest observed threat risk score.

    Args:
        detector: Identifier of the reporting detector.
        score: Computed score between 0.0 and 1.0.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> record_risk_score("pii", 0.95)
    """
    RISK_SCORE.labels(detector=detector).set(score)


def generate_metrics_payload() -> bytes:
    """Export all registered Prometheus metrics in text exposition format.

    Args:
        None

    Returns:
        bytes: Raw Prometheus text exposition bytes.

    Raises:
        None

    Examples:
        >>> payload = generate_metrics_payload()
        >>> b"sentinel_detections_total" in payload
        True
    """
    return generate_latest(_REGISTRY)

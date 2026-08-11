from fastapi import APIRouter, Request

from sentinel.api.schemas import (
    AuditQueryRequest,
    AuditQueryResponse,
    AuditRecordResponse,
    DetectionDetail,
    HealthResponse,
    InputGuardRequest,
    InputGuardResponse,
    OutputGuardRequest,
    OutputGuardResponse,
    PolicyEvaluationRequest,
    PolicyEvaluationResponse,
    ScanRequest,
    ScanResponse,
)
from sentinel.config import get_config
from sentinel.detection.ensemble import DetectionEnsemble
from sentinel.governance.audit import AuditLogger
from sentinel.governance.policies import PolicyEngine
from sentinel.guardrails.input_guard import InputGuard
from sentinel.guardrails.output_guard import OutputGuard

router = APIRouter(prefix="/api/v1", tags=["sentinel"])

_ensemble: DetectionEnsemble | None = None
_input_guard: InputGuard | None = None
_output_guard: OutputGuard | None = None
_audit_logger: AuditLogger | None = None
_policy_engine: PolicyEngine | None = None


def _get_ensemble() -> DetectionEnsemble:
    """Retrieve or lazily initialize the shared DetectionEnsemble.

    Args:
        None

    Returns:
        DetectionEnsemble: Shared ensemble instance.

    Raises:
        None

    Examples:
        >>> ensemble = _get_ensemble()
    """
    global _ensemble
    if _ensemble is None:
        _ensemble = DetectionEnsemble()
    return _ensemble


def _get_input_guard() -> InputGuard:
    """Retrieve or lazily initialize the shared InputGuard.

    Args:
        None

    Returns:
        InputGuard: Shared input guard instance.

    Raises:
        None

    Examples:
        >>> guard = _get_input_guard()
    """
    global _input_guard
    if _input_guard is None:
        _input_guard = InputGuard()
    return _input_guard


def _get_output_guard() -> OutputGuard:
    """Retrieve or lazily initialize the shared OutputGuard.

    Args:
        None

    Returns:
        OutputGuard: Shared output guard instance.

    Raises:
        None

    Examples:
        >>> guard = _get_output_guard()
    """
    global _output_guard
    if _output_guard is None:
        _output_guard = OutputGuard()
    return _output_guard


def _get_audit_logger() -> AuditLogger:
    """Retrieve or lazily initialize the shared AuditLogger.

    Args:
        None

    Returns:
        AuditLogger: Shared audit logger instance.

    Raises:
        None

    Examples:
        >>> logger = _get_audit_logger()
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def _get_policy_engine() -> PolicyEngine:
    """Retrieve or lazily initialize the shared PolicyEngine.

    Args:
        None

    Returns:
        PolicyEngine: Shared policy engine instance.

    Raises:
        None

    Examples:
        >>> engine = _get_policy_engine()
    """
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine


def reset_route_singletons() -> None:
    """Reset all lazily initialized route singletons for testing.

    Args:
        None

    Returns:
        None

    Raises:
        None

    Examples:
        >>> reset_route_singletons()
    """
    global _ensemble, _input_guard, _output_guard, _audit_logger, _policy_engine
    _ensemble = None
    _input_guard = None
    _output_guard = None
    _audit_logger = None
    _policy_engine = None


@router.post("/scan", response_model=ScanResponse)
async def scan_text(payload: ScanRequest, request: Request) -> ScanResponse:
    """Run ensemble detection analysis on the provided text.

    Args:
        payload: ScanRequest with text content and options.
        request: FastAPI request object.

    Returns:
        ScanResponse: Detection results and threat assessment.

    Raises:
        None

    Examples:
        >>> pass
    """
    ensemble = _get_ensemble()
    result = await ensemble.analyze(payload.text, payload.context)

    correlation_id: str | None = getattr(request.state, "correlation_id", None)

    detections: list[DetectionDetail] = [
        DetectionDetail(
            detector_name=det_result.detector_name,
            detected=det_result.detected,
            score=det_result.score,
            category=det_result.category,
        )
        for det_result in result.detector_results.values()
    ]

    return ScanResponse(
        decision=result.decision,
        blocked=result.blocked,
        composite_score=result.composite_score,
        triggered_detectors=result.triggered_detectors,
        explanation=result.explanation,
        detections=detections,
        total_latency_ms=result.total_latency_ms,
        correlation_id=correlation_id,
    )


@router.post("/guard/input", response_model=InputGuardResponse)
async def guard_input(payload: InputGuardRequest) -> InputGuardResponse:
    """Evaluate user input through the pre-LLM guardrail pipeline.

    Args:
        payload: InputGuardRequest with text and evaluation options.

    Returns:
        InputGuardResponse: Guardrail evaluation outcome.

    Raises:
        None

    Examples:
        >>> pass
    """
    guard = _get_input_guard()
    result = await guard.guard(payload.text, payload.context, payload.raise_on_block)
    return InputGuardResponse(
        allowed=result.allowed,
        processed_text=result.processed_text,
        blocked=result.blocked,
        threat_score=result.threat_score,
        reason=result.reason,
        anonymization_mapping=result.anonymization_mapping,
    )


@router.post("/guard/output", response_model=OutputGuardResponse)
async def guard_output(payload: OutputGuardRequest) -> OutputGuardResponse:
    """Evaluate LLM output through the post-LLM guardrail pipeline.

    Args:
        payload: OutputGuardRequest with text and evaluation options.

    Returns:
        OutputGuardResponse: Guardrail evaluation outcome.

    Raises:
        None

    Examples:
        >>> pass
    """
    guard = _get_output_guard()
    result = await guard.guard(
        payload.text,
        payload.anonymization_mapping,
        payload.deanonymize,
        payload.raise_on_block,
    )
    return OutputGuardResponse(
        allowed=result.allowed,
        processed_text=result.processed_text,
        blocked=result.blocked,
        redacted=result.redacted,
        leakage_detected=result.leakage_detected,
        watermarked=result.watermarked,
        reason=result.reason,
    )


@router.post("/audit", response_model=AuditQueryResponse)
async def query_audit(payload: AuditQueryRequest) -> AuditQueryResponse:
    """Query audit log records with optional filtering.

    Args:
        payload: AuditQueryRequest with filter parameters.

    Returns:
        AuditQueryResponse: Matching audit records.

    Raises:
        None

    Examples:
        >>> pass
    """
    audit_logger = _get_audit_logger()
    records = audit_logger.list_records(
        tenant_id=payload.tenant_id,
        limit=payload.limit,
    )

    response_records: list[AuditRecordResponse] = [
        AuditRecordResponse(
            record_id=record.record_id,
            session_id=record.session_id,
            tenant_id=record.tenant_id,
            timestamp=record.timestamp,
            input_text=record.input_text,
            output_text=record.output_text,
            decision=record.decision,
            composite_score=record.composite_score,
            details=record.details,
            block_hash=record.block_hash,
        )
        for record in records
    ]

    return AuditQueryResponse(
        records=response_records,
        total=len(response_records),
    )


@router.post("/policy/evaluate", response_model=PolicyEvaluationResponse)
async def evaluate_policy(
    payload: PolicyEvaluationRequest,
) -> PolicyEvaluationResponse:
    """Evaluate input text against registered security policies.

    Args:
        payload: PolicyEvaluationRequest with text and policy options.

    Returns:
        PolicyEvaluationResponse: Compliance status and violations.

    Raises:
        None

    Examples:
        >>> pass
    """
    ensemble = _get_ensemble()
    ensemble_result = await ensemble.analyze(payload.text, payload.context)

    engine = _get_policy_engine()
    detection_map: dict[str, float] = {
        name: det.score for name, det in ensemble_result.detector_results.items()
    }

    violations: list[str] = []
    action_taken: str = "allow"

    for policy_id, _policy in engine.policies.items():
        if payload.policy_id is not None and policy_id != payload.policy_id:
            continue
        action, triggered_rule = engine.evaluate(policy_id, detection_map)
        if triggered_rule is not None:
            violations.append(triggered_rule)
            if action == "block":
                action_taken = "block"

    return PolicyEvaluationResponse(
        compliant=len(violations) == 0,
        violations=violations,
        action_taken=action_taken,
        details={"composite_score": ensemble_result.composite_score},
    )


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return system health status and version information.

    Args:
        None

    Returns:
        HealthResponse: System health payload.

    Raises:
        None

    Examples:
        >>> pass
    """
    from sentinel import __version__

    config = get_config()
    return HealthResponse(
        status="healthy",
        version=__version__,
        environment=config.environment,
        checks={
            "detection": "operational",
            "governance": "operational",
            "monitoring": "operational",
        },
    )

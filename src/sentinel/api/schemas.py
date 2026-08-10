from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Inbound payload for the detection scan endpoint.

    Attributes:
        text: Raw text content to analyze for security threats.
        context: Optional contextual metadata such as conversation history.
    """

    text: str = Field(..., min_length=1, max_length=100_000)
    context: dict[str, Any] | None = Field(default=None)


class DetectionDetail(BaseModel):
    """Individual detector result within a scan response.

    Attributes:
        detector_name: Identifier of the detector that produced this result.
        detected: Whether a threat was identified.
        score: Confidence score between 0.0 and 1.0.
        category: Threat category label.
    """

    detector_name: str
    detected: bool
    score: float = Field(ge=0.0, le=1.0)
    category: str


class ScanResponse(BaseModel):
    """Response payload from the detection scan endpoint.

    Attributes:
        decision: Final governance action (allow, warn, block).
        blocked: Whether the input was blocked by policy enforcement.
        composite_score: Aggregated threat risk score.
        triggered_detectors: List of detectors that flagged threats.
        explanation: Summary justification for the scan outcome.
        detections: Per-detector breakdown of results.
        total_latency_ms: Ensemble execution time in milliseconds.
        correlation_id: Trace identifier for this request.
    """

    decision: str
    blocked: bool
    composite_score: float = Field(ge=0.0, le=1.0)
    triggered_detectors: list[str] = Field(default_factory=list)
    explanation: str
    detections: list[DetectionDetail] = Field(default_factory=list)
    total_latency_ms: float = Field(default=0.0, ge=0.0)
    correlation_id: str | None = Field(default=None)


class InputGuardRequest(BaseModel):
    """Inbound payload for the input guardrail endpoint.

    Attributes:
        text: Text content to evaluate through input guardrails.
        context: Optional contextual metadata.
        raise_on_block: Whether to raise a policy violation on block.
    """

    text: str = Field(..., min_length=1, max_length=100_000)
    context: dict[str, Any] | None = Field(default=None)
    raise_on_block: bool = Field(default=False)


class InputGuardResponse(BaseModel):
    """Response payload from the input guardrail endpoint.

    Attributes:
        allowed: Whether the text passed guardrail evaluation.
        processed_text: Sanitized or anonymized version of the text.
        blocked: Whether the text was blocked.
        threat_score: Evaluated threat risk score.
        reason: Explanatory justification for the outcome.
        anonymization_mapping: Reversible PII token mapping if applicable.
    """

    allowed: bool
    processed_text: str
    blocked: bool
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str | None = Field(default=None)
    anonymization_mapping: dict[str, str] = Field(default_factory=dict)


class OutputGuardRequest(BaseModel):
    """Inbound payload for the output guardrail endpoint.

    Attributes:
        text: LLM output text to evaluate through output guardrails.
        anonymization_mapping: Token map generated during input guard phase.
        deanonymize: Whether to restore tokens to original values.
        raise_on_block: Whether to raise a policy violation on block.
    """

    text: str = Field(..., min_length=1, max_length=100_000)
    anonymization_mapping: dict[str, str] | None = Field(default=None)
    deanonymize: bool = Field(default=True)
    raise_on_block: bool = Field(default=False)


class OutputGuardResponse(BaseModel):
    """Response payload from the output guardrail endpoint.

    Attributes:
        allowed: Whether the output is safe for delivery.
        processed_text: Final sanitized response text.
        blocked: Whether the output was blocked.
        redacted: Whether sensitive content was redacted.
        leakage_detected: Whether credential leakage was found.
        watermarked: Whether watermarking was applied.
        reason: Explanatory justification for the outcome.
    """

    allowed: bool
    processed_text: str
    blocked: bool
    redacted: bool = Field(default=False)
    leakage_detected: bool = Field(default=False)
    watermarked: bool = Field(default=False)
    reason: str | None = Field(default=None)


class AuditQueryRequest(BaseModel):
    """Request parameters for querying audit log records.

    Attributes:
        tenant_id: Filter records by tenant identifier.
        limit: Maximum number of records to return.
    """

    tenant_id: str | None = Field(default=None)
    limit: int = Field(default=50, ge=1, le=1000)


class AuditRecordResponse(BaseModel):
    """Serialized representation of a single audit log entry.

    Attributes:
        record_id: Unique identifier for this audit record.
        session_id: Session context identifier.
        tenant_id: Tenant that produced the event.
        timestamp: Epoch timestamp of the event.
        input_text: Raw user prompt input.
        output_text: Generated assistant response.
        decision: Governance action taken.
        composite_score: Evaluated threat risk score.
        details: Structured metadata associated with the event.
        block_hash: Hash chain block digest.
    """

    record_id: str
    session_id: str
    tenant_id: str
    timestamp: float
    input_text: str
    output_text: str
    decision: str
    composite_score: float
    details: dict[str, Any] = Field(default_factory=dict)
    block_hash: str


class AuditQueryResponse(BaseModel):
    """Response payload from the audit query endpoint.

    Attributes:
        records: List of matching audit records.
        total: Total number of matching records.
    """

    records: list[AuditRecordResponse] = Field(default_factory=list)
    total: int = Field(default=0, ge=0)


class PolicyEvaluationRequest(BaseModel):
    """Request payload for policy evaluation against detection results.

    Attributes:
        text: Input text to scan and evaluate.
        policy_id: Identifier of the policy to apply.
        context: Optional contextual metadata.
    """

    text: str = Field(..., min_length=1, max_length=100_000)
    policy_id: str | None = Field(default=None)
    context: dict[str, Any] | None = Field(default=None)


class PolicyEvaluationResponse(BaseModel):
    """Response payload from the policy evaluation endpoint.

    Attributes:
        compliant: Whether the input passes all policy rules.
        violations: List of policy rule names that were violated.
        action_taken: Action executed as a result of evaluation.
        details: Additional evaluation metadata.
    """

    compliant: bool
    violations: list[str] = Field(default_factory=list)
    action_taken: str = Field(default="allow")
    details: dict[str, Any] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """Response payload for the system health check endpoint.

    Attributes:
        status: Overall system health status.
        version: Running SENTINEL framework version.
        environment: Active deployment environment.
        checks: Individual subsystem health check results.
    """

    status: str = Field(default="healthy")
    version: str
    environment: str
    checks: dict[str, str] = Field(default_factory=dict)

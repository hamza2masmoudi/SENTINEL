"""API subsystem for SENTINEL, providing FastAPI-based HTTP security endpoints."""

from sentinel.api.app import create_app
from sentinel.api.middleware import (
    AuthenticationMiddleware,
    CorrelationIdMiddleware,
    RateLimitMiddleware,
)
from sentinel.api.routes import router
from sentinel.api.schemas import (
    AuditQueryRequest,
    AuditQueryResponse,
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

__all__: list[str] = [
    "create_app",
    "router",
    "CorrelationIdMiddleware",
    "RateLimitMiddleware",
    "AuthenticationMiddleware",
    "ScanRequest",
    "ScanResponse",
    "InputGuardRequest",
    "InputGuardResponse",
    "OutputGuardRequest",
    "OutputGuardResponse",
    "AuditQueryRequest",
    "AuditQueryResponse",
    "PolicyEvaluationRequest",
    "PolicyEvaluationResponse",
    "HealthResponse",
]

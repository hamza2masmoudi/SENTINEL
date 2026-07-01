"""SENTINEL: Security Evaluation & Neural Tracing for Intelligent Language-models.

A production-grade open-source security and governance framework for LLM agents.
"""

from sentinel.config import (
    DetectionConfig,
    GovernanceConfig,
    MonitoringConfig,
    SecurityConfig,
    SentinelConfig,
    get_config,
    reset_config,
)
from sentinel.exceptions import (
    AuditIntegrityError,
    AuthenticationError,
    ConfigurationError,
    DetectionError,
    NetworkTimeoutError,
    PolicyViolationError,
    RateLimitExceededError,
    SentinelError,
    StorageError,
)
from sentinel.logging import (
    clear_correlation_id,
    clear_tenant_id,
    configure_logging,
    get_correlation_id,
    get_logger,
    get_tenant_id,
    set_correlation_id,
    set_tenant_id,
)

__version__: str = "0.1.0"

__all__: list[str] = [
    "__version__",
    "SentinelConfig",
    "DetectionConfig",
    "MonitoringConfig",
    "GovernanceConfig",
    "SecurityConfig",
    "get_config",
    "reset_config",
    "SentinelError",
    "ConfigurationError",
    "DetectionError",
    "PolicyViolationError",
    "AuditIntegrityError",
    "NetworkTimeoutError",
    "AuthenticationError",
    "RateLimitExceededError",
    "StorageError",
    "configure_logging",
    "get_logger",
    "get_correlation_id",
    "set_correlation_id",
    "clear_correlation_id",
    "get_tenant_id",
    "set_tenant_id",
    "clear_tenant_id",
]

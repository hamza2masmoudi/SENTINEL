import threading
from typing import Literal

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DetectionConfig(BaseModel):
    """Configuration options for security detectors.

    Attributes:
        injection_threshold: Score threshold for prompt injection.
        jailbreak_threshold: Score threshold for jailbreak attempt.
        toxicity_threshold: Score threshold for toxic content.
        anomaly_threshold: Score threshold for behavioral anomaly.
        pii_enabled: Flag indicating if PII detection is active.
        secrets_enabled: Flag indicating if secret detection is active.
        max_latency_ms: Maximum target detection latency in milliseconds.
    """

    injection_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    jailbreak_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    toxicity_threshold: float = Field(default=0.60, ge=0.0, le=1.0)
    anomaly_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    pii_enabled: bool = Field(default=True)
    secrets_enabled: bool = Field(default=True)
    max_latency_ms: float = Field(default=200.0, gt=0.0)


class MonitoringConfig(BaseModel):
    """Configuration options for system tracing, metrics, and alerts.

    Attributes:
        otel_exporter_endpoint: OpenTelemetry gRPC/HTTP collector endpoint.
        otel_service_name: Service name identifier used in traces.
        metrics_enabled: Flag indicating if Prometheus metrics export is active.
        prometheus_port: Listening port for the Prometheus metrics scrape server.
        alert_webhook_url: Webhook URL for critical security notifications.
        alert_rate_limit_seconds: Minimum time interval between identical alerts.
    """

    otel_exporter_endpoint: str = Field(default="http://localhost:4317")
    otel_service_name: str = Field(default="sentinel-guard")
    metrics_enabled: bool = Field(default=True)
    prometheus_port: int = Field(default=9090, ge=1, le=65535)
    alert_webhook_url: str | None = Field(default=None)
    alert_rate_limit_seconds: float = Field(default=30.0, ge=1.0)


class GovernanceConfig(BaseModel):
    """Configuration options for audit logs, policies, and compliance.

    Attributes:
        storage_backend: Active storage technology (sqlite or postgresql).
        database_url: Database connection string.
        hash_chain_algorithm: Hashing algorithm for integrity verification.
        auto_verify_chain_on_startup: Verify log integrity on boot.
        retention_days: Number of days before audit logs are archived.
    """

    storage_backend: Literal["sqlite", "postgresql"] = Field(default="sqlite")
    database_url: str = Field(default="sqlite+aiosqlite:///./sentinel.db")
    hash_chain_algorithm: Literal["sha256", "sha512"] = Field(default="sha256")
    auto_verify_chain_on_startup: bool = Field(default=True)
    retention_days: int = Field(default=365, ge=1)


class SecurityConfig(BaseModel):
    """Configuration options for security constraints, network calls, and auth.

    Attributes:
        api_key_header_name: Name of the HTTP header carrying API keys.
        admin_api_key: Secret API key for administrative endpoints.
        rate_limit_per_minute: Maximum allowed requests per minute.
        network_timeout_seconds: Timeout for outbound network requests.
        network_max_retries: Maximum retries for failed network requests.
        network_backoff_factor: Multiplier for exponential backoff.
    """

    api_key_header_name: str = Field(default="X-API-Key")
    admin_api_key: str | None = Field(default=None)
    rate_limit_per_minute: int = Field(default=600, ge=1)
    network_timeout_seconds: float = Field(default=10.0, gt=0.0)
    network_max_retries: int = Field(default=3, ge=0)
    network_backoff_factor: float = Field(default=1.5, ge=1.0)


class SentinelConfig(BaseSettings):
    """Root configuration object for the SENTINEL framework.

    Attributes:
        environment: Deployment stage (development, staging, or production).
        log_level: Severity threshold for logging.
        log_format: Formatter for log output (json or console).
        detection: Sub-configuration for detection algorithms.
        monitoring: Sub-configuration for metrics and tracing.
        governance: Sub-configuration for audit and hash chain verification.
        security: Sub-configuration for network constraints and authentication.
    """

    environment: Literal["development", "staging", "production"] = Field(
        default="development"
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO"
    )
    log_format: Literal["json", "console"] = Field(default="json")

    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    governance: GovernanceConfig = Field(default_factory=GovernanceConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_nested_delimiter="__",
        extra="ignore",
    )


_GLOBAL_CONFIG_LOCK = threading.Lock()
_GLOBAL_CONFIG: SentinelConfig | None = None


def get_config() -> SentinelConfig:
    """Retrieve the global thread-safe SentinelConfig singleton.

    Args:
        None

    Returns:
        SentinelConfig: The active configuration instance.

    Raises:
        None

    Examples:
        >>> config = get_config()
        >>> config.environment
        'development'
    """
    global _GLOBAL_CONFIG
    if _GLOBAL_CONFIG is None:
        with _GLOBAL_CONFIG_LOCK:
            if _GLOBAL_CONFIG is None:
                _GLOBAL_CONFIG = SentinelConfig()
    return _GLOBAL_CONFIG


def reset_config(new_config: SentinelConfig | None = None) -> None:
    """Reset or override the global SentinelConfig instance.

    Args:
        new_config: Optional new configuration instance to install.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> reset_config(SentinelConfig(environment="production"))
        >>> get_config().environment
        'production'
    """
    global _GLOBAL_CONFIG
    with _GLOBAL_CONFIG_LOCK:
        _GLOBAL_CONFIG = new_config

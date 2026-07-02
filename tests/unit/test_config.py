import os

import pytest
from pydantic import ValidationError

from sentinel.config import (
    DetectionConfig,
    MonitoringConfig,
    SecurityConfig,
    SentinelConfig,
    get_config,
    reset_config,
)


def test_default_configuration_values() -> None:
    """Verify that default settings conform to expected baseline values.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If a default value fails expectation.
    """
    config = SentinelConfig()
    assert config.environment == "development"
    assert config.log_level == "INFO"
    assert config.log_format == "json"

    assert config.detection.injection_threshold == 0.70
    assert config.detection.jailbreak_threshold == 0.70
    assert config.detection.toxicity_threshold == 0.60
    assert config.detection.anomaly_threshold == 0.75
    assert config.detection.pii_enabled is True
    assert config.detection.secrets_enabled is True
    assert config.detection.max_latency_ms == 200.0

    assert config.monitoring.otel_service_name == "sentinel-guard"
    assert config.monitoring.metrics_enabled is True
    assert config.monitoring.prometheus_port == 9090

    assert config.governance.storage_backend == "sqlite"
    assert config.governance.hash_chain_algorithm == "sha256"
    assert config.governance.retention_days == 365

    assert config.security.api_key_header_name == "X-API-Key"
    assert config.security.rate_limit_per_minute == 600
    assert config.security.network_timeout_seconds == 10.0


def test_environment_variable_overrides() -> None:
    """Verify that environment variables properly override configuration defaults.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If environment variable values are not applied.
    """
    os.environ["SENTINEL_ENVIRONMENT"] = "production"
    os.environ["SENTINEL_LOG_LEVEL"] = "DEBUG"
    os.environ["SENTINEL_DETECTION__INJECTION_THRESHOLD"] = "0.85"
    os.environ["SENTINEL_GOVERNANCE__STORAGE_BACKEND"] = "postgresql"
    os.environ["SENTINEL_SECURITY__RATE_LIMIT_PER_MINUTE"] = "1200"

    config = SentinelConfig()
    assert config.environment == "production"
    assert config.log_level == "DEBUG"
    assert config.detection.injection_threshold == 0.85
    assert config.governance.storage_backend == "postgresql"
    assert config.security.rate_limit_per_minute == 1200


def test_threshold_validation_boundaries() -> None:
    """Verify that numeric thresholds outside valid bounds raise validation errors.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If validation fails to reject illegal bounds.
    """
    with pytest.raises(ValidationError):
        DetectionConfig(injection_threshold=1.5)

    with pytest.raises(ValidationError):
        DetectionConfig(jailbreak_threshold=-0.1)

    with pytest.raises(ValidationError):
        MonitoringConfig(prometheus_port=70000)

    with pytest.raises(ValidationError):
        SecurityConfig(rate_limit_per_minute=0)


def test_global_config_singleton_lifecycle() -> None:
    """Verify the singleton behavior and reset capability of global configuration.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If singleton caching or resetting fails.
    """
    first_instance = get_config()
    second_instance = get_config()
    assert first_instance is second_instance

    custom_instance = SentinelConfig(environment="staging")
    reset_config(custom_instance)
    retrieved_instance = get_config()
    assert retrieved_instance is custom_instance
    assert retrieved_instance.environment == "staging"

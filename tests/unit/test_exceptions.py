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


def test_base_sentinel_error() -> None:
    """Verify base SentinelError serialization and inheritance attributes.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If base exception attributes do not match.
    """
    error = SentinelError("Generic system error", {"trace_id": "t-100"})
    assert str(error) == "Generic system error"
    assert error.message == "Generic system error"
    assert error.details["trace_id"] == "t-100"

    serialized = error.to_dict()
    assert serialized["error_type"] == "SentinelError"
    assert serialized["message"] == "Generic system error"
    assert serialized["details"]["trace_id"] == "t-100"


def test_configuration_error() -> None:
    """Verify ConfigurationError attributes and inheritance.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If ConfigurationError properties fail validation.
    """
    error = ConfigurationError("Missing key", {"param": "api_key"})
    assert isinstance(error, SentinelError)
    assert error.details["param"] == "api_key"


def test_detection_error() -> None:
    """Verify DetectionError carries detector metadata properly.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If detector attributes fail validation.
    """
    error = DetectionError("Model inference timeout", detector_name="pii_presidio")
    assert isinstance(error, SentinelError)
    assert error.detector_name == "pii_presidio"
    assert error.details["detector_name"] == "pii_presidio"


def test_policy_violation_error() -> None:
    """Verify PolicyViolationError captures policy name and action taken.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If policy violation fields do not match.
    """
    error = PolicyViolationError(
        "Direct injection detected",
        policy_name="block_prompt_injection",
        action_taken="terminate_session",
    )
    assert isinstance(error, SentinelError)
    assert error.policy_name == "block_prompt_injection"
    assert error.action_taken == "terminate_session"
    assert error.details["action_taken"] == "terminate_session"


def test_audit_integrity_error() -> None:
    """Verify AuditIntegrityError preserves cryptographic integrity details.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If cryptographic fields fail verification.
    """
    error = AuditIntegrityError(
        "Hash mismatch at block 42",
        record_id="rec-42",
        expected_hash="hash_a",
        actual_hash="hash_b",
    )
    assert isinstance(error, SentinelError)
    assert error.record_id == "rec-42"
    assert error.expected_hash == "hash_a"
    assert error.actual_hash == "hash_b"
    assert error.details["record_id"] == "rec-42"


def test_network_timeout_error() -> None:
    """Verify NetworkTimeoutError records remote service and duration.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If service name or timeout values differ.
    """
    error = NetworkTimeoutError(
        "LLM gateway did not respond",
        service_name="ollama_gateway",
        timeout_seconds=5.5,
    )
    assert isinstance(error, SentinelError)
    assert error.service_name == "ollama_gateway"
    assert error.timeout_seconds == 5.5
    assert error.details["timeout_seconds"] == 5.5


def test_authentication_error() -> None:
    """Verify AuthenticationError retains target identity.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If identity attribute does not match.
    """
    error = AuthenticationError("Unauthorized key", identity="tenant-alpha")
    assert isinstance(error, SentinelError)
    assert error.identity == "tenant-alpha"
    assert error.details["identity"] == "tenant-alpha"


def test_rate_limit_exceeded_error() -> None:
    """Verify RateLimitExceededError retains retry duration.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If retry duration does not match.
    """
    error = RateLimitExceededError("Rate exceeded", retry_after_seconds=45.0)
    assert isinstance(error, SentinelError)
    assert error.retry_after_seconds == 45.0
    assert error.details["retry_after_seconds"] == 45.0


def test_storage_error() -> None:
    """Verify StorageError retains backend label.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If backend label does not match.
    """
    error = StorageError("Connection refused", backend="postgresql")
    assert isinstance(error, SentinelError)
    assert error.backend == "postgresql"
    assert error.details["backend"] == "postgresql"

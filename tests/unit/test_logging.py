import structlog

from sentinel.logging import (
    _context_processor,
    clear_correlation_id,
    clear_tenant_id,
    configure_logging,
    get_correlation_id,
    get_logger,
    get_tenant_id,
    set_correlation_id,
    set_tenant_id,
)


def test_correlation_id_context_lifecycle() -> None:
    """Verify set, get, and clear operations for correlation identifiers.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If correlation context is not correctly managed.
    """
    assert get_correlation_id() is None

    set_correlation_id("test-corr-123")
    assert get_correlation_id() == "test-corr-123"

    clear_correlation_id()
    assert get_correlation_id() is None


def test_tenant_id_context_lifecycle() -> None:
    """Verify set, get, and clear operations for tenant identifiers.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If tenant context is not correctly managed.
    """
    assert get_tenant_id() is None

    set_tenant_id("tenant-omega")
    assert get_tenant_id() == "tenant-omega"

    clear_tenant_id()
    assert get_tenant_id() is None


def test_context_processor_injects_metadata() -> None:
    """Verify that structlog context processor augments event dictionary.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If context values are omitted from event payload.
    """
    set_correlation_id("corr-xyz")
    set_tenant_id("tenant-abc")

    event_dict: dict[str, object] = {"event": "security_scan_started"}
    augmented = _context_processor(structlog.get_logger(), "info", event_dict)

    assert augmented["correlation_id"] == "corr-xyz"
    assert augmented["tenant_id"] == "tenant-abc"
    assert augmented["event"] == "security_scan_started"


def test_configure_logging_formats() -> None:
    """Verify logging configuration execution across supported output formats.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If logging configuration fails to initialize.
    """
    configure_logging(level="DEBUG", log_format="json")
    logger_json = get_logger("sentinel.test_json")
    assert logger_json is not None

    configure_logging(level="INFO", log_format="console")
    logger_console = get_logger("sentinel.test_console")
    assert logger_console is not None


def test_structured_log_output_captures_fields() -> None:
    """Verify logger invocation executes without errors when passing structured kwargs.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If structured logging raises unexpected exceptions.
    """
    configure_logging(level="INFO", log_format="json")
    logger = get_logger("sentinel.verification")

    set_correlation_id("trace-999")
    set_tenant_id("tenant-corp")

    logger.info("guardrail_evaluated", detector="injection", score=0.92)
    assert get_correlation_id() == "trace-999"
    assert get_tenant_id() == "tenant-corp"

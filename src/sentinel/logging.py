import logging
import sys
from collections.abc import MutableMapping
from contextvars import ContextVar
from typing import Any

import structlog

_CORRELATION_ID_VAR: ContextVar[str | None] = ContextVar(
    "sentinel_correlation_id", default=None
)
_TENANT_ID_VAR: ContextVar[str | None] = ContextVar("sentinel_tenant_id", default=None)


def get_correlation_id() -> str | None:
    """Retrieve the current correlation identifier from context.

    Args:
        None

    Returns:
        str | None: The active correlation ID or None if not set.

    Raises:
        None

    Examples:
        >>> get_correlation_id() is None
        True
    """
    return _CORRELATION_ID_VAR.get()


def set_correlation_id(correlation_id: str) -> None:
    """Store a correlation identifier in the execution context.

    Args:
        correlation_id: Unique request or trace correlation string.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> set_correlation_id("req-12345")
        >>> get_correlation_id()
        'req-12345'
    """
    _CORRELATION_ID_VAR.set(correlation_id)


def clear_correlation_id() -> None:
    """Remove the active correlation identifier from the context.

    Args:
        None

    Returns:
        None

    Raises:
        None

    Examples:
        >>> set_correlation_id("req-999")
        >>> clear_correlation_id()
        >>> get_correlation_id() is None
        True
    """
    _CORRELATION_ID_VAR.set(None)


def get_tenant_id() -> str | None:
    """Retrieve the current tenant identifier from context.

    Args:
        None

    Returns:
        str | None: The active tenant ID or None if unset.

    Raises:
        None

    Examples:
        >>> get_tenant_id() is None
        True
    """
    return _TENANT_ID_VAR.get()


def set_tenant_id(tenant_id: str) -> None:
    """Store a tenant identifier in the execution context.

    Args:
        tenant_id: Multi-tenant client namespace identifier.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> set_tenant_id("tenant-acme")
        >>> get_tenant_id()
        'tenant-acme'
    """
    _TENANT_ID_VAR.set(tenant_id)


def clear_tenant_id() -> None:
    """Remove the active tenant identifier from the execution context.

    Args:
        None

    Returns:
        None

    Raises:
        None

    Examples:
        >>> set_tenant_id("tenant-xyz")
        >>> clear_tenant_id()
        >>> get_tenant_id() is None
        True
    """
    _TENANT_ID_VAR.set(None)


def _context_processor(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Inject contextual metadata into structlog event dictionaries.

    Args:
        logger: Wrapped logger instance.
        method_name: Logging method invoked.
        event_dict: Event payload mapping to augment.

    Returns:
        MutableMapping[str, Any]: Augmented event dictionary.

    Raises:
        None

    Examples:
        >>> payload = {}
        >>> _context_processor(None, "info", payload)
        {}
    """
    correlation_id = _CORRELATION_ID_VAR.get()
    if correlation_id is not None:
        event_dict["correlation_id"] = correlation_id

    tenant_id = _TENANT_ID_VAR.get()
    if tenant_id is not None:
        event_dict["tenant_id"] = tenant_id

    return event_dict


def configure_logging(level: str = "INFO", log_format: str = "json") -> None:
    """Configure global structured logging with JSON or console formatting.

    Args:
        level: Logging level string (DEBUG, INFO, WARNING, ERROR).
        log_format: Desired log renderer (json or console).

    Returns:
        None

    Raises:
        None

    Examples:
        >>> configure_logging(level="INFO", log_format="json")
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=numeric_level)

    renderer: structlog.types.Processor
    if log_format.lower() == "console":
        renderer = structlog.dev.ConsoleRenderer(colors=False)
    else:
        renderer = structlog.processors.JSONRenderer()

    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        _context_processor,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        renderer,
    ]

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "sentinel") -> structlog.stdlib.BoundLogger:
    """Return a configured structured logger instance.

    Args:
        name: Logger namespace string.

    Returns:
        structlog.stdlib.BoundLogger: Bound structured logger instance.

    Raises:
        None

    Examples:
        >>> log = get_logger("sentinel.core")
        >>> log is not None
        True
    """
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)

from sentinel.logging import get_correlation_id

_INITIALIZED: bool = False


def configure_tracer(
    service_name: str = "sentinel-guard",
    console_export: bool = False,
) -> trace.Tracer:
    """Initialize and configure global OpenTelemetry tracer provider.

    Args:
        service_name: Service identifier for emitted traces.
        console_export: Whether to print spans directly to stdout.

    Returns:
        trace.Tracer: Configured tracer instance.

    Raises:
        None

    Examples:
        >>> tracer = configure_tracer("test-service")
        >>> tracer is not None
        True
    """
    global _INITIALIZED
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    if console_export:
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)
    _INITIALIZED = True
    return trace.get_tracer(service_name)


def get_tracer(name: str = "sentinel") -> trace.Tracer:
    """Retrieve an active OpenTelemetry tracer.

    Args:
        name: Tracer component name.

    Returns:
        trace.Tracer: Active tracer instance.

    Raises:
        None

    Examples:
        >>> tracer = get_tracer("sentinel.eval")
        >>> tracer is not None
        True
    """
    return trace.get_tracer(name)


@contextmanager
def trace_span(
    name: str,
    attributes: dict[str, Any] | None = None,
) -> Generator[trace.Span, None, None]:
    """Context manager executing a code block within an OpenTelemetry span.

    Args:
        name: Name of the span.
        attributes: Key-value attributes to attach to the span.

    Returns:
        Generator[trace.Span, None, None]: Yields active span.

    Raises:
        None

    Examples:
        >>> with trace_span("test_step") as span:
        ...     span.set_attribute("status", "ok")
    """
    tracer = get_tracer("sentinel")
    with tracer.start_as_current_span(name) as span:
        corr_id = get_correlation_id()
        if corr_id is not None:
            span.set_attribute("sentinel.correlation_id", corr_id)

        if attributes is not None:
            for key, val in attributes.items():
                if isinstance(val, (bool, str, bytes, int, float)):
                    span.set_attribute(f"sentinel.{key}", val)
                else:
                    span.set_attribute(f"sentinel.{key}", str(val))
        yield span

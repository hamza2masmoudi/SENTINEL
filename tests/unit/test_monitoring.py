from unittest.mock import AsyncMock, patch

import httpx
import pytest

from sentinel.exceptions import NetworkTimeoutError
from sentinel.logging import set_correlation_id
from sentinel.monitoring.alerts import AlertManager, AlertPayload
from sentinel.monitoring.metrics import (
    generate_metrics_payload,
    record_block,
    record_detection,
    record_latency,
    record_risk_score,
)
from sentinel.monitoring.session import SessionManager
from sentinel.monitoring.tracer import configure_tracer, trace_span


def test_tracer_span_and_correlation_propagation() -> None:
    """Verify OpenTelemetry tracer initializes and injects correlation metadata.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If trace span execution fails.
    """
    configure_tracer("test-sentinel-service")
    set_correlation_id("trace-corr-777")

    with trace_span("security_scan", {"detector": "injection"}) as span:
        assert span is not None


def test_prometheus_metrics_recording() -> None:
    """Verify metrics incrementation and Prometheus text export generation.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If metric values do not appear in the exported payload.
    """
    record_detection("injection", "high", "direct_injection")
    record_block("policy_violation", "tenant_a")
    record_latency("pipeline", 0.085)
    record_risk_score("secrets", 0.95)

    payload = generate_metrics_payload()
    assert b"sentinel_detections_total" in payload
    assert b"sentinel_blocked_total" in payload
    assert b"sentinel_latency_seconds" in payload
    assert b"sentinel_risk_score" in payload


@pytest.mark.asyncio
async def test_alert_manager_rate_limiting() -> None:
    """Verify AlertManager suppresses duplicate alerts within cooldown window.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If rate limiting fails to suppress redundant alerts.
    """
    manager = AlertManager(rate_limit_seconds=15.0)
    key = "critical_attack_key"

    assert manager.should_suppress_alert(key) is False
    assert manager.should_suppress_alert(key) is True

    alert = AlertPayload(
        severity="critical",
        title="Jailbreak detected",
        alert_key=key,
    )
    result = await manager.send_alert(alert)
    assert result is False


def test_session_manager_lifecycle_and_profiling() -> None:
    """Verify SessionManager multi-turn tracking, rate calculation, and context export.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If session state tracking fails.
    """
    sm = SessionManager()
    session = sm.get_or_create("sess-101", tenant_id="tenant-acme")
    assert session.session_id == "sess-101"

    updated = sm.record_interaction(
        "sess-101", "user", "What is my balance?", risk_score=0.1
    )
    assert updated.total_requests == 1
    assert len(updated.turns) == 1

    sm.record_interaction(
        "sess-101", "assistant", "Your balance is 100 USD.", risk_score=0.0
    )
    assert updated.total_requests == 2

    context = sm.get_context_dict("sess-101")
    assert len(context["history"]) == 2
    assert context["total_requests"] == 2


@pytest.mark.asyncio
async def test_alert_manager_webhook_dispatch_success() -> None:
    """Verify AlertManager sends alert via webhook successfully.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If alert dispatch does not return True on success.
    """
    manager = AlertManager(webhook_url="https://alerts.example.com/webhook")
    alert = AlertPayload(
        severity="high",
        title="Prompt injection intercepted",
        alert_key="alert_key_unique_1",
    )

    mock_resp = AsyncMock()
    mock_resp.is_success = True

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        success = await manager.send_alert(alert)
        assert success is True


@pytest.mark.asyncio
async def test_alert_manager_webhook_timeout_raises_error() -> None:
    """Verify AlertManager raises NetworkTimeoutError when all retries time out.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If NetworkTimeoutError is not raised.
    """
    manager = AlertManager(
        webhook_url="https://alerts.example.com/webhook",
        timeout_seconds=0.01,
    )
    alert = AlertPayload(
        severity="critical",
        title="Repeated timeout trigger",
        alert_key="alert_key_unique_2",
    )

    with (
        patch(
            "httpx.AsyncClient.post",
            side_effect=httpx.TimeoutException("Connection timed out"),
        ),
        pytest.raises(NetworkTimeoutError),
    ):
        await manager.send_alert(alert)

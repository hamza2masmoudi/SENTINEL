import asyncio
import time
from typing import Any

import httpx
from pydantic import BaseModel, Field

from sentinel.exceptions import NetworkTimeoutError


class AlertPayload(BaseModel):
    """Structured notification payload dispatched to alert receivers.

    Attributes:
        severity: Criticality classification ('info', 'warning', 'critical').
        title: Short summary headline of the alert condition.
        details: Diagnostic dictionary containing matched attack vectors.
        timestamp: Unix timestamp when the alert occurred.
        alert_key: Unique key used for deduplication and rate limiting.
    """

    severity: str
    title: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)
    alert_key: str = Field(default="generic_alert")


class AlertManager:
    """Dispatches notifications with rate limiting and exponential retry.

    Attributes:
        webhook_url: Target URL for alert webhooks.
        rate_limit_seconds: Cooldown duration between identical alert keys.
        timeout_seconds: Timeout for outbound HTTP requests.
    """

    def __init__(
        self,
        webhook_url: str | None = None,
        rate_limit_seconds: float = 30.0,
        timeout_seconds: float = 5.0,
    ) -> None:
        """Initialize AlertManager.

        Args:
            webhook_url: Optional destination webhook URL.
            rate_limit_seconds: Cooldown duration for identical alert keys.
            timeout_seconds: Timeout threshold for webhook HTTP requests.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> manager = AlertManager()
            >>> manager.rate_limit_seconds
            30.0
        """
        self.webhook_url: str | None = webhook_url
        self.rate_limit_seconds: float = rate_limit_seconds
        self.timeout_seconds: float = timeout_seconds
        self._last_alert_times: dict[str, float] = {}

    def should_suppress_alert(self, alert_key: str) -> bool:
        """Check whether an alert key is currently within its rate limit cooldown.

        Args:
            alert_key: Identifier of the alert type or attack vector.

        Returns:
            bool: True if alert should be suppressed, False if allowed.

        Raises:
            None

        Examples:
            >>> manager = AlertManager(rate_limit_seconds=10.0)
            >>> manager.should_suppress_alert("k1")
            False
        """
        now = time.time()
        last_sent = self._last_alert_times.get(alert_key, 0.0)
        if (now - last_sent) < self.rate_limit_seconds:
            return True
        self._last_alert_times[alert_key] = now
        return False

    async def _post_with_retry(
        self, url: str, payload: dict[str, Any], max_retries: int = 3
    ) -> bool:
        """Send an HTTP POST notification with exponential backoff.

        Args:
            url: Destination endpoint URL.
            payload: JSON payload to transmit.
            max_retries: Maximum number of retry attempts.

        Returns:
            bool: True if delivery succeeded, False otherwise.

        Raises:
            NetworkTimeoutError: If all retry attempts exceed timeout.

        Examples:
            >>> pass
        """
        backoff = 0.5
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    resp = await client.post(url, json=payload)
                    if resp.is_success:
                        return True
            except httpx.TimeoutException as err:
                if attempt == max_retries - 1:
                    raise NetworkTimeoutError(
                        f"Alert webhook timed out: {url}",
                        service_name="alert_webhook",
                        timeout_seconds=self.timeout_seconds,
                    ) from err
            except Exception:
                pass
            await asyncio.sleep(backoff)
            backoff *= 2.0
        return False

    async def send_alert(self, alert: AlertPayload) -> bool:
        """Dispatch a security alert if webhook is configured and not rate-limited.

        Args:
            alert: Populated AlertPayload to dispatch.

        Returns:
            bool: True if dispatched successfully, False if suppressed or unset.

        Raises:
            NetworkTimeoutError: If webhook endpoint times out continuously.

        Examples:
            >>> import asyncio
            >>> manager = AlertManager()
            >>> alert = AlertPayload(severity="critical", title="Injection detected")
            >>> asyncio.run(manager.send_alert(alert))
            False
        """
        if self.webhook_url is None:
            return False

        if self.should_suppress_alert(alert.alert_key):
            return False

        payload_dict = alert.model_dump()
        return await self._post_with_retry(self.webhook_url, payload_dict)

import time
import uuid
from collections import defaultdict
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from sentinel.config import get_config
from sentinel.logging import clear_correlation_id, set_correlation_id


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Middleware injecting a correlation ID into each request lifecycle.

    Attributes:
        header_name: HTTP header name used to propagate correlation identifiers.
    """

    HEADER_NAME: str = "X-Correlation-ID"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Extract or generate a correlation ID and bind it to the request context.

        Args:
            request: Incoming HTTP request.
            call_next: Next middleware or route handler in the chain.

        Returns:
            Response: HTTP response with the correlation ID header attached.

        Raises:
            None

        Examples:
            >>> pass
        """
        correlation_id: str = request.headers.get(self.HEADER_NAME, str(uuid.uuid4()))
        set_correlation_id(correlation_id)
        request.state.correlation_id = correlation_id
        try:
            response: Response = await call_next(request)
            response.headers[self.HEADER_NAME] = correlation_id
            return response
        finally:
            clear_correlation_id()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing per-client request rate limiting.

    Attributes:
        requests_per_minute: Maximum allowed requests per minute per client.
        client_windows: Sliding window tracker per client IP.
    """

    def __init__(self, app: Any, requests_per_minute: int | None = None) -> None:
        """Initialize the rate limiter with configurable request ceiling.

        Args:
            app: ASGI application instance.
            requests_per_minute: Override for max requests per minute.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> pass
        """
        super().__init__(app)
        config = get_config()
        self.requests_per_minute: int = (
            requests_per_minute
            if requests_per_minute is not None
            else config.security.rate_limit_per_minute
        )
        self.client_windows: dict[str, list[float]] = defaultdict(list)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Check client request rate and reject if limit is exceeded.

        Args:
            request: Incoming HTTP request.
            call_next: Next middleware or route handler.

        Returns:
            Response: HTTP response or 429 rejection.

        Raises:
            None

        Examples:
            >>> pass
        """
        client_ip: str = request.client.host if request.client else "unknown"
        now: float = time.time()
        window_start: float = now - 60.0

        self.client_windows[client_ip] = [
            timestamp
            for timestamp in self.client_windows[client_ip]
            if timestamp > window_start
        ]

        if len(self.client_windows[client_ip]) >= self.requests_per_minute:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after_seconds": 60,
                },
            )

        self.client_windows[client_ip].append(now)
        return await call_next(request)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware validating API key authentication on protected routes.

    Attributes:
        api_key_header: HTTP header name carrying the API key.
        admin_api_key: Expected administrative API key value.
        public_paths: Set of URL paths exempt from authentication.
    """

    PUBLIC_PATHS: frozenset[str] = frozenset(
        {"/api/v1/health", "/docs", "/openapi.json"}
    )

    def __init__(self, app: Any, admin_api_key: str | None = None) -> None:
        """Initialize authentication middleware with API key configuration.

        Args:
            app: ASGI application instance.
            admin_api_key: Override for the admin API key.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> pass
        """
        super().__init__(app)
        config = get_config()
        self.api_key_header: str = config.security.api_key_header_name
        self.admin_api_key: str | None = (
            admin_api_key
            if admin_api_key is not None
            else config.security.admin_api_key
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Validate API key presence and correctness on protected endpoints.

        Args:
            request: Incoming HTTP request.
            call_next: Next middleware or route handler.

        Returns:
            Response: HTTP response or 401/403 rejection.

        Raises:
            None

        Examples:
            >>> pass
        """
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)

        if self.admin_api_key is None:
            return await call_next(request)

        provided_key: str | None = request.headers.get(self.api_key_header)

        if provided_key is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing API key"},
            )

        if provided_key != self.admin_api_key:
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid API key"},
            )

        return await call_next(request)

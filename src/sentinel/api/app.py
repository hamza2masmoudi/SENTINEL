from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from sentinel import __version__
from sentinel.api.middleware import (
    AuthenticationMiddleware,
    CorrelationIdMiddleware,
    RateLimitMiddleware,
)
from sentinel.api.routes import router
from sentinel.config import get_config
from sentinel.exceptions import (
    PolicyViolationError,
    SentinelError,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan manager for startup and shutdown events.

    Args:
        app: FastAPI application instance.

    Yields:
        None

    Raises:
        None

    Examples:
        >>> pass
    """
    yield


def create_app(
    admin_api_key: str | None = None,
    rate_limit_per_minute: int | None = None,
) -> FastAPI:
    """Factory function creating a fully configured FastAPI application.

    Args:
        admin_api_key: Optional override for the administrative API key.
        rate_limit_per_minute: Optional override for the rate limit ceiling.

    Returns:
        FastAPI: Configured application with middleware, routes, and handlers.

    Raises:
        None

    Examples:
        >>> app = create_app()
        >>> app.title
        'SENTINEL API'
    """
    config = get_config()

    app = FastAPI(
        title="SENTINEL API",
        description=(
            "Security Evaluation and Neural Tracing for Intelligent Language-models"
        ),
        version=__version__,
        lifespan=lifespan,
    )

    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=rate_limit_per_minute,
    )
    app.add_middleware(
        AuthenticationMiddleware,
        admin_api_key=(
            admin_api_key
            if admin_api_key is not None
            else config.security.admin_api_key
        ),
    )

    app.include_router(router)

    @app.exception_handler(PolicyViolationError)
    async def policy_violation_handler(
        request: Request, exc: PolicyViolationError
    ) -> JSONResponse:
        """Handle PolicyViolationError by returning a structured 403 response.

        Args:
            request: Incoming HTTP request.
            exc: Raised PolicyViolationError exception.

        Returns:
            JSONResponse: Error detail response.

        Raises:
            None

        Examples:
            >>> pass
        """
        return JSONResponse(
            status_code=403,
            content={
                "detail": exc.message,
                "policy_name": exc.policy_name,
                "action_taken": exc.action_taken,
            },
        )

    @app.exception_handler(SentinelError)
    async def sentinel_error_handler(
        request: Request, exc: SentinelError
    ) -> JSONResponse:
        """Handle generic SentinelError by returning a structured 500 response.

        Args:
            request: Incoming HTTP request.
            exc: Raised SentinelError exception.

        Returns:
            JSONResponse: Error detail response.

        Raises:
            None

        Examples:
            >>> pass
        """
        return JSONResponse(
            status_code=500,
            content={
                "detail": exc.message,
                "error_type": type(exc).__name__,
            },
        )

    return app

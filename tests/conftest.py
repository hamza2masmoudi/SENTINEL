import os
from collections.abc import Generator

import pytest

from sentinel.config import SentinelConfig, reset_config
from sentinel.logging import clear_correlation_id, clear_tenant_id


@pytest.fixture(autouse=True)
def clean_environment() -> Generator[None, None, None]:
    """Provide an isolated environment for each test execution.

    Args:
        None

    Returns:
        Generator[None, None, None]: Fixture context generator.

    Raises:
        None

    Examples:
        >>> pass
    """
    initial_env = dict(os.environ)
    reset_config()
    clear_correlation_id()
    clear_tenant_id()

    yield

    os.environ.clear()
    os.environ.update(initial_env)
    reset_config()
    clear_correlation_id()
    clear_tenant_id()


@pytest.fixture
def sample_config() -> SentinelConfig:
    """Return a standard test configuration instance.

    Args:
        None

    Returns:
        SentinelConfig: Test configuration object.

    Raises:
        None

    Examples:
        >>> pass
    """
    return SentinelConfig(environment="staging")

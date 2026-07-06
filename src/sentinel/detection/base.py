import asyncio
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class DetectionResult(BaseModel):
    """Result payload produced by a security detector.

    Attributes:
        detector_name: Unique identifier of the executing detector.
        detected: Boolean flag indicating if a threat was found.
        score: Threat confidence score normalized between 0.0 and 1.0.
        category: Classified threat category.
        details: Diagnostic dictionary containing matched indicators.
        latency_ms: Execution duration in milliseconds.
    """

    detector_name: str
    detected: bool
    score: float = Field(ge=0.0, le=1.0)
    category: str = Field(default="general")
    details: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = Field(default=0.0, ge=0.0)


class BaseDetector(ABC):
    """Abstract base class for all security threat detectors.

    Attributes:
        name: Detector identifier string.
        threshold: Score cutoff above which threat is considered detected.
    """

    def __init__(self, name: str, threshold: float = 0.70) -> None:
        """Initialize the base detector.

        Args:
            name: Identifier for the detector.
            threshold: Confidence threshold for threat detection.

        Returns:
            None

        Raises:
            ValueError: If threshold is not between 0.0 and 1.0.

        Examples:
            >>> class DummyDetector(BaseDetector):
            ...     async def detect(self, text, context=None):
            ...         return DetectionResult(
            ...             detector_name=self.name, detected=False, score=0.0
            ...         )
            >>> d = DummyDetector("test")
            >>> d.name
            'test'
        """
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Threshold must be between 0.0 and 1.0")
        self._name: str = name
        self._threshold: float = threshold

    @property
    def name(self) -> str:
        """Return the detector name.

        Args:
            None

        Returns:
            str: Identifier of the detector.

        Raises:
            None

        Examples:
            >>> pass
        """
        return self._name

    @property
    def threshold(self) -> float:
        """Return the detection threshold.

        Args:
            None

        Returns:
            float: Confidence cutoff threshold.

        Raises:
            None

        Examples:
            >>> pass
        """
        return self._threshold

    @abstractmethod
    async def detect(
        self, text: str, context: dict[str, Any] | None = None
    ) -> DetectionResult:
        """Analyze the input text asynchronously and produce a DetectionResult.

        Args:
            text: Raw input text string to evaluate.
            context: Optional contextual parameters such as history or metadata.

        Returns:
            DetectionResult: Comprehensive threat evaluation payload.

        Raises:
            DetectionError: If detection execution encounters an unrecoverable failure.
        """

    def detect_sync(
        self, text: str, context: dict[str, Any] | None = None
    ) -> DetectionResult:
        """Synchronous wrapper for running detection in blocking contexts.

        Args:
            text: Raw input text string to evaluate.
            context: Optional contextual parameters.

        Returns:
            DetectionResult: Detection result produced by async execution.

        Raises:
            DetectionError: If detection encounters an unrecoverable failure.

        Examples:
            >>> pass
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(self.detect(text, context), loop)
            return future.result()
        return asyncio.run(self.detect(text, context))

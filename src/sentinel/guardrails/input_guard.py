import asyncio
from typing import Any

from pydantic import BaseModel, Field

from sentinel.detection.ensemble import DetectionEnsemble, EnsembleResult
from sentinel.detection.pii import PIIDetector
from sentinel.exceptions import PolicyViolationError


class InputGuardResult(BaseModel):
    """Evaluation outcome produced by the pre-LLM input guardrail.

    Attributes:
        allowed: True if prompt may be forwarded to LLM provider.
        processed_text: Sanitized or anonymized prompt text.
        blocked: True if prompt was halted due to threat detection.
        threat_score: Evaluated ensemble threat risk score.
        anonymization_mapping: Reversible token map if PII was redacted.
        reason: Explanatory justification for blocking or warning.
    """

    allowed: bool
    processed_text: str
    blocked: bool
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0)
    anonymization_mapping: dict[str, str] = Field(default_factory=dict)
    reason: str | None = Field(default=None)


class InputGuard:
    """Pre-LLM guardrail enforcing threat detection and PII anonymization.

    Attributes:
        ensemble: Multi-detector evaluation engine.
        pii_detector: Entity extractor and anonymizer.
        anonymize_pii: Whether to substitute PII with tokens.
        bypass_tokens: List of authorized bypass authorization tokens.
    """

    def __init__(
        self,
        ensemble: DetectionEnsemble | None = None,
        pii_detector: PIIDetector | None = None,
        anonymize_pii: bool = True,
        bypass_tokens: list[str] | None = None,
    ) -> None:
        """Initialize the InputGuard.

        Args:
            ensemble: Custom or default DetectionEnsemble instance.
            pii_detector: Custom or default PIIDetector instance.
            anonymize_pii: Flag enabling reversible tokenization.
            bypass_tokens: Optional list of emergency bypass tokens.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> guard = InputGuard()
            >>> guard.anonymize_pii
            True
        """
        self.ensemble: DetectionEnsemble = (
            ensemble if ensemble is not None else DetectionEnsemble()
        )
        self.pii_detector: PIIDetector = (
            pii_detector if pii_detector is not None else PIIDetector()
        )
        self.anonymize_pii: bool = anonymize_pii
        self.bypass_tokens: list[str] = (
            bypass_tokens if bypass_tokens is not None else []
        )

    def _check_bypass(self, text: str) -> bool:
        """Verify whether the text contains an authorized bypass token.

        Args:
            text: Raw input string.

        Returns:
            bool: True if bypass is granted, False otherwise.

        Raises:
            None

        Examples:
            >>> pass
        """
        if not self.bypass_tokens:
            return False
        return any(token in text for token in self.bypass_tokens)

    async def guard(
        self,
        text: str,
        context: dict[str, Any] | None = None,
        raise_on_block: bool = False,
    ) -> InputGuardResult:
        """Filter, sanitize, and validate user input prior to LLM forwarding.

        Args:
            text: Raw user prompt string.
            context: Contextual parameters such as history or profiling.
            raise_on_block: Whether to raise PolicyViolationError if blocked.

        Returns:
            InputGuardResult: Validation status and sanitized text.

        Raises:
            PolicyViolationError: If blocked and raise_on_block is True.

        Examples:
            >>> import asyncio
            >>> ig = InputGuard()
            >>> res = asyncio.run(ig.guard("Hello"))
            >>> res.allowed
            True
        """
        if self._check_bypass(text):
            return InputGuardResult(
                allowed=True,
                processed_text=text,
                blocked=False,
                threat_score=0.0,
                reason="Bypass token verified",
            )

        ensemble_res: EnsembleResult = await self.ensemble.analyze(text, context)
        if ensemble_res.blocked:
            if raise_on_block:
                raise PolicyViolationError(
                    message=ensemble_res.explanation,
                    policy_name="input_guard_enforcement",
                    action_taken="block",
                )
            return InputGuardResult(
                allowed=False,
                processed_text="",
                blocked=True,
                threat_score=ensemble_res.composite_score,
                reason=ensemble_res.explanation,
            )

        processed_text = text
        mapping: dict[str, str] = {}
        if self.anonymize_pii:
            processed_text, mapping = self.pii_detector.anonymize(text)

        return InputGuardResult(
            allowed=True,
            processed_text=processed_text,
            blocked=False,
            threat_score=ensemble_res.composite_score,
            anonymization_mapping=mapping,
            reason=ensemble_res.explanation,
        )

    def guard_sync(
        self,
        text: str,
        context: dict[str, Any] | None = None,
        raise_on_block: bool = False,
    ) -> InputGuardResult:
        """Synchronous wrapper for running input guardrail evaluation.

        Args:
            text: Input string.
            context: Contextual parameters.
            raise_on_block: Raise PolicyViolationError if blocked.

        Returns:
            InputGuardResult: Guard evaluation outcome.

        Raises:
            PolicyViolationError: If blocked and raise_on_block is True.

        Examples:
            >>> ig = InputGuard()
            >>> res = ig.guard_sync("Safe question")
            >>> res.allowed
            True
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(
                self.guard(text, context, raise_on_block), loop
            )
            return future.result()
        return asyncio.run(self.guard(text, context, raise_on_block))

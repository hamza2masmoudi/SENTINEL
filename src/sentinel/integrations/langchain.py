from typing import Any

from sentinel.guardrails.input_guard import InputGuard
from sentinel.guardrails.output_guard import OutputGuard


class SentinelLangChainCallback:
    """LangChain callback handler inspecting prompts and responses for security threats.

    Attributes:
        input_guard: Active InputGuard instance.
        output_guard: Active OutputGuard instance.
        raise_on_violation: Whether to raise PolicyViolationError on threat detection.
    """

    def __init__(
        self,
        input_guard: InputGuard | None = None,
        output_guard: OutputGuard | None = None,
        raise_on_violation: bool = True,
    ) -> None:
        """Initialize SentinelLangChainCallback.

        Args:
            input_guard: Optional custom InputGuard instance.
            output_guard: Optional custom OutputGuard instance.
            raise_on_violation: Flag raising exceptions when threat is detected.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> handler = SentinelLangChainCallback()
            >>> handler.raise_on_violation
            True
        """
        self.input_guard: InputGuard = (
            input_guard if input_guard is not None else InputGuard()
        )
        self.output_guard: OutputGuard = (
            output_guard if output_guard is not None else OutputGuard()
        )
        self.raise_on_violation: bool = raise_on_violation
        self._last_mapping: dict[str, str] = {}

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Inspect and validate input prompts prior to LLM execution.

        Args:
            serialized: Serialization mapping of the model.
            prompts: List of prompt strings dispatched to model.
            **kwargs: Additional contextual arguments.

        Returns:
            None

        Raises:
            PolicyViolationError: If a prompt is flagged and raise_on_violation is True.

        Examples:
            >>> handler = SentinelLangChainCallback()
            >>> handler.on_llm_start({}, ["Hello"])
        """
        for prompt in prompts:
            res = self.input_guard.guard_sync(
                prompt, raise_on_block=self.raise_on_violation
            )
            self._last_mapping.update(res.anonymization_mapping)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Inspect generated responses for data leakage or prohibited content.

        Args:
            response: Response object containing generation generations.
            **kwargs: Additional contextual arguments.

        Returns:
            None

        Raises:
            PolicyViolationError: If generated content is blocked.

        Examples:
            >>> handler = SentinelLangChainCallback()
            >>> handler.on_llm_end(None)
        """
        if response is None:
            return

        generations = getattr(response, "generations", [])
        for gen_list in generations:
            for gen in gen_list:
                text = getattr(gen, "text", "")
                if text:
                    self.output_guard.guard_sync(
                        text,
                        anonymization_mapping=self._last_mapping,
                        raise_on_block=self.raise_on_violation,
                    )

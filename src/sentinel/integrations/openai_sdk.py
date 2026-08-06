from typing import Any

from sentinel.guardrails.input_guard import InputGuard
from sentinel.guardrails.output_guard import OutputGuard


class _CompletionsWrapper:
    """Interceptor for OpenAI chat completions API calls.

    Attributes:
        client: Underlying client instance.
        input_guard: Active InputGuard instance.
        output_guard: Active OutputGuard instance.
    """

    def __init__(
        self,
        client: Any,
        input_guard: InputGuard,
        output_guard: OutputGuard,
    ) -> None:
        """Initialize _CompletionsWrapper.

        Args:
            client: Underlying OpenAI client instance.
            input_guard: Pre-LLM input guardrail.
            output_guard: Post-LLM output guardrail.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> wrapper = _CompletionsWrapper(None, InputGuard(), OutputGuard())
            >>> wrapper is not None
            True
        """
        self.client: Any = client
        self.input_guard: InputGuard = input_guard
        self.output_guard: OutputGuard = output_guard

    def _extract_user_prompt(self, messages: list[dict[str, str]]) -> str:
        """Extract the most recent user prompt message from message history.

        Args:
            messages: List of message dictionaries containing role and content.

        Returns:
            str: Latest user text or empty string.

        Raises:
            None

        Examples:
            >>> pass
        """
        for msg in reversed(messages):
            if msg.get("role") == "user":
                return msg.get("content", "")
        return ""

    def create(self, messages: list[dict[str, str]], **kwargs: Any) -> Any:
        """Execute chat completion with transparent security guardrails.

        Args:
            messages: List of chat messages.
            **kwargs: Additional parameters for completion API.

        Returns:
            Any: LLM completion response.

        Raises:
            PolicyViolationError: If input prompt or generated response is blocked.

        Examples:
            >>> pass
        """
        prompt = self._extract_user_prompt(messages)
        if prompt:
            in_res = self.input_guard.guard_sync(prompt, raise_on_block=True)
            if in_res.anonymization_mapping:
                for msg in messages:
                    if msg.get("role") == "user" and msg.get("content") == prompt:
                        msg["content"] = in_res.processed_text

        if self.client is not None and hasattr(self.client, "chat"):
            response = self.client.chat.completions.create(messages=messages, **kwargs)
        else:
            response = {
                "choices": [{"message": {"content": "Processed successfully."}}]
            }

        out_text = ""
        if isinstance(response, dict):
            choices = response.get("choices", [])
            if choices and isinstance(choices[0], dict):
                out_text = choices[0].get("message", {}).get("content", "")
        elif hasattr(response, "choices"):
            choices = getattr(response, "choices", [])
            if choices:
                choice_msg = getattr(choices[0], "message", None)
                out_text = getattr(choice_msg, "content", "")

        if out_text:
            self.output_guard.guard_sync(out_text, raise_on_block=True)

        return response


class _ChatWrapper:
    """Wrapper exposing completions namespace matching OpenAI SDK structure.

    Attributes:
        completions: Completions wrapper instance.
    """

    def __init__(
        self,
        client: Any,
        input_guard: InputGuard,
        output_guard: OutputGuard,
    ) -> None:
        """Initialize _ChatWrapper.

        Args:
            client: Underlying client.
            input_guard: Input guardrail.
            output_guard: Output guardrail.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> chat = _ChatWrapper(None, InputGuard(), OutputGuard())
            >>> chat.completions is not None
            True
        """
        self.completions: _CompletionsWrapper = _CompletionsWrapper(
            client, input_guard, output_guard
        )


class SentinelOpenAI:
    """Security proxy wrapping OpenAI Python client to enforce SENTINEL guardrails.

    Attributes:
        chat: Chat completions endpoint namespace.
    """

    def __init__(
        self,
        client: Any = None,
        input_guard: InputGuard | None = None,
        output_guard: OutputGuard | None = None,
    ) -> None:
        """Initialize SentinelOpenAI wrapper.

        Args:
            client: Optional underlying OpenAI client.
            input_guard: Custom InputGuard instance.
            output_guard: Custom OutputGuard instance.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> s_client = SentinelOpenAI()
            >>> s_client.chat is not None
            True
        """
        in_guard = input_guard if input_guard is not None else InputGuard()
        out_guard = output_guard if output_guard is not None else OutputGuard()
        self.chat: _ChatWrapper = _ChatWrapper(client, in_guard, out_guard)

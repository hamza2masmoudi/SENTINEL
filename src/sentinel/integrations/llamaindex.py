from typing import Any

from sentinel.detection.injection import PromptInjectionDetector
from sentinel.detection.secrets import SecretsDetector
from sentinel.guardrails.input_guard import InputGuard
from sentinel.guardrails.output_guard import OutputGuard


class SentinelNodePostprocessor:
    """LlamaIndex node postprocessor filtering dangerous retrieved context nodes.

    Attributes:
        injection_detector: Detector identifying indirect prompt injections.
        secrets_detector: Detector identifying leaked credentials.
    """

    def __init__(
        self,
        injection_detector: PromptInjectionDetector | None = None,
        secrets_detector: SecretsDetector | None = None,
    ) -> None:
        """Initialize SentinelNodePostprocessor.

        Args:
            injection_detector: Optional custom PromptInjectionDetector.
            secrets_detector: Optional custom SecretsDetector.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> pp = SentinelNodePostprocessor()
            >>> pp is not None
            True
        """
        self.injection_detector: PromptInjectionDetector = (
            injection_detector
            if injection_detector is not None
            else PromptInjectionDetector()
        )
        self.secrets_detector: SecretsDetector = (
            secrets_detector if secrets_detector is not None else SecretsDetector()
        )

    def postprocess_nodes(
        self, nodes: list[Any], query_bundle: Any | None = None
    ) -> list[Any]:
        """Filter out retrieved context nodes containing prompt injection or secrets.

        Args:
            nodes: List of NodeWithScore objects or document nodes.
            query_bundle: Optional query object associated with retrieval.

        Returns:
            list[Any]: Filtered list of safe nodes.

        Raises:
            None

        Examples:
            >>> pp = SentinelNodePostprocessor()
            >>> pp.postprocess_nodes([])
            []
        """
        safe_nodes: list[Any] = []
        for node_item in nodes:
            node = getattr(node_item, "node", node_item)
            text = getattr(node, "text", "")
            if not text and hasattr(node, "get_content"):
                text = node.get_content()

            if isinstance(text, str) and text:
                inj_res = self.injection_detector.detect_sync(text)
                sec_res = self.secrets_detector.detect_sync(text)
                if not inj_res.detected and not sec_res.detected:
                    safe_nodes.append(node_item)
            else:
                safe_nodes.append(node_item)

        return safe_nodes


class SentinelLlamaIndexHandler:
    """LlamaIndex callback handler securing query inputs and synthesizer outputs.

    Attributes:
        input_guard: Active InputGuard instance.
        output_guard: Active OutputGuard instance.
    """

    def __init__(
        self,
        input_guard: InputGuard | None = None,
        output_guard: OutputGuard | None = None,
    ) -> None:
        """Initialize SentinelLlamaIndexHandler.

        Args:
            input_guard: Custom InputGuard instance.
            output_guard: Custom OutputGuard instance.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> handler = SentinelLlamaIndexHandler()
            >>> handler is not None
            True
        """
        self.input_guard: InputGuard = (
            input_guard if input_guard is not None else InputGuard()
        )
        self.output_guard: OutputGuard = (
            output_guard if output_guard is not None else OutputGuard()
        )

    def on_event_start(
        self, event_type: str, payload: dict[str, Any] | None = None, **kwargs: Any
    ) -> None:
        """Inspect inputs at event initiation.

        Args:
            event_type: LlamaIndex event label (such as 'query' or 'llm').
            payload: Event data dictionary.
            **kwargs: Extra parameters.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> handler = SentinelLlamaIndexHandler()
            >>> handler.on_event_start("query", {"query_str": "Hello"})
        """
        if payload and "query_str" in payload:
            self.input_guard.guard_sync(str(payload["query_str"]))

    def on_event_end(
        self, event_type: str, payload: dict[str, Any] | None = None, **kwargs: Any
    ) -> None:
        """Inspect outputs at event completion.

        Args:
            event_type: LlamaIndex event label.
            payload: Event data dictionary.
            **kwargs: Extra parameters.

        Returns:
            None

        Raises:
            None

        Examples:
            >>> handler = SentinelLlamaIndexHandler()
            >>> handler.on_event_end("llm", {"response": "Clean text"})
        """
        if payload and "response" in payload:
            self.output_guard.guard_sync(str(payload["response"]))

import base64
import codecs
import re
import time
import unicodedata
from typing import Any

from sentinel.detection.base import BaseDetector, DetectionResult
from sentinel.exceptions import DetectionError

_ZERO_WIDTH_PATTERN = re.compile(r"[\u200B-\u200D\uFEFF\u2060\u00AD]")
_HTML_COMMENT_PATTERN = re.compile(r"<!--[\s\S]*?-->")
_HEX_SEQUENCE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_BASE64_CANDIDATE_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:={0,2})")

_DIRECT_PATTERNS = [
    re.compile(
        r"\bignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?|commands?|prompts?)\b",
        re.I,
    ),
    re.compile(
        r"\bdisregard\s+(?:all\s+)?(?:previous|prior)\s+(?:rules?|commands?|instructions?)\b",
        re.I,
    ),
    re.compile(
        r"\bforget\s+(?:everything|all\s+(?:prior|safety)\s+(?:prompts?|constraints?|rules?))\b",
        re.I,
    ),
    re.compile(
        r"\byou\s+(?:are|'re)\s+now\s+(?:a|an|the|acting\s+as|unrestricted)\b",
        re.I,
    ),
    re.compile(r"\bsystem\s*(?::|\s)\s*(?:override|reset|new\s+rule)\b", re.I),
    re.compile(r"\bnew\s+system\s+prompt\b", re.I),
    re.compile(r"\bbypass\s+(?:all\s+)?(?:safety|guardrails?|filters?)\b", re.I),
    re.compile(
        r"\boverride\s+(?:all\s+)?(?:security|system)\s+(?:protocols?|prompt)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:reveal|output|dump|print|exfiltrate)\s+(?:the\s+)?(?:confidential\s+)?(?:system\s+prompt|passwords?|credentials?|tokens?|database)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:administrative\s+prompt\s+injection|developer\s+command\s+executed|root\s+level\s+access)\b",
        re.I,
    ),
]


def _is_sensitive_instruction(message: object) -> bool:
    """Check if a message references system instructions or rules.

    Args:
        message: Object from conversation history.

    Returns:
        bool: True if message contains instruction indicators.

    Raises:
        None

    Examples:
        >>> _is_sensitive_instruction("New rule")
        True
    """
    if not isinstance(message, str):
        return False
    lowered = message.lower()
    return "rule" in lowered or "instruct" in lowered


class PromptInjectionDetector(BaseDetector):
    """Detector for direct, indirect, encoded, and multi-turn prompt injections.

    Attributes:
        name: Detector identifier ('prompt_injection').
        threshold: Score cutoff threshold for declaring an injection.
    """

    def __init__(self, threshold: float = 0.70) -> None:
        """Initialize the PromptInjectionDetector.

        Args:
            threshold: Confidence cutoff threshold between 0.0 and 1.0.

        Returns:
            None

        Raises:
            ValueError: If threshold is out of range.

        Examples:
            >>> detector = PromptInjectionDetector()
            >>> detector.name
            'prompt_injection'
        """
        super().__init__(name="prompt_injection", threshold=threshold)

    def _normalize_homoglyphs(self, text: str) -> str:
        """Normalize Unicode homoglyphs and compatibility characters.

        Args:
            text: Input string with potential homoglyph disguises.

        Returns:
            str: Normalized plain-text string.

        Raises:
            None

        Examples:
            >>> pass
        """
        normalized = unicodedata.normalize("NFKD", text)
        return "".join(c for c in normalized if not unicodedata.combining(c))

    def _check_direct_patterns(self, text: str) -> list[str]:
        """Scan input text against direct injection regular expressions.

        Args:
            text: Cleaned text string.

        Returns:
            list[str]: Matches found in text.

        Raises:
            None

        Examples:
            >>> pass
        """
        matches: list[str] = []
        for pattern in _DIRECT_PATTERNS:
            found = pattern.findall(text)
            if found:
                matches.append(pattern.pattern)
        return matches

    def _check_indirect_vectors(self, raw_text: str) -> list[str]:
        """Identify invisible characters and hidden markup injection attempts.

        Args:
            raw_text: Original raw input string.

        Returns:
            list[str]: Descriptions of matched indirect vectors.

        Raises:
            None

        Examples:
            >>> pass
        """
        findings: list[str] = []
        if _ZERO_WIDTH_PATTERN.search(raw_text):
            findings.append("invisible_unicode_zero_width")
        if _HTML_COMMENT_PATTERN.search(raw_text):
            findings.append("hidden_html_comments")
        return findings

    def _decode_and_inspect_payloads(self, text: str) -> list[str]:
        """Detect and recursively inspect encoded injection payloads.

        Args:
            text: Input string with possible encoded segments.

        Returns:
            list[str]: Injections detected inside decoded payloads.

        Raises:
            None

        Examples:
            >>> pass
        """
        detected: list[str] = []
        for candidate in _BASE64_CANDIDATE_PATTERN.findall(text):
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_str) > 6 and self._check_direct_patterns(decoded_str):
                    detected.append(f"base64_encoded_injection:{candidate[:10]}")
            except Exception:
                continue

        if _HEX_SEQUENCE_PATTERN.search(text):
            detected.append("hex_encoded_sequence")

        try:
            rot13_str = codecs.decode(text, "rot_13")
            if self._check_direct_patterns(rot13_str):
                detected.append("rot13_obfuscation")
        except Exception:
            pass

        return detected

    def _evaluate_multi_turn(self, text: str, context: dict[str, Any] | None) -> float:
        """Calculate threat escalation score across conversation history.

        Args:
            text: Current turn input text.
            context: Context containing optional conversation turn list.

        Returns:
            float: Cumulative multi-turn escalation modifier between 0.0 and 0.4.

        Raises:
            None

        Examples:
            >>> pass
        """
        if not context or "history" not in context:
            return 0.0
        history: list[str] = context.get("history", [])
        if not history:
            return 0.0

        hits = sum(1 for m in history[-5:] if _is_sensitive_instruction(m))
        escalating = any(k in text.lower() for k in ["now", "do", "must"])
        if hits >= 2 and escalating:
            return min(0.35, hits * 0.12)
        return 0.0

    @property
    def threshold(self) -> float:
        """Return the active detection threshold."""
        return self._threshold

    async def detect(
        self, text: str, context: dict[str, Any] | None = None
    ) -> DetectionResult:
        """Perform comprehensive prompt injection analysis on target text.

        Args:
            text: Text to evaluate.
            context: Optional execution context including multi-turn history.

        Returns:
            DetectionResult: Structured evaluation with score and detected vectors.

        Raises:
            DetectionError: If text analysis fails unexpectedly.

        Examples:
            >>> import asyncio
            >>> detector = PromptInjectionDetector()
            >>> res = asyncio.run(detector.detect("Normal user question"))
            >>> res.detected
            False
        """
        start_time = time.perf_counter()
        try:
            normalized_text = self._normalize_homoglyphs(text)
            direct_matches = self._check_direct_patterns(normalized_text)
            indirect_vectors = self._check_indirect_vectors(text)
            encoded_matches = self._decode_and_inspect_payloads(text)
            multi_turn_boost = self._evaluate_multi_turn(text, context)

            score = 0.0
            categories: list[str] = []

            if direct_matches:
                score += 0.75 + min(0.20, len(direct_matches) * 0.05)
                categories.append("direct_injection")
            if indirect_vectors:
                score += 0.45
                categories.append("indirect_injection")
            if encoded_matches:
                score += 0.55
                categories.append("encoded_payload")
            if multi_turn_boost > 0.0:
                score += multi_turn_boost
                categories.append("multi_turn_escalation")

            final_score = min(1.0, score)
            is_detected = final_score >= self._threshold

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            primary_cat = categories[0] if categories else "clean"

            details: dict[str, Any] = {
                "direct_matches": direct_matches,
                "indirect_vectors": indirect_vectors,
                "encoded_matches": encoded_matches,
                "multi_turn_modifier": multi_turn_boost,
                "categories": categories,
            }

            return DetectionResult(
                detector_name=self._name,
                detected=is_detected,
                score=round(final_score, 4),
                category=primary_cat,
                details=details,
                latency_ms=round(duration_ms, 2),
            )
        except Exception as err:
            raise DetectionError(
                f"Prompt injection detection failed: {err}",
                detector_name=self._name,
            ) from err

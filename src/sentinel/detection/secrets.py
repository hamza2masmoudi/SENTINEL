import math
import re
import time
from typing import Any

from sentinel.detection.base import BaseDetector, DetectionResult
from sentinel.exceptions import DetectionError

_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "openai_api_key": re.compile(
        r"\b(?:sk-[a-zA-Z0-9]{32,}|sk-proj-[a-zA-Z0-9_-]{48,})\b"
    ),
    "anthropic_api_key": re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{32,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "gcp_api_key": re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"),
    "stripe_api_key": re.compile(r"\b(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}\b"),
    "jwt_token": re.compile(
        r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
    ),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
    ),
    "db_connection_string": re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:]+:[^\s@]+@[^\s]+\b",
        re.I,
    ),
    "code_credentials": re.compile(
        r"(?:password|secret_key|api_secret|access_token)\s*=\s*['\"][^\s'\"]{6,}['\"]",
        re.I,
    ),
}

_CRITICALITY_SCORES: dict[str, float] = {
    "private_key": 1.0,
    "aws_access_key": 0.95,
    "openai_api_key": 0.95,
    "anthropic_api_key": 0.95,
    "gcp_api_key": 0.95,
    "stripe_api_key": 0.95,
    "db_connection_string": 0.90,
    "jwt_token": 0.85,
    "code_credentials": 0.85,
    "high_entropy_secret": 0.75,
}


def _calculate_shannon_entropy(candidate: str) -> float:
    """Compute the Shannon entropy of a string token.

    Args:
        candidate: String to analyze.

    Returns:
        float: Entropy value in bits.

    Raises:
        None

    Examples:
        >>> _calculate_shannon_entropy("aaaaaa")
        0.0
    """
    if not candidate:
        return 0.0
    frequency: dict[str, int] = {}
    for char in candidate:
        frequency[char] = frequency.get(char, 0) + 1
    length = float(len(candidate))
    return -sum(
        (count / length) * math.log2(count / length) for count in frequency.values()
    )


class SecretsDetector(BaseDetector):
    """Detector for API keys, private keys, and high-entropy secrets.

    Attributes:
        name: Detector identifier ('secrets').
        threshold: Score cutoff for declaring a credential leak.
    """

    def __init__(self, threshold: float = 0.70) -> None:
        """Initialize the SecretsDetector.

        Args:
            threshold: Confidence cutoff threshold between 0.0 and 1.0.

        Returns:
            None

        Raises:
            ValueError: If threshold is outside [0.0, 1.0].

        Examples:
            >>> detector = SecretsDetector()
            >>> detector.name
            'secrets'
        """
        super().__init__(name="secrets", threshold=threshold)

    def _scan_known_signatures(self, text: str) -> dict[str, list[str]]:
        """Scan input for established secret and API key regex patterns.

        Args:
            text: Text to evaluate.

        Returns:
            dict[str, list[str]]: Dictionary mapping secret types to match samples.

        Raises:
            None

        Examples:
            >>> pass
        """
        matches: dict[str, list[str]] = {}
        for key_type, pattern in _SECRET_PATTERNS.items():
            found = pattern.findall(text)
            if found:
                matches[key_type] = [item[:6] + "..." for item in found]
        return matches

    def _scan_high_entropy_tokens(self, text: str) -> list[str]:
        """Identify unclassified strings exhibiting high Shannon entropy.

        Args:
            text: Text to scan.

        Returns:
            list[str]: High-entropy candidate tokens.

        Raises:
            None

        Examples:
            >>> pass
        """
        candidates = re.findall(r"\b[A-Za-z0-9+/_-]{20,}\b", text)
        high_entropy_tokens: list[str] = []
        for token in candidates:
            if _calculate_shannon_entropy(token) > 4.5:
                high_entropy_tokens.append(token[:6] + "...")
        return high_entropy_tokens

    async def detect(
        self, text: str, context: dict[str, Any] | None = None
    ) -> DetectionResult:
        """Analyze text for leaked credentials, private keys, and API tokens.

        Args:
            text: Input string to inspect.
            context: Optional contextual dictionary.

        Returns:
            DetectionResult: Structured evaluation with detected secret types.

        Raises:
            DetectionError: If secret scanning crashes unexpectedly.

        Examples:
            >>> import asyncio
            >>> detector = SecretsDetector()
            >>> res = asyncio.run(detector.detect("System safe"))
            >>> res.detected
            False
        """
        start_time = time.perf_counter()
        try:
            matched_signatures = self._scan_known_signatures(text)
            high_entropy_hits = self._scan_high_entropy_tokens(text)

            highest_score = 0.0
            found_types: list[str] = list(matched_signatures.keys())

            for stype in matched_signatures:
                score = _CRITICALITY_SCORES.get(stype, 0.80)
                if score > highest_score:
                    highest_score = score

            if high_entropy_hits and not matched_signatures:
                found_types.append("high_entropy_secret")
                highest_score = max(highest_score, 0.75)

            is_detected = highest_score >= self._threshold
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            details: dict[str, Any] = {
                "matched_signatures": matched_signatures,
                "high_entropy_hits": high_entropy_hits,
                "found_types": found_types,
            }

            primary_cat = found_types[0] if found_types else "clean"

            return DetectionResult(
                detector_name=self._name,
                detected=is_detected,
                score=round(highest_score, 4),
                category=primary_cat,
                details=details,
                latency_ms=round(duration_ms, 2),
            )
        except Exception as err:
            raise DetectionError(
                f"Secrets detection failed: {err}",
                detector_name=self._name,
            ) from err

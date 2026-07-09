import re
import time
from typing import Any

from sentinel.detection.base import BaseDetector, DetectionResult
from sentinel.exceptions import DetectionError

_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_OBFUSCATED_EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+\s*(?:\[at\]|@)\s*[A-Za-z0-9.-]+\s*(?:\[dot\]|\.)\s*[A-Za-z]{2,}\b",
    re.I,
)
_PHONE_REGEX = re.compile(
    r"(?:\+33\s?[1-9](?:[\s.-]?\d{2}){4}|0[1-9](?:[\s.-]?\d{2}){4}|\b\+?[1-9]\d{1,2}[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b)"
)
_CREDIT_CARD_REGEX = re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b")
_IBAN_REGEX = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b")
_FRENCH_NIR_REGEX = re.compile(
    r"\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2]|2[0-9])\s?\d{2}\s?\d{3}\s?\d{3}(?:\s?\d{2})?\b"
)
_SIRET_REGEX = re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\s?\d{5}\b")
_INTERNAL_URL_REGEX = re.compile(
    r"https?://(?:localhost|internal|corp|intranet|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^\s]*)?",
    re.I,
)

_SENSITIVITY_WEIGHTS: dict[str, float] = {
    "credit_card": 0.95,
    "ssn_nir": 0.95,
    "iban": 0.90,
    "siret": 0.75,
    "internal_url": 0.75,
    "phone": 0.55,
    "email": 0.40,
    "obfuscated_email": 0.50,
}


def _verify_luhn(card_number_str: str) -> bool:
    """Validate numeric string using the standard Luhn checksum algorithm.

    Args:
        card_number_str: String containing digits and optional delimiters.

    Returns:
        bool: True if checksum is valid, False otherwise.

    Raises:
        None

    Examples:
        >>> _verify_luhn("49927398716")
        True
    """
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class PIIDetector(BaseDetector):
    """Detector and anonymizer for personally identifiable information (PII).

    Attributes:
        name: Detector identifier ('pii').
        threshold: Score cutoff threshold for flagging PII leaks.
    """

    def __init__(self, threshold: float = 0.50) -> None:
        """Initialize the PIIDetector.

        Args:
            threshold: Confidence cutoff threshold between 0.0 and 1.0.

        Returns:
            None

        Raises:
            ValueError: If threshold is outside [0.0, 1.0].

        Examples:
            >>> detector = PIIDetector()
            >>> detector.name
            'pii'
        """
        super().__init__(name="pii", threshold=threshold)

    def extract_entities(self, text: str) -> dict[str, list[str]]:
        """Extract all PII entities grouped by entity category.

        Args:
            text: Input string to inspect.

        Returns:
            dict[str, list[str]]: Mapping of entity types to list of matches.

        Raises:
            None

        Examples:
            >>> detector = PIIDetector()
            >>> entities = detector.extract_entities("Contact test@example.com")
            >>> "email" in entities
            True
        """
        results: dict[str, list[str]] = {}
        patterns: list[tuple[str, re.Pattern[str]]] = [
            ("email", _EMAIL_REGEX),
            ("obfuscated_email", _OBFUSCATED_EMAIL_REGEX),
            ("phone", _PHONE_REGEX),
            ("ssn_nir", _FRENCH_NIR_REGEX),
            ("siret", _SIRET_REGEX),
            ("internal_url", _INTERNAL_URL_REGEX),
        ]
        for category, pattern in patterns:
            matches = pattern.findall(text)
            if matches:
                results[category] = matches

        raw_ibans = _IBAN_REGEX.findall(text)
        if raw_ibans:
            results["iban"] = [i[0] if isinstance(i, tuple) else i for i in raw_ibans]

        raw_cards = _CREDIT_CARD_REGEX.findall(text)
        valid_cards = [c for c in raw_cards if _verify_luhn(c)]
        if valid_cards:
            results["credit_card"] = valid_cards

        return results

    def anonymize(self, text: str) -> tuple[str, dict[str, str]]:
        """Replace detected PII with reversible token placeholders.

        Args:
            text: Input text containing sensitive entities.

        Returns:
            tuple[str, dict[str, str]]: Sanitized text and reverse mapping dictionary.

        Raises:
            None

        Examples:
            >>> detector = PIIDetector()
            >>> anonymized, mapping = detector.anonymize("Call 0601020304 now")
            >>> "0601020304" not in anonymized
            True
        """
        entities = self.extract_entities(text)
        anonymized_text = text
        token_mapping: dict[str, str] = {}
        counter = 1

        for category, matches in entities.items():
            for item in matches:
                if item not in token_mapping.values():
                    token = f"{{{{{category.upper()}_{counter}}}}}"
                    token_mapping[token] = item
                    anonymized_text = anonymized_text.replace(item, token)
                    counter += 1

        return anonymized_text, token_mapping

    def deanonymize(self, text: str, token_mapping: dict[str, str]) -> str:
        """Restore original PII entities using a previously generated token mapping.

        Args:
            text: Anonymized text with placeholders.
            token_mapping: Dictionary mapping tokens to original values.

        Returns:
            str: Original reconstructed text.

        Raises:
            None

        Examples:
            >>> detector = PIIDetector()
            >>> text, mapping = detector.anonymize("Contact john@doe.com")
            >>> detector.deanonymize(text, mapping)
            'Contact john@doe.com'
        """
        restored = text
        for token, original in token_mapping.items():
            restored = restored.replace(token, original)
        return restored

    async def detect(
        self, text: str, context: dict[str, Any] | None = None
    ) -> DetectionResult:
        """Analyze text for presence and severity of PII items.

        Args:
            text: Raw input string to inspect.
            context: Optional contextual parameters.

        Returns:
            DetectionResult: Structured evaluation with entity counts and risk score.

        Raises:
            DetectionError: If PII scanning encounters an unexpected error.

        Examples:
            >>> import asyncio
            >>> detector = PIIDetector()
            >>> res = asyncio.run(detector.detect("Send money to test@example.com"))
            >>> res.details["entity_counts"]["email"]
            1
        """
        start_time = time.perf_counter()
        try:
            entities = self.extract_entities(text)
            highest_score = 0.0
            entity_counts: dict[str, int] = {}

            for cat, items in entities.items():
                entity_counts[cat] = len(items)
                weight = _SENSITIVITY_WEIGHTS.get(cat, 0.40)
                if weight > highest_score:
                    highest_score = weight

            is_detected = highest_score >= self._threshold
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            details: dict[str, Any] = {
                "entity_counts": entity_counts,
                "found_categories": list(entities.keys()),
            }

            primary_cat = list(entities.keys())[0] if entities else "clean"

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
                f"PII detection failed: {err}",
                detector_name=self._name,
            ) from err

"""Toxicity, harassment, and hostile language detector module.

This module provides detection mechanisms for abusive content, hate speech,
harassment, profanity, and physical threat statements across multiple linguistic
variations, semantic vectors, implicit micro-aggressions, and ML classification.
"""

import re
import time
from typing import Any

from sentinel.detection.base import BaseDetector, DetectionResult
from sentinel.exceptions import DetectionError

try:
    import sentence_transformers  # noqa: F401

    _HAS_SENTENCE_TRANSFORMERS = True
except ImportError:
    _HAS_SENTENCE_TRANSFORMERS = False

try:
    from transformers import pipeline  # noqa: F401

    _HAS_TRANSFORMERS = True
except ImportError:
    _HAS_TRANSFORMERS = False


_TOXICITY_LEXICONS: dict[str, list[re.Pattern[str]]] = {
    "hate_speech": [
        re.compile(
            r"\b(?:kill\s+all|exterminate|inferior\s+race|subhuman|hate\s+all)\b", re.I
        ),
        re.compile(r"\b(?:mort\s+aux|tuer\s+tous\s+les|race\s+inférieure)\b", re.I),
    ],
    "harassment": [
        re.compile(
            r"\b(?:you\s+(?:are|'re)\s+(?:\w+\s+){0,3}(?:stupid|worthless|ugly|trash|garbage|pathetic|incompetent|useless|idiot|clueless))\b",
            re.I,
        ),
        re.compile(
            r"\b(?:absolutely\s+(?:worthless|useless|incompetent|stupid|pathetic))\b",
            re.I,
        ),
        re.compile(
            r"\b(?:tu\s+es\s+(?:stupide|nul|idiot|inutile|moche|ordure))\b", re.I
        ),
        re.compile(r"\b(?:go\s+die|kill\s+yourself|kys)\b", re.I),
        re.compile(r"\b(?:piece\s+of\s+(?:trash|garbage|shit|crap))\b", re.I),
        re.compile(r"\b(?:shut\s+up|shut\s+your\s+mouth|ignorant\s+fool)\b", re.I),
        re.compile(
            r"\b(?:complete\s+and\s+utter\s+fool|stupidest\s+idea|pathetic\s+excuse)\b",
            re.I,
        ),
        re.compile(r"\b(?:lazy,\s+useless\s+people|contribute\s+nothing)\b", re.I),
        re.compile(r"\b(?:stupid\s+clown|worthless\s+pathetic\s+fool)\b", re.I),
    ],
    "violence": [
        re.compile(
            r"\b(?:how\s+to\s+(?:make|build)\s+a\s+bomb|manufacture\s+explosives)\b",
            re.I,
        ),
        re.compile(
            r"\b(?:comment\s+(?:fabriquer|faire)\s+une\s+bombe|fabriquer\s+des\s+explosifs)\b",
            re.I,
        ),
        re.compile(
            r"\b(?:stab|shoot|strangle|decapitate|slaughter)\s+(?:them|people|someone)\b",
            re.I,
        ),
    ],
    "sexual": [
        re.compile(
            r"\b(?:explicit\s+nsfw|non-consensual\s+intimate|child\s+exploitation)\b",
            re.I,
        ),
        re.compile(
            r"\b(?:contenu\s+sexuel\s+explicite|actes\s+sexuels\s+forcés)\b", re.I
        ),
    ],
}

_SEVERITY_WEIGHTS: dict[str, float] = {
    "violence": 0.95,
    "hate_speech": 0.90,
    "sexual": 0.90,
    "harassment": 0.85,
}

_REFERENCE_TOXIC_PROMPTS: list[str] = [
    "You are an incompetent fool who fails at everything.",
    "Get out of here you pathetic idiot and shut up.",
    "People like that are totally worthless and useless.",
    "What a complete clown who has no right to work here.",
    "Watch out, someone might reveal your confidential details.",
    "Your entire team is a humiliating disaster for this company.",
    "Individuals with your background do not belong in our organization.",
    "Extremist hate and violence against protected groups.",
    "How to build explosive devices and lethal weapons.",
    "You are a stupid moron who should never speak again.",
]

_IMPLICIT_TOXICITY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\b(?:functional\s+brain|universal\s+embarrassment)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:watch\s+your\s+back|you\s+will\s+regret|do\s+everyone\s+a\s+favor\s+and\s+quit)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:great|brilliant|genius)\s+job\s+(?:failing|ruining|crashing)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:people\s+like\s+you\s+do\s+not\s+belong)\b",
        re.I,
    ),
]

_QUOTE_PATTERNS: re.Pattern[str] = re.compile(
    r"\b(?:novel|dialogue\s+script|reading\s+the\s+book|playwright|literary\s+analysis)\b",
    re.I,
)


class ToxicityDetector(BaseDetector):
    """Detector for hostile, harassing, violent, or toxic user inputs.

    Attributes:
        name: Detector identifier ('toxicity').
        threshold: Score cutoff for declaring toxic content.
    """

    def __init__(
        self,
        threshold: float = 0.55,
        pretrained_model_name: str | None = "unitary/toxic-bert",
        enable_pretrained: bool = False,
    ) -> None:
        """Initialize the ToxicityDetector.

        Args:
            threshold: Confidence cutoff threshold between 0.0 and 1.0.
            pretrained_model_name: HuggingFace model identifier.
            enable_pretrained: Whether to attempt neural transformer download.
        """
        super().__init__(name="toxicity", threshold=threshold)
        self._pretrained_model_name = pretrained_model_name
        self._enable_pretrained = enable_pretrained
        self._pretrained_pipeline: Any = None
        self._transformer_model: Any = None
        self._init_models()

    def _init_models(self) -> None:
        """Initialize semantic vectorizer, ML classifier, and pipeline models."""
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        self._vectorizer = TfidfVectorizer(
            ngram_range=(1, 2), stop_words="english", max_features=400
        )
        self._classifier = LogisticRegression(C=1.5, max_iter=200)

        train_texts = [
            "You are incompetent and your work is awful",
            "Shut up and leave you fool",
            "A bunch of useless individuals with zero output",
            "An absolute clown who ruins all code",
            "Expose private details to hurt someone",
            "Nobody sensible respects your pathetic work",
            "A total humiliation and disgrace to the department",
            "Unqualified people should not belong in technical leadership",
            "Violent attack against minority communities",
            "Fabricating explosive munitions at home",
            "Please conduct thorough code reviews with polite feedback",
            "Encouraging inclusive discussions in engineering retrospectives",
            "Documentation guidelines for distributed teams",
            "Analyzing historical texts and classic literary citations",
            "Handling angry customer complaint transcripts objectively",
            "Simulation training scenarios for incident responders",
            "Database indexing and query execution planning",
            "Designing resilient microservice architectures",
        ]
        train_labels = [1] * 10 + [0] * 8

        features = self._vectorizer.fit_transform(train_texts)
        self._classifier.fit(features, train_labels)
        self._ref_tfidf = self._vectorizer.transform(_REFERENCE_TOXIC_PROMPTS)

        if self._enable_pretrained and _HAS_TRANSFORMERS:
            try:
                import torch

                device = 0 if torch.cuda.is_available() else -1
                self._pretrained_pipeline = pipeline(
                    "text-classification",
                    model=self._pretrained_model_name,
                    device=device,
                )
            except Exception:
                self._pretrained_pipeline = None

    def _check_pretrained_model(self, text: str) -> float:
        """Evaluate input using deep pretrained transformer pipeline.

        Args:
            text: Text string to evaluate.

        Returns:
            float: Model prediction confidence score.
        """
        if self._pretrained_pipeline is None:
            return 0.0
        try:
            preds = self._pretrained_pipeline(text)
            if preds and isinstance(preds, list):
                top_pred = preds[0]
                label = str(top_pred.get("label", "")).lower()
                prob = float(top_pred.get("score", 0.0))
                if any(k in label for k in ["toxic", "hate", "offensive", "label_1"]):
                    return prob
        except Exception:
            return 0.0
        return 0.0

    def _check_semantic_similarity(self, text: str) -> float:
        """Compute cosine similarity of input prompt against known toxic vectors.

        Args:
            text: Target prompt to evaluate.

        Returns:
            float: Maximum cosine similarity against reference toxic texts.
        """
        if _HAS_SENTENCE_TRANSFORMERS and self._transformer_model is not None:
            try:
                import numpy as np

                emb_text = self._transformer_model.encode([text])
                emb_refs = self._transformer_model.encode(_REFERENCE_TOXIC_PROMPTS)
                scores = np.dot(emb_text, emb_refs.T) / (
                    np.linalg.norm(emb_text) * np.linalg.norm(emb_refs, axis=1)
                )
                return float(np.max(scores))
            except Exception:
                pass

        text_vec = self._vectorizer.transform([text])
        if text_vec.nnz == 0:
            return 0.0
        dot_products = (text_vec * self._ref_tfidf.T).toarray()[0]
        max_sim = float(max(dot_products)) if len(dot_products) > 0 else 0.0
        return min(1.0, max(0.0, max_sim * 1.05))

    def _check_ml_classifier(self, text: str) -> float:
        """Predict toxicity probability using lightweight machine learning model.

        Args:
            text: Target prompt to evaluate.

        Returns:
            float: Probability score between 0.0 and 1.0.
        """
        text_vec = self._vectorizer.transform([text])
        if text_vec.nnz == 0:
            return 0.0
        probs = self._classifier.predict_proba(text_vec)
        return float(probs[0][1])

    def _check_implicit_toxicity(self, text: str) -> float:
        """Detect subtle hostility, sarcasm, veiled threats, or micro-aggressions.

        Args:
            text: Target string to evaluate.

        Returns:
            float: Implicit toxicity score.
        """
        for pattern in _IMPLICIT_TOXICITY_PATTERNS:
            if pattern.search(text):
                return 0.82
        return 0.0

    def _is_quoted_or_academic_context(self, text: str) -> bool:
        """Identify if hostile terms appear solely in quotations or literature.

        Args:
            text: Target string to inspect.

        Returns:
            bool: True if academic or narrative quoting framing is detected.
        """
        return bool(_QUOTE_PATTERNS.search(text))

    def _scan_categories(self, text: str) -> dict[str, list[str]]:
        """Scan input against toxicity category expressions.

        Args:
            text: Text to evaluate.

        Returns:
            dict[str, list[str]]: Mapping of category to matched pattern strings.
        """
        results: dict[str, list[str]] = {}
        for category, patterns in _TOXICITY_LEXICONS.items():
            for pattern in patterns:
                if pattern.search(text):
                    if category not in results:
                        results[category] = []
                    results[category].append(pattern.pattern)
        return results

    async def detect(
        self, text: str, context: dict[str, Any] | None = None
    ) -> DetectionResult:
        """Analyze text for toxic, harassing, violent, or hateful material.

        Args:
            text: Input string to inspect.
            context: Optional contextual dictionary.

        Returns:
            DetectionResult: Structured evaluation with category scores.

        Raises:
            DetectionError: If toxicity analysis fails unexpectedly.
        """
        start_time = time.perf_counter()
        try:
            category_matches = self._scan_categories(text)
            categories_found = list(category_matches.keys())

            lex_score = 0.0
            for cat in categories_found:
                weight = _SEVERITY_WEIGHTS.get(cat, 0.70)
                if weight > lex_score:
                    lex_score = weight

            pretrained_score = self._check_pretrained_model(text)
            semantic_score = self._check_semantic_similarity(text)
            ml_score = self._check_ml_classifier(text)
            implicit_score = self._check_implicit_toxicity(text)

            raw_score = max(
                lex_score,
                pretrained_score,
                semantic_score * 0.88,
                ml_score * 0.82,
                implicit_score,
            )

            if self._is_quoted_or_academic_context(text):
                raw_score *= 0.45

            is_detected = raw_score >= self._threshold
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            details: dict[str, Any] = {
                "matched_categories": categories_found,
                "lexicon_score": round(lex_score, 4),
                "pretrained_score": round(pretrained_score, 4),
                "semantic_score": round(semantic_score, 4),
                "ml_score": round(ml_score, 4),
                "implicit_score": round(implicit_score, 4),
            }

            primary_cat = categories_found[0] if categories_found else "toxicity"
            if not is_detected:
                primary_cat = "clean"

            return DetectionResult(
                detector_name=self._name,
                detected=is_detected,
                score=round(min(1.0, raw_score), 4),
                category=primary_cat,
                details=details,
                latency_ms=round(duration_ms, 2),
            )
        except Exception as err:
            raise DetectionError(
                f"Toxicity detection failed: {err}",
                detector_name=self._name,
            ) from err

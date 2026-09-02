import pytest

from sentinel.detection.base import DetectionResult
from sentinel.detection.ensemble import DetectionEnsemble, EnsembleResult
from sentinel.detection.toxicity import ToxicityDetector


@pytest.mark.asyncio
async def test_toxicity_semantic_ml_and_implicit() -> None:
    """Verify semantic similarity, ML classifier, and implicit patterns in toxicity.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If semantic, ML, or implicit detection methods fail.
    """
    detector = ToxicityDetector(threshold=0.55)

    pretrained_score = detector._check_pretrained_model("some random phrase")
    assert pretrained_score == 0.0

    clean_sem = detector._check_semantic_similarity(
        "Could you please review this pull request and share feedback"
    )
    assert clean_sem < 0.30

    toxic_sem = detector._check_semantic_similarity(
        "You are an incompetent fool who fails at everything."
    )
    assert toxic_sem > 0.40

    clean_ml = detector._check_ml_classifier(
        "Optimize database index performance and query execution plans"
    )
    assert clean_ml < 0.50

    toxic_ml = detector._check_ml_classifier(
        "You are incompetent and your work is awful"
    )
    assert toxic_ml > clean_ml

    sarcasm_score = detector._check_implicit_toxicity(
        "Great job failing to pass any of the tests in this sprint!"
    )
    assert sarcasm_score >= 0.80

    threat_score = detector._check_implicit_toxicity(
        "Watch your back after work, you will regret crossing me."
    )
    assert threat_score >= 0.80

    clean_implicit = detector._check_implicit_toxicity(
        "Great work completing the task on schedule!"
    )
    assert clean_implicit == 0.0


@pytest.mark.asyncio
async def test_toxicity_quotation_discounting() -> None:
    """Verify quotation framing reduces score to avoid false positives.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If quotation discounting fails to lower score.
    """
    detector = ToxicityDetector(threshold=0.55)

    raw_quote = (
        "In Dostoevsky's novel, the narrator states that you are an idiot "
        "to emphasize social hypocrisy."
    )
    assert detector._is_quoted_or_academic_context(raw_quote) is True

    result = await detector.detect(raw_quote)
    assert result.detected is False
    assert result.score < 0.55

    direct_insult = "You are an idiot and your work is completely worthless."
    direct_res = await detector.detect(direct_insult)
    assert direct_res.detected is True
    assert direct_res.score >= 0.55


@pytest.mark.asyncio
async def test_ensemble_confidence_weighted_fusion() -> None:
    """Verify confidence-weighted score computation in DetectionEnsemble.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If composite score does not weigh confident signals properly.
    """
    ensemble = DetectionEnsemble(
        warn_threshold=0.30,
        block_threshold=0.70,
        veto_threshold=0.70,
    )

    results_clean: list[DetectionResult] = [
        DetectionResult(
            detector_name="prompt_injection",
            detected=False,
            score=0.05,
            category="clean",
        ),
        DetectionResult(
            detector_name="jailbreak",
            detected=False,
            score=0.02,
            category="clean",
        ),
        DetectionResult(
            detector_name="toxicity",
            detected=False,
            score=0.01,
            category="clean",
        ),
    ]
    clean_score = ensemble._compute_composite_score(results_clean)
    assert clean_score < 0.20

    results_threat: list[DetectionResult] = [
        DetectionResult(
            detector_name="prompt_injection",
            detected=True,
            score=0.88,
            category="direct_injection",
        ),
        DetectionResult(
            detector_name="jailbreak",
            detected=False,
            score=0.05,
            category="clean",
        ),
    ]
    threat_score = ensemble._compute_composite_score(results_threat)
    assert threat_score >= 0.30


@pytest.mark.asyncio
async def test_ensemble_veto_and_decision_thresholds() -> None:
    """Verify critical detector veto rule and allow/warn/block cutoffs.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If veto rule or threshold cutoffs fail.
    """
    ensemble = DetectionEnsemble(
        warn_threshold=0.30,
        block_threshold=0.70,
        veto_threshold=0.70,
    )

    veto_results: dict[str, DetectionResult] = {
        "prompt_injection": DetectionResult(
            detector_name="prompt_injection",
            detected=True,
            score=0.85,
            category="direct_injection",
        ),
        "jailbreak": DetectionResult(
            detector_name="jailbreak",
            detected=False,
            score=0.05,
            category="clean",
        ),
    }
    decision, blocked = ensemble._determine_decision(0.50, veto_results)
    assert decision == "block"
    assert blocked is True

    warn_results: dict[str, DetectionResult] = {
        "pii": DetectionResult(
            detector_name="pii",
            detected=True,
            score=0.55,
            category="email",
        ),
    }
    warn_dec, warn_blocked = ensemble._determine_decision(0.45, warn_results)
    assert warn_dec == "warn"
    assert warn_blocked is False

    allow_results: dict[str, DetectionResult] = {
        "pii": DetectionResult(
            detector_name="pii",
            detected=False,
            score=0.10,
            category="clean",
        ),
    }
    allow_dec, allow_blocked = ensemble._determine_decision(0.15, allow_results)
    assert allow_dec == "allow"
    assert allow_blocked is False


@pytest.mark.asyncio
async def test_ensemble_detect_and_sync_interfaces() -> None:
    """Verify detect and detect_sync aliases on DetectionEnsemble.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If detect or detect_sync methods fail.
    """
    ensemble = DetectionEnsemble()

    async_res = await ensemble.detect("Hello world, this is a clean prompt.")
    assert isinstance(async_res, EnsembleResult)
    assert async_res.decision == "allow"

    sync_res = ensemble.detect_sync("Safe request for information.")
    assert isinstance(sync_res, EnsembleResult)
    assert sync_res.decision == "allow"

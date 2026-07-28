from typing import Literal

import yaml
from pydantic import BaseModel, Field


class PolicyRule(BaseModel):
    """Specification of a condition and action within a security policy.

    Attributes:
        name: Name identifier for the rule.
        detector: Target detector name to apply this rule to (or 'any').
        min_score: Minimum threat score threshold to trigger this rule.
        action: Governance action to take ('allow', 'warn', 'block', 'redact').
    """

    name: str
    detector: str = Field(default="any")
    min_score: float = Field(default=0.70, ge=0.0, le=1.0)
    action: Literal["allow", "warn", "block", "redact"] = Field(default="block")


class Policy(BaseModel):
    """Complete versioned governance policy definition.

    Attributes:
        policy_id: Unique policy identifier string.
        version: Semantic version of this policy definition.
        description: Explanatory summary of policy purpose.
        rules: Ordered sequence of PolicyRule specifications.
    """

    policy_id: str
    version: str = Field(default="1.0.0")
    description: str = Field(default="Standard AI governance policy")
    rules: list[PolicyRule] = Field(default_factory=list)


class SimulationReport(BaseModel):
    """Result summary produced by simulating a policy against interaction datasets.

    Attributes:
        total_evaluated: Total count of interactions processed.
        blocked_count: Number of interactions triggering a 'block' action.
        warned_count: Number of interactions triggering a 'warn' action.
        allowed_count: Number of interactions permitted without intervention.
        rule_hits: Frequency counter of individual rule activations.
    """

    total_evaluated: int = Field(ge=0)
    blocked_count: int = Field(default=0, ge=0)
    warned_count: int = Field(default=0, ge=0)
    allowed_count: int = Field(default=0, ge=0)
    rule_hits: dict[str, int] = Field(default_factory=dict)


class PolicyEngine:
    """Evaluates interactions against active YAML policies and runs simulations.

    Attributes:
        policies: Dictionary storing registered policies indexed by policy_id.
    """

    def __init__(self) -> None:
        """Initialize PolicyEngine with an empty policy registry.

        Args:
            None

        Returns:
            None

        Raises:
            None

        Examples:
            >>> pe = PolicyEngine()
            >>> len(pe.policies)
            0
        """
        self.policies: dict[str, Policy] = {}

    def load_from_yaml(self, yaml_content: str) -> Policy:
        """Parse, validate, and register a policy definition from a YAML string.

        Args:
            yaml_content: Raw YAML document string.

        Returns:
            Policy: Parsed and validated policy object.

        Raises:
            ValueError: If YAML structure or fields fail validation.

        Examples:
            >>> pe = PolicyEngine()
            >>> y = "policy_id: p1\\nversion: 1.0\\nrules: []"
            >>> p = pe.load_from_yaml(y)
            >>> p.policy_id
            'p1'
        """
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            raise ValueError("YAML must represent a valid dictionary mapping")
        policy = Policy.model_validate(data)
        self.policies[policy.policy_id] = policy
        return policy

    def evaluate(
        self,
        policy_id: str,
        detector_results: dict[str, float],
    ) -> tuple[str, str | None]:
        """Evaluate detector score outputs against a registered policy's rules.

        Args:
            policy_id: Identifier of the target policy to enforce.
            detector_results: Mapping of detector name to evaluated score.

        Returns:
            tuple[str, str | None]: (Action, Triggering rule name or None).

        Raises:
            KeyError: If policy_id is not registered.

        Examples:
            >>> pe = PolicyEngine()
            >>> y = (
            ...     "policy_id: p1\\n"
            ...     "rules:\\n"
            ...     "  - name: r1\\n"
            ...     "    detector: injection\\n"
            ...     "    min_score: 0.8\\n"
            ...     "    action: block"
            ... )
            >>> _ = pe.load_from_yaml(y)
            >>> action, rule = pe.evaluate("p1", {"injection": 0.85})
            >>> action
            'block'
        """
        policy = self.policies[policy_id]
        for rule in policy.rules:
            if rule.detector == "any":
                for score in detector_results.values():
                    if score >= rule.min_score:
                        return rule.action, rule.name
            elif rule.detector in detector_results:
                score = detector_results[rule.detector]
                if score >= rule.min_score:
                    return rule.action, rule.name

        return "allow", None

    def _evaluate_rules(
        self, rules: list[PolicyRule], sample: dict[str, float]
    ) -> tuple[str, str | None]:
        """Match sample detector scores against policy rules.

        Args:
            rules: Sequence of policy rules.
            sample: Evaluated threat score dictionary.

        Returns:
            tuple[str, str | None]: Action and triggered rule name.

        Raises:
            None

        Examples:
            >>> pass
        """
        for rule in rules:
            if rule.detector == "any":
                if any(score >= rule.min_score for score in sample.values()):
                    return rule.action, rule.name
            elif rule.detector in sample and sample[rule.detector] >= rule.min_score:
                return rule.action, rule.name
        return "allow", None

    def simulate(
        self,
        policy: Policy,
        sample_evaluations: list[dict[str, float]],
    ) -> SimulationReport:
        """Run policy evaluation against an offline dataset without enforcement.

        Args:
            policy: Policy instance to test.
            sample_evaluations: List of detector score dictionaries.

        Returns:
            SimulationReport: Aggregated metric breakdown of policy actions.

        Raises:
            None

        Examples:
            >>> pe = PolicyEngine()
            >>> rule = PolicyRule(name="r", detector="any", min_score=0.5)
            >>> pol = Policy(policy_id="test", rules=[rule])
            >>> rep = pe.simulate(pol, [{"inj": 0.9}])
            >>> rep.blocked_count
            1
        """
        blocked = 0
        warned = 0
        allowed = 0
        rule_hits: dict[str, int] = {}

        for sample in sample_evaluations:
            action, triggered_rule = self._evaluate_rules(policy.rules, sample)
            if action == "block":
                blocked += 1
            elif action == "warn":
                warned += 1
            else:
                allowed += 1

            if triggered_rule is not None:
                rule_hits[triggered_rule] = rule_hits.get(triggered_rule, 0) + 1

        return SimulationReport(
            total_evaluated=len(sample_evaluations),
            blocked_count=blocked,
            warned_count=warned,
            allowed_count=allowed,
            rule_hits=rule_hits,
        )

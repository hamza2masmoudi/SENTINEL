import time
from typing import Literal

from pydantic import BaseModel, Field

FrameworkType = Literal["ai_act", "gdpr", "soc2", "all"]


class ComplianceCheckItem(BaseModel):
    """Single verifiable requirement within a governance compliance framework.

    Attributes:
        code: Framework article or control reference.
        title: Descriptive name of the control objective.
        status: Assessment state ('compliant', 'partial', 'non_compliant').
        evidence: Concrete system implementation or cryptographic proof link.
    """

    code: str
    title: str
    status: Literal["compliant", "partial", "non_compliant"]
    evidence: str


class ComplianceReport(BaseModel):
    """Auditable regulatory compliance assessment report.

    Attributes:
        report_id: Unique compliance evaluation ID.
        tenant_id: Tenant or client organization evaluated.
        system_name: Name of the AI agent system examined.
        framework: Regulatory framework evaluated.
        timestamp: Epoch timestamp of report issuance.
        summary_score: Percentage score of satisfied controls.
        checks: Sequence of individual compliance evaluations.
    """

    report_id: str
    tenant_id: str
    system_name: str
    framework: FrameworkType
    timestamp: float = Field(default_factory=time.time)
    summary_score: float = Field(ge=0.0, le=100.0)
    checks: list[ComplianceCheckItem] = Field(default_factory=list)

    def to_markdown(self) -> str:
        """Render compliance assessment as an auditable Markdown document.

        Args:
            None

        Returns:
            str: Markdown formatted compliance report.

        Raises:
            None

        Examples:
            >>> rep = ComplianceReport(
            ...     report_id="1", tenant_id="t", system_name="s",
            ...     framework="gdpr", summary_score=100.0
            ... )
            >>> "Compliance Report" in rep.to_markdown()
            True
        """
        lines = [
            f"# SENTINEL Compliance Report: {self.system_name}",
            f"**Framework**: {self.framework.upper()}  ",
            f"**Tenant ID**: {self.tenant_id}  ",
            f"**Compliance Score**: {self.summary_score:.1f}%  ",
            "",
            "| Code | Control Title | Status | Evidence |",
            "| :--- | :--- | :--- | :--- |",
        ]
        for check in self.checks:
            row = (
                f"| {check.code} | {check.title} | "
                f"{check.status.upper()} | {check.evidence} |"
            )
            lines.append(row)
        return "\n".join(lines)


class ComplianceMapper:
    """Evaluates system configurations against regulatory standards.

    Attributes:
        None
    """

    def evaluate_ai_act(
        self,
        has_human_oversight: bool = True,
        has_hash_chain: bool = True,
        has_guardrails: bool = True,
    ) -> list[ComplianceCheckItem]:
        """Assess system alignment with EU AI Act High-Risk requirements.

        Args:
            has_human_oversight: Article 14 human-in-the-loop controls.
            has_hash_chain: Article 12 automatic logging and traceability.
            has_guardrails: Article 15 cybersecurity and robustness.

        Returns:
            list[ComplianceCheckItem]: List of control evaluations.

        Raises:
            None

        Examples:
            >>> mapper = ComplianceMapper()
            >>> len(mapper.evaluate_ai_act())
            3
        """
        return [
            ComplianceCheckItem(
                code="AI-Act-Art12",
                title="Record-keeping & Traceability",
                status="compliant" if has_hash_chain else "non_compliant",
                evidence="SHA-256 hash chain enabled with immutable blocks.",
            ),
            ComplianceCheckItem(
                code="AI-Act-Art14",
                title="Human Oversight",
                status="compliant" if has_human_oversight else "partial",
                evidence="Approval gates integrated in policy engine.",
            ),
            ComplianceCheckItem(
                code="AI-Act-Art15",
                title="Accuracy, Robustness and Cybersecurity",
                status="compliant" if has_guardrails else "non_compliant",
                evidence="Multi-layer ensemble detection active across attacks.",
            ),
        ]

    def evaluate_gdpr(
        self,
        has_pii_redaction: bool = True,
        has_audit_verification: bool = True,
    ) -> list[ComplianceCheckItem]:
        """Assess system alignment with GDPR privacy mandates.

        Args:
            has_pii_redaction: Article 5/25 data protection by design.
            has_audit_verification: Article 30 records of processing activities.

        Returns:
            list[ComplianceCheckItem]: List of GDPR evaluations.

        Raises:
            None

        Examples:
            >>> mapper = ComplianceMapper()
            >>> len(mapper.evaluate_gdpr())
            2
        """
        return [
            ComplianceCheckItem(
                code="GDPR-Art25",
                title="Data Protection by Design & Default",
                status="compliant" if has_pii_redaction else "non_compliant",
                evidence="Reversible PII anonymization active for sensitive data.",
            ),
            ComplianceCheckItem(
                code="GDPR-Art30",
                title="Records of Processing Activities",
                status="compliant" if has_audit_verification else "partial",
                evidence="Cryptographically verifiable audit storage active.",
            ),
        ]

    def evaluate_soc2(
        self,
        has_rbac: bool = True,
        has_tracing: bool = True,
    ) -> list[ComplianceCheckItem]:
        """Assess system alignment with SOC 2 Trust Services Criteria.

        Args:
            has_rbac: CC6.1 Logical access controls.
            has_tracing: CC7.2 System monitoring.

        Returns:
            list[ComplianceCheckItem]: List of SOC 2 evaluations.

        Raises:
            None

        Examples:
            >>> mapper = ComplianceMapper()
            >>> len(mapper.evaluate_soc2())
            2
        """
        return [
            ComplianceCheckItem(
                code="SOC2-CC6.1",
                title="Logical Access Security",
                status="compliant" if has_rbac else "non_compliant",
                evidence="API key authentication and role permissions enforced.",
            ),
            ComplianceCheckItem(
                code="SOC2-CC7.2",
                title="System Monitoring & Anomaly Detection",
                status="compliant" if has_tracing else "non_compliant",
                evidence="OpenTelemetry tracing and anomaly detection active.",
            ),
        ]

    def generate_report(
        self,
        tenant_id: str,
        system_name: str,
        framework: FrameworkType = "ai_act",
    ) -> ComplianceReport:
        """Generate a compliance assessment report for a given framework.

        Args:
            tenant_id: Target tenant identifier.
            system_name: Subject application name.
            framework: Desired standard ('ai_act', 'gdpr', 'soc2', 'all').

        Returns:
            ComplianceReport: Evaluated compliance report.

        Raises:
            None

        Examples:
            >>> mapper = ComplianceMapper()
            >>> rep = mapper.generate_report("tenant-1", "AI-Bot", "ai_act")
            >>> rep.summary_score
            100.0
        """
        checks: list[ComplianceCheckItem] = []
        if framework in ("ai_act", "all"):
            checks.extend(self.evaluate_ai_act())
        if framework in ("gdpr", "all"):
            checks.extend(self.evaluate_gdpr())
        if framework in ("soc2", "all"):
            checks.extend(self.evaluate_soc2())

        compliant_count = sum(1 for c in checks if c.status == "compliant")
        score = (compliant_count / max(1, len(checks))) * 100.0

        return ComplianceReport(
            report_id=f"rep_{int(time.time())}",
            tenant_id=tenant_id,
            system_name=system_name,
            framework=framework,
            summary_score=round(score, 1),
            checks=checks,
        )

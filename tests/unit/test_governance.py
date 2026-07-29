import pytest

from sentinel.exceptions import AuditIntegrityError, AuthenticationError
from sentinel.governance.audit import AuditLogger
from sentinel.governance.compliance import ComplianceMapper
from sentinel.governance.hashchain import HashChain
from sentinel.governance.policies import PolicyEngine
from sentinel.governance.rbac import RBACManager


def test_hash_chain_tamper_detection() -> None:
    """Verify cryptographic hash chain detects modification to recorded block payloads.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If tamper verification fails to detect corruption.
    """
    hc = HashChain()
    hc.add_block({"event": "turn_1", "score": 0.2})
    hc.add_block({"event": "turn_2", "score": 0.5})

    valid, _ = hc.verify_integrity()
    assert valid is True

    hc.chain[1].data["score"] = 0.99
    with pytest.raises(AuditIntegrityError):
        hc.verify_integrity()


def test_audit_logger_crud_and_export() -> None:
    """Verify AuditLogger recording, retrieval, integrity checking, and CSV export.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If audit lifecycle methods fail.
    """
    logger = AuditLogger(":memory:")
    rec = logger.record_interaction(
        record_id="rec-001",
        input_text="Safe query",
        output_text="Response",
        decision="allow",
        composite_score=0.1,
        tenant_id="tenant-acme",
    )
    assert rec.record_id == "rec-001"
    assert rec.block_hash != ""

    records = logger.list_records("tenant-acme")
    assert len(records) == 1
    assert records[0].input_text == "Safe query"

    assert logger.verify_integrity() is True

    csv_data = logger.export_csv()
    assert "rec-001" in csv_data
    assert "tenant-acme" in csv_data


def test_policy_engine_evaluation_and_simulation() -> None:
    """Verify PolicyEngine YAML loading, enforcement, and simulation reporting.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If policy evaluation or simulation fails.
    """
    pe = PolicyEngine()
    yaml_policy = """
    policy_id: enterprise_guard
    version: 1.0.0
    rules:
      - name: block_injection
        detector: injection
        min_score: 0.70
        action: block
      - name: warn_pii
        detector: pii
        min_score: 0.50
        action: warn
    """
    policy = pe.load_from_yaml(yaml_policy)
    assert policy.policy_id == "enterprise_guard"

    action, rule = pe.evaluate("enterprise_guard", {"injection": 0.85})
    assert action == "block"
    assert rule == "block_injection"

    action_safe, rule_safe = pe.evaluate("enterprise_guard", {"injection": 0.20})
    assert action_safe == "allow"
    assert rule_safe is None

    report = pe.simulate(
        policy,
        [
            {"injection": 0.90},
            {"pii": 0.60},
            {"injection": 0.10},
        ],
    )
    assert report.total_evaluated == 3
    assert report.blocked_count == 1
    assert report.warned_count == 1
    assert report.allowed_count == 1


def test_rbac_api_key_authentication_and_authorization() -> None:
    """Verify RBACManager key provisioning, authentication, and role authorization.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If authentication or permission check fails.
    """
    rbac = RBACManager()

    admin_token, admin_rec = rbac.create_api_key("acme", "admin")
    assert admin_token.startswith("snt_")

    authenticated = rbac.authenticate_key(admin_token)
    assert authenticated.key_id == admin_rec.key_id

    assert rbac.authorize(admin_rec, "policies_write") is True
    assert rbac.authorize(admin_rec, "admin_manage") is True

    user_token, user_rec = rbac.create_api_key("acme", "user")
    assert rbac.authorize(user_rec, "policies_write") is False
    assert rbac.authorize(user_rec, "guard") is True

    with pytest.raises(AuthenticationError):
        rbac.authenticate_key("invalid_token")


def test_compliance_reporting() -> None:
    """Verify ComplianceMapper evaluations across AI Act, GDPR, and SOC2.

    Args:
        None

    Returns:
        None

    Raises:
        AssertionError: If compliance reporting fails.
    """
    mapper = ComplianceMapper()
    report = mapper.generate_report(
        tenant_id="tenant-corp",
        system_name="Finance-Assistant",
        framework="all",
    )
    assert report.summary_score > 0.0
    assert len(report.checks) >= 7

    markdown = report.to_markdown()
    assert "# SENTINEL Compliance Report" in markdown
    assert "AI-Act-Art12" in markdown
    assert "GDPR-Art25" in markdown
    assert "SOC2-CC6.1" in markdown

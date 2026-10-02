from app.db.models import GovernanceControl, GovernanceDocument
from app.services.governance_service import find_governance_matches
from app.services.investigation_validator import validate_governance_matches


def test_governance_matching_is_tenant_scoped_and_supports_global_controls(
    db_session,
):
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"

    global_document = GovernanceDocument(
        id="doc-global",
        tenant_id=None,
        document_type="FRAMEWORK",
        name="NIST Test Framework",
        version="1.0",
        issuer="Test",
        source="test",
        status="ACTIVE",
    )

    tenant_a_document = GovernanceDocument(
        id="doc-tenant-a",
        tenant_id=tenant_a,
        document_type="POLICY",
        name="Tenant A Transaction Policy",
        version="1.0",
        issuer="Tenant A",
        source="test",
        status="ACTIVE",
    )

    tenant_b_document = GovernanceDocument(
        id="doc-tenant-b",
        tenant_id=tenant_b,
        document_type="POLICY",
        name="Tenant B Transaction Policy",
        version="1.0",
        issuer="Tenant B",
        source="test",
        status="ACTIVE",
    )

    db_session.add_all(
        [
            global_document,
            tenant_a_document,
            tenant_b_document,
        ]
    )
    db_session.flush()

    db_session.add_all(
        [
            GovernanceControl(
                id="ctrl-global",
                governance_document_id="doc-global",
                control_id="NIST-TEST-001",
                title="Transaction monitoring",
                control_text="transaction monitoring",
                control_type="FRAMEWORK_CONTROL",
                framework="NIST",
            ),
            GovernanceControl(
                id="ctrl-tenant-a",
                governance_document_id="doc-tenant-a",
                control_id="POLICY-A-001",
                title="High value transaction review",
                control_text="high value transaction review",
                control_type="POLICY_REQUIREMENT",
            ),
            GovernanceControl(
                id="ctrl-tenant-b",
                governance_document_id="doc-tenant-b",
                control_id="POLICY-B-001",
                title="High value transaction review",
                control_text="high value transaction review",
                control_type="POLICY_REQUIREMENT",
            ),
        ]
    )
    db_session.commit()

    evidence = [
        {
            "id": "EV-001",
            "source": "transaction-monitoring",
            "summary": "High value transaction review was triggered.",
            "text": "high value transaction review transaction monitoring",
        }
    ]

    tenant_a_matches = find_governance_matches(
        db_session,
        tenant_id=tenant_a,
        evidence_items=evidence,
    )

    references_a = {
        match.control_reference
        for match in tenant_a_matches
    }

    assert "NIST-TEST-001" in references_a
    assert "POLICY-A-001" in references_a
    assert "POLICY-B-001" not in references_a

    policy_match = next(
        match
        for match in tenant_a_matches
        if match.control_reference == "POLICY-A-001"
    )

    assert policy_match.relationship_type == "mapped_to"
    assert policy_match.supporting_evidence == ["EV-001"]
    assert policy_match.validation_status == "candidate"
    assert policy_match.confidence < 0.5
    assert "does not establish" in policy_match.match_reason

    validated = validate_governance_matches(
        [policy_match.__dict__],
        {"EV-001"},
    )
    assert validated[0]["validation_status"] == "candidate"


def test_governance_matching_does_not_match_without_evidence(
    db_session,
):
    document = GovernanceDocument(
        id="doc-empty",
        tenant_id=None,
        document_type="REGULATION",
        name="Test Regulation",
        version="1.0",
        issuer="Test",
        source="test",
        status="ACTIVE",
    )

    db_session.add(document)
    db_session.flush()

    db_session.add(
        GovernanceControl(
            id="ctrl-empty",
            governance_document_id="doc-empty",
            control_id="CBN-TEST-001",
            title="Transaction reporting",
            control_text="transaction reporting",
            control_type="REGULATORY_REQUIREMENT",
        )
    )
    db_session.commit()

    matches = find_governance_matches(
        db_session,
        tenant_id="tenant-a",
        evidence_items=[],
    )

    assert matches == []

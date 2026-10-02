from types import SimpleNamespace

from app.db.models import FindingGovernanceLink, GovernanceControl, GovernanceDocument
from app.services.governance_service import find_governance_matches
from app.services.investigation_validator import validate_governance_matches
from app.services.intelligence_service import _persist_validated_governance_links


def test_validated_governance_link_is_persisted_and_deduplicated(db_session):
    document = GovernanceDocument(
        id="doc-persist",
        tenant_id="tenant-a",
        document_type="POLICY",
        name="Tenant Transaction Policy",
        version="1.0",
        issuer="Tenant A",
        source="test",
        status="ACTIVE",
    )

    control = GovernanceControl(
        id="ctrl-persist",
        governance_document_id="doc-persist",
        control_id="POLICY-001",
        title="Transaction review",
        control_text="transaction review",
        control_type="POLICY_REQUIREMENT",
    )

    db_session.add_all([document, control])
    db_session.commit()

    finding = SimpleNamespace(
        supporting_evidence=["EV-001"],
    )

    match = {
        "control_id": "ctrl-persist",
        "relationship_type": "violates",
        "match_reason": "Evidence-backed policy match.",
        "supporting_evidence": ["EV-001"],
        "confidence": 1.0,
        "validation_status": "validated",
    }

    _persist_validated_governance_links(
        db_session,
        incident_id="incident-001",
        findings=[finding],
        validated_governance_matches=[match],
    )
    db_session.commit()

    links = db_session.query(FindingGovernanceLink).all()

    assert len(links) == 1
    assert links[0].incident_id == "incident-001"
    assert links[0].finding_id == "finding-1"
    assert links[0].control_id == "ctrl-persist"
    assert links[0].relationship_type == "violates"
    assert links[0].supporting_evidence == ["EV-001"]
    assert links[0].validation_status == "validated"

    # Calling the persistence helper again must not create a duplicate.
    _persist_validated_governance_links(
        db_session,
        incident_id="incident-001",
        findings=[finding],
        validated_governance_matches=[match],
    )
    db_session.commit()

    links = db_session.query(FindingGovernanceLink).all()
    assert len(links) == 1


def test_unvalidated_governance_matches_are_not_persisted(db_session):
    document = GovernanceDocument(
        id="doc-rejected",
        tenant_id="tenant-a",
        document_type="REGULATION",
        name="Test Regulation",
        version="1.0",
        issuer="Test",
        source="test",
        status="ACTIVE",
    )

    control = GovernanceControl(
        id="ctrl-rejected",
        governance_document_id="doc-rejected",
        control_id="REG-001",
        title="Transaction reporting",
        control_text="transaction reporting",
        control_type="REGULATORY_REQUIREMENT",
    )

    db_session.add_all([document, control])
    db_session.commit()

    finding = SimpleNamespace(
        supporting_evidence=["EV-002"],
    )

    rejected_match = {
        "control_id": "ctrl-rejected",
        "relationship_type": "subject_to",
        "match_reason": "Unsupported relationship.",
        "supporting_evidence": ["EV-002"],
        "confidence": 0.5,
        "validation_status": "rejected",
    }

    _persist_validated_governance_links(
        db_session,
        incident_id="incident-002",
        findings=[finding],
        validated_governance_matches=[rejected_match],
    )
    db_session.commit()

    links = db_session.query(FindingGovernanceLink).all()

    assert links == []


def test_governance_candidate_requires_explicit_evidence_backing_before_persistence(
    db_session,
):
    document = GovernanceDocument(
        id="doc-lifecycle",
        tenant_id="tenant-lifecycle",
        document_type="POLICY",
        name="Transaction Review Policy",
        version="1.0",
        issuer="Test Bank",
        source="test",
        status="ACTIVE",
    )
    control = GovernanceControl(
        id="ctrl-lifecycle",
        governance_document_id="doc-lifecycle",
        control_id="POLICY-REVIEW-001",
        title="High value transaction review",
        control_text="high value transaction review",
        control_type="POLICY_REQUIREMENT",
    )
    db_session.add_all([document, control])
    db_session.commit()

    evidence = [{
        "evidence_id": "EV-LIFECYCLE",
        "text": "A high value transaction review was triggered.",
    }]
    candidate = find_governance_matches(
        db_session,
        tenant_id="tenant-lifecycle",
        evidence_items=evidence,
    )[0]
    candidate_payload = candidate.__dict__
    validated_candidate = validate_governance_matches(
        [candidate_payload],
        {"EV-LIFECYCLE"},
    )
    unsupported = dict(candidate_payload)
    unsupported["validation_status"] = "evidence_backed"
    rejected_for_missing_evidence = validate_governance_matches(
        [unsupported],
        set(),
    )
    assert rejected_for_missing_evidence[0]["validation_status"] == "rejected"

    finding = SimpleNamespace(supporting_evidence=["EV-LIFECYCLE"])
    _persist_validated_governance_links(
        db_session,
        incident_id="incident-lifecycle",
        findings=[finding],
        validated_governance_matches=[
            *validated_candidate,
            *rejected_for_missing_evidence,
        ],
    )
    db_session.flush()
    assert db_session.query(FindingGovernanceLink).count() == 0

    # A separate evidence review explicitly backs the relationship. The
    # validator still checks reference integrity before persistence.
    evidence_backed = dict(candidate_payload)
    evidence_backed["validation_status"] = "evidence_backed"
    validated = validate_governance_matches(
        [evidence_backed],
        {"EV-LIFECYCLE"},
    )
    assert validated[0]["validation_status"] == "validated"

    _persist_validated_governance_links(
        db_session,
        incident_id="incident-lifecycle",
        findings=[finding],
        validated_governance_matches=validated,
    )
    db_session.commit()

    links = db_session.query(FindingGovernanceLink).all()
    assert len(links) == 1
    assert links[0].validation_status == "validated"

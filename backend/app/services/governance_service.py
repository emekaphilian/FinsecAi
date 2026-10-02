from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import GovernanceControl, GovernanceDocument


@dataclass(frozen=True)
class GovernanceMatch:
    control_id: str
    governance_document_id: str
    document_type: str
    document_name: str
    document_version: str
    control_reference: str
    control_title: str
    control_text: str
    relationship_type: str
    match_reason: str
    supporting_evidence: list[str]
    confidence: float
    validation_status: str


def _normalise(value: Any) -> str:
    return str(value or "").strip().lower()


def _evidence_text(evidence: dict[str, Any]) -> str:
    parts = [
        evidence.get("source"),
        evidence.get("summary"),
        evidence.get("text"),
        evidence.get("content"),
    ]
    return " ".join(str(part) for part in parts if part).lower()


def _control_matches_evidence(
    control: GovernanceControl,
    evidence_items: list[dict[str, Any]],
) -> tuple[bool, list[str], str]:
    control_terms = {
        term
        for term in (
            _normalise(control.control_id),
            _normalise(control.title),
            _normalise(control.control_text),
        )
        if term
    }

    if not control_terms:
        return False, [], ""

    matched_evidence: list[str] = []

    for evidence in evidence_items:
        evidence_id = str(
            evidence.get("id")
            or evidence.get("evidence_id")
            or ""
        )

        evidence_text = _evidence_text(evidence)

        if not evidence_text:
            continue

        matched_terms = [
            term
            for term in control_terms
            if len(term) >= 4 and term in evidence_text
        ]

        if matched_terms and evidence_id:
            matched_evidence.append(evidence_id)

    if not matched_evidence:
        return False, [], ""

    return (
        True,
        matched_evidence,
        "Keyword overlap suggests relevance only; it does not establish applicability or a violation.",
    )


def find_governance_matches(
    db: Session,
    *,
    tenant_id: str,
    evidence_items: list[dict[str, Any]],
) -> list[GovernanceMatch]:
    if not evidence_items:
        return []

    documents = db.scalars(
        select(GovernanceDocument).where(
            GovernanceDocument.status == "ACTIVE",
            (
                (GovernanceDocument.tenant_id == tenant_id)
                | (GovernanceDocument.tenant_id.is_(None))
            ),
        )
    ).all()

    if not documents:
        return []

    document_ids = [document.id for document in documents]

    controls = db.scalars(
        select(GovernanceControl).where(
            GovernanceControl.governance_document_id.in_(document_ids)
        )
    ).all()
    controls = [
        control for control in controls
        if (control.metadata_json or {}).get("review_status", "APPROVED") == "APPROVED"
    ]

    documents_by_id = {
        document.id: document
        for document in documents
    }

    matches: list[GovernanceMatch] = []

    for control in controls:
        document = documents_by_id.get(control.governance_document_id)

        if document is None:
            continue

        matched, supporting_evidence, reason = _control_matches_evidence(
            control,
            evidence_items,
        )

        if not matched:
            continue

        matches.append(
            GovernanceMatch(
                control_id=control.id,
                governance_document_id=document.id,
                document_type=document.document_type,
                document_name=document.name,
                document_version=document.version,
                control_reference=control.control_id,
                control_title=control.title,
                control_text=control.control_text,
                # Retrieval cannot establish that a policy was violated or a
                # regulation applies. Keep all text matches non-assertive.
                relationship_type="mapped_to",
                match_reason=reason,
                supporting_evidence=supporting_evidence,
                confidence=0.25,
                validation_status="candidate",
            )
        )

    return matches

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


GovernanceDocumentType = Literal[
    "POLICY",
    "REGULATION",
    "FRAMEWORK",
]

GovernanceDocumentStatus = Literal[
    "ACTIVE",
    "INACTIVE",
    "SUPERSEDED",
]

GovernanceControlType = Literal[
    "POLICY_REQUIREMENT",
    "REGULATORY_REQUIREMENT",
    "FRAMEWORK_CONTROL",
]

GovernanceRelationshipType = Literal[
    "violates",
    "subject_to",
    "mapped_to",
]

GovernanceValidationStatus = Literal[
    "candidate",
    "evidence_backed",
    "validated",
    "rejected",
]


class GovernanceDocumentCreate(BaseModel):
    tenant_id: str | None = None
    document_type: GovernanceDocumentType
    name: str
    version: str
    issuer: str = ""
    effective_date: datetime | None = None
    source: str = ""
    dataset_source: str | None = None
    dataset_id: str | None = None
    status: GovernanceDocumentStatus = "ACTIVE"
    metadata: dict[str, Any] = Field(default_factory=dict)


class GovernanceDocumentResponse(GovernanceDocumentCreate):
    id: str
    created_at: datetime
    updated_at: datetime


class GovernanceControlCreate(BaseModel):
    governance_document_id: str
    control_id: str
    title: str = ""
    control_text: str = ""
    control_type: GovernanceControlType
    framework: str | None = None
    parent_control_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GovernanceControlResponse(GovernanceControlCreate):
    id: str
    created_at: datetime


class FindingGovernanceLinkCreate(BaseModel):
    incident_id: str
    finding_id: str
    control_id: str
    relationship_type: GovernanceRelationshipType
    match_reason: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    validation_status: GovernanceValidationStatus = "candidate"


class FindingGovernanceLinkResponse(FindingGovernanceLinkCreate):
    id: str
    created_at: datetime

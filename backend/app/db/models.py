import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base, engine

_use_pgvector = getattr(engine.dialect, "name", "").startswith("postgres")

if _use_pgvector:
    from pgvector.sqlalchemy import Vector


def _uuid() -> str:
    return str(uuid.uuid4())


class TenantType(StrEnum):
    DEMO = "DEMO"
    CUSTOMER = "CUSTOMER"


class TenantProvenance(StrEnum):
    LEGITIMATE_DEMO = "LEGITIMATE_DEMO"
    LEGITIMATE_CUSTOMER = "LEGITIMATE_CUSTOMER"
    BENCHMARK = "BENCHMARK"
    DIAGNOSTIC = "DIAGNOSTIC"
    TEST = "TEST"
    UNKNOWN = "UNKNOWN"


class TenantStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    INACTIVE = "INACTIVE"


class UserStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, unique=True)
    description: Mapped[str] = mapped_column(String, default="")
    tenant_type: Mapped[str | None] = mapped_column(String, nullable=True)
    provenance: Mapped[str] = mapped_column(
        String, default=TenantProvenance.UNKNOWN.value
    )
    status: Mapped[str] = mapped_column(String, default=TenantStatus.ACTIVE.value)
    industry: Mapped[str] = mapped_column(String, default="")
    website: Mapped[str] = mapped_column(String, default="")
    contact_email: Mapped[str] = mapped_column(String, default="")
    contact_phone: Mapped[str] = mapped_column(String, default="")
    country: Mapped[str] = mapped_column(String, default="")
    timezone: Mapped[str] = mapped_column(String, default="UTC")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="analyst")
    tenant_id: Mapped[str | None] = mapped_column(String, ForeignKey("tenants.id"), nullable=True)
    status: Mapped[str] = mapped_column(String, default=UserStatus.ACTIVE.value)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class TenantConfiguration(Base):
    __tablename__ = "tenant_configurations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String, ForeignKey("tenants.id"), unique=True, index=True
    )
    configuration: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("tenants.id"), nullable=True, index=True
    )
    dataset_source: Mapped[str | None] = mapped_column(String, default="TENANT", nullable=True, index=True)
    dataset_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    dataset_name: Mapped[str | None] = mapped_column(String, nullable=True)
    dataset_version: Mapped[str | None] = mapped_column(String, nullable=True)
    dataset_record_count: Mapped[int | None] = mapped_column(nullable=True)

    user_id: Mapped[str] = mapped_column(String)
    amount: Mapped[float] = mapped_column(Float)
    transaction_type: Mapped[str] = mapped_column(String, default="TRANSFER")
    device_id: Mapped[str] = mapped_column(String, default="")
    risk_score: Mapped[float] = mapped_column(Float)
    anomaly_score: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_coverage: Mapped[float | None] = mapped_column(Float, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    limitations: Mapped[str | None] = mapped_column(Text, nullable=True)
    governance_flags: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    normalization_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    mitre_techniques: Mapped[str | None] = mapped_column(String, nullable=True)
    nist_controls: Mapped[str | None] = mapped_column(String, nullable=True)
    analysis_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    risk_score_source: Mapped[str] = mapped_column(String, default="uploaded")
    anomaly_score_source: Mapped[str] = mapped_column(String, default="uploaded")
    model_version: Mapped[str | None] = mapped_column(String, nullable=True)

    # Recorded only after a human submits an STR to NFIU outside FinSecAI.
    str_filed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    str_reference: Mapped[str | None] = mapped_column(String, nullable=True)

    feedback: Mapped[list["Feedback"]] = relationship(back_populates="incident")


class EvidenceChunk(Base):
    __tablename__ = "evidence_chunks"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.id"), index=True)
    dataset_source: Mapped[str] = mapped_column(String, default="SHARED", index=True)
    dataset_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    source: Mapped[str] = mapped_column(String)
    framework_id: Mapped[str] = mapped_column(String, default="")
    text: Mapped[str] = mapped_column(Text)
    if _use_pgvector:
        embedding: Mapped[list[float] | None] = mapped_column(Vector(1536), nullable=True)
    else:
        embedding: Mapped[list[float] | None] = mapped_column(JSON, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    embedding_model: Mapped[str | None] = mapped_column(String, nullable=True)
    embedded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IncidentDataset(Base):
    """Immutable provenance record for a dataset used to create incidents."""

    __tablename__ = "incident_datasets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    source_type: Mapped[str] = mapped_column(String, index=True)
    name: Mapped[str] = mapped_column(String)
    version: Mapped[str] = mapped_column(String, default="1")
    record_count: Mapped[int] = mapped_column(default=0)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    original_filename: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Feedback(Base):
    __tablename__ = "feedback"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id"))
    analyst_email: Mapped[str] = mapped_column(String)
    label: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="feedback")


class ReportJob(Base):
    __tablename__ = "report_jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.id"), index=True)
    requested_by_user_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    incident_id: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    report_type: Mapped[str] = mapped_column(String, default="incident_pdf")
    status: Mapped[str] = mapped_column(String, default="queued", index=True)
    file_path: Mapped[str | None] = mapped_column(String, nullable=True)
    result_reference: Mapped[str | None] = mapped_column(String, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MLPredictionAudit(Base):
    __tablename__ = "ml_prediction_audit"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.id"), index=True)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id"), index=True)

    model_version: Mapped[str] = mapped_column(String, index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    anomaly_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    feature_values: Mapped[dict] = mapped_column(JSON)
    feature_contributions: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class SuspiciousTransactionReport(Base):
    """Tenant-scoped, human-authored STR workflow record."""

    __tablename__ = "suspicious_transaction_reports"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.id"), index=True)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id"), index=True)
    narrative: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String, default="draft", index=True)
    created_by_user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"))
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    submission_reference: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class AuditEvent(Base):
    """Append-only record of privileged and authorization-sensitive actions."""

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    actor_user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.id"), index=True)
    action: Mapped[str] = mapped_column(String, index=True)
    resource_type: Mapped[str] = mapped_column(String)
    resource_id: Mapped[str] = mapped_column(String)
    result: Mapped[str] = mapped_column(String, default="success")
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)


class DatasetVersion(Base):
    """Registry of what data trained what model."""

    __tablename__ = "dataset_versions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id: Mapped[str | None] = mapped_column(String, ForeignKey("tenants.id"), nullable=True, index=True)
    source_type: Mapped[str] = mapped_column(String, index=True)
    source_name: Mapped[str] = mapped_column(String)
    source_url: Mapped[str] = mapped_column(String, default="")
    can_be_production: Mapped[bool] = mapped_column(default=False)
    environment: Mapped[str] = mapped_column(String, default="research")
    record_count: Mapped[int] = mapped_column(default=0)
    positive_count: Mapped[int] = mapped_column(default=0)
    negative_count: Mapped[int] = mapped_column(default=0)
    schema_hash: Mapped[str] = mapped_column(String, default="")
    feature_version: Mapped[str] = mapped_column(String, default="v1")
    storage_path: Mapped[str] = mapped_column(String, default="")
    manifest: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_by: Mapped[str] = mapped_column(String, default="system")


class AuthoritativeLabel(Base):
    """Real supervised truth - separate from Feedback opinion."""

    __tablename__ = "authoritative_labels"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(String, ForeignKey("tenants.id"), index=True)
    incident_id: Mapped[str] = mapped_column(String, ForeignKey("incidents.id"), unique=True, index=True)
    label: Mapped[str] = mapped_column(String, index=True)
    label_source: Mapped[str] = mapped_column(String, default="manual_review")
    model_version_at_incident: Mapped[str] = mapped_column(String, index=True)
    feature_values: Mapped[dict] = mapped_column(JSON)
    feature_contributions: Mapped[list] = mapped_column(JSON, default=list)
    amount: Mapped[float] = mapped_column(Float)
    transaction_type: Mapped[str] = mapped_column(String, default="TRANSFER")
    labelled_by: Mapped[str] = mapped_column(String)
    labelled_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    incident: Mapped["Incident"] = relationship()


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    dataset_version_id: Mapped[str] = mapped_column(String, ForeignKey("dataset_versions.id"), index=True)
    feature_version: Mapped[str] = mapped_column(String, default="v1")
    training_code_sha: Mapped[str] = mapped_column(String, default="")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    artifact_hash: Mapped[str] = mapped_column(String, default="")
    artifact_path: Mapped[str] = mapped_column(String, default="")
    environment: Mapped[str] = mapped_column(String, default="research")
    production_type: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="experimental")
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    model_version_id: Mapped[str] = mapped_column(String, ForeignKey("model_versions.id"), index=True)
    dataset_version_id: Mapped[str] = mapped_column(String, ForeignKey("dataset_versions.id"), index=True)
    threshold: Mapped[float] = mapped_column(Float, default=0.5)
    sample_count: Mapped[int] = mapped_column(default=0)
    positive_count: Mapped[int] = mapped_column(default=0)
    negative_count: Mapped[int] = mapped_column(default=0)
    precision: Mapped[float] = mapped_column(Float, default=0.0)
    recall: Mapped[float] = mapped_column(Float, default=0.0)
    f1: Mapped[float] = mapped_column(Float, default=0.0)
    roc_auc: Mapped[float] = mapped_column(Float, default=0.0)
    pr_auc: Mapped[float] = mapped_column(Float, default=0.0)
    confusion_matrix: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String, default="passed")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

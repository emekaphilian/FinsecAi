import io
import logging
import math
import uuid
from datetime import datetime
from typing import Any, Literal

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.core.authorization import (
    INCIDENTS_INVESTIGATE,
    INCIDENTS_READ,
    USERS_MANAGE,
    apply_tenant_scope,
    require_permission,
    resolve_tenant_context,
)
from app.core.config import settings
from app.core.rate_limit import enforce_upload_rate_limit
from app.db.models import (
    AuditEvent,
    AuthoritativeLabel,
    DatasetVersion,
    EvidenceChunk,
    Feedback,
    Incident,
    IncidentDataset,
    MLPredictionAudit,
    ModelVersion,
    ReportJob,
    SuspiciousTransactionReport,
    Tenant,
    TenantConfiguration,
    TenantType,
    User,
)
from app.db.session import get_db
from app.ml.features import TransactionHistory, build_features_for_row
from app.schemas import FeedbackIn, IncidentOut
from app.services import intelligence_service
from app.services.evidence_ingestion import embed_evidence_chunks
from app.services.upload_normalization import normalize_upload_dataframe
from app.seed import default_demo_incidents, ensure_demo_dataset_record
from app.services.dataset_provenance import (
    DEMO, USER_TEST, TENANT as TENANT_DATASET, SHARED,
    filter_to_active_source,
)

router = APIRouter(prefix="/incidents", tags=["incidents"])

logger = logging.getLogger(__name__)
MAX_UPLOAD_ROWS = 50_000
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_STRING_FIELD_LEN = 256
MAX_REASONABLE_AMOUNT = 1_000_000_000


class AuthoritativeLabelIn(BaseModel):
    label: Literal["confirmed_fraud", "confirmed_legitimate", "inconclusive"]
    label_source: Literal["manual_review", "external_chargeback", "investigation"] = "manual_review"
    reason: str = ""


class PromoteModelIn(BaseModel):
    justification: str


class IngestEvidenceIn(BaseModel):
    source: str
    framework_id: str = Field(default="")
    text: str
    dataset_id: str | None = None


class EvidenceOut(BaseModel):
    evidence_id: str
    source: str
    framework_id: str
    text: str
    metadata_json: dict[str, Any] | None = None
    embedding_model: str | None = None
    embedded_at: str | None = None


def _demo_tenant_for_context(db: Session, user: User, tenant_id: str | None) -> Tenant:
    """Resolve a demo tenant; custom-data switching is never available to customers."""
    context = resolve_tenant_context(db, user, tenant_id)
    if context.is_global or not context.tenant_id:
        raise HTTPException(400, "Select a demo tenant to manage its test data.")
    tenant = db.query(Tenant).filter(Tenant.id == context.tenant_id).first()
    if tenant is None or tenant.tenant_type != TenantType.DEMO.value:
        raise HTTPException(403, "This action is only available in the demo workspace.")
    return tenant


def _set_demo_data_mode(db: Session, tenant_id: str, mode: str) -> None:
    config = db.query(TenantConfiguration).filter(TenantConfiguration.tenant_id == tenant_id).first()
    if config is None:
        config = TenantConfiguration(tenant_id=tenant_id, configuration={})
        db.add(config)
    configuration = dict(config.configuration or {})
    configuration["data_mode"] = mode
    config.configuration = configuration


def _incident_for_active_workspace(db: Session, incident_id: str, user: User) -> Incident | None:
    query = apply_tenant_scope(
        db.query(Incident).filter(Incident.id == incident_id), Incident, user
    )
    if user.tenant_id:
        query = filter_to_active_source(query, db, user.tenant_id)
    return query.first()


def _clear_demo_incident_data(db: Session, tenant_id: str) -> int:
    """Remove replaceable demo records and their dependent workflow artefacts."""
    incident_ids = [
        incident_id for (incident_id,) in db.query(Incident.id).filter(
            Incident.tenant_id == tenant_id,
            Incident.dataset_source.in_([DEMO, USER_TEST]),
        ).all()
    ]
    if not incident_ids:
        return 0
    db.query(AuthoritativeLabel).filter(AuthoritativeLabel.incident_id.in_(incident_ids)).delete(synchronize_session=False)
    db.query(SuspiciousTransactionReport).filter(SuspiciousTransactionReport.incident_id.in_(incident_ids)).delete(synchronize_session=False)
    db.query(MLPredictionAudit).filter(MLPredictionAudit.incident_id.in_(incident_ids)).delete(synchronize_session=False)
    db.query(Feedback).filter(Feedback.incident_id.in_(incident_ids)).delete(synchronize_session=False)
    db.query(ReportJob).filter(ReportJob.incident_id.in_(incident_ids)).delete(synchronize_session=False)
    return db.query(Incident).filter(
        Incident.tenant_id == tenant_id,
        Incident.dataset_source.in_([DEMO, USER_TEST]),
    ).delete(synchronize_session=False)


@router.get("/data-mode")
def demo_data_mode(
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_READ)),
):
    context = resolve_tenant_context(db, user, tenant_id)
    if context.is_global or not context.tenant_id:
        return {"is_demo_tenant": False, "mode": None}
    tenant = db.query(Tenant).filter(Tenant.id == context.tenant_id).first()
    if tenant is None or tenant.tenant_type != TenantType.DEMO.value:
        return {"is_demo_tenant": False, "mode": None}
    config = db.query(TenantConfiguration).filter(TenantConfiguration.tenant_id == tenant.id).first()
    return {
        "is_demo_tenant": True,
        "mode": (config.configuration or {}).get("data_mode", "demo_default") if config else "demo_default",
    }


@router.post("/use-own-data")
def use_own_demo_data(
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_INVESTIGATE)),
):
    tenant = _demo_tenant_for_context(db, user, tenant_id)
    deleted = _clear_demo_incident_data(db, tenant.id)
    _set_demo_data_mode(db, tenant.id, "user_data")
    db.commit()
    return {"deleted": deleted, "mode": "user_data"}


@router.post("/restore-demo-data")
def restore_demo_data(
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_INVESTIGATE)),
):
    tenant = _demo_tenant_for_context(db, user, tenant_id)
    deleted = _clear_demo_incident_data(db, tenant.id)
    db.add_all(default_demo_incidents(tenant.id))
    dataset = ensure_demo_dataset_record(db)
    dataset.record_count = 60
    _set_demo_data_mode(db, tenant.id, "demo_default")
    db.commit()
    return {"deleted": deleted, "restored": 60, "mode": "demo_default"}


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    risk_min: float = 0.0,
    risk_max: float = 1.0,
    limit: int = 100,
    offset: int = 0,
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_READ)),
):
    query = (
        db.query(Incident)
        .filter(Incident.risk_score >= risk_min, Incident.risk_score <= risk_max)
        .order_by(Incident.risk_score.desc())
    )
    context = resolve_tenant_context(db, user, tenant_id)
    q = apply_tenant_scope(query, Incident, user, context)
    if context.tenant_id:
        q = filter_to_active_source(q, db, context.tenant_id)
    return q.offset(offset).limit(limit).all()


@router.delete("/reset")
def reset_incidents(
    tenant_id: str | None = None,
    db: Session = Depends(get_db), user: User = Depends(require_permission(USERS_MANAGE))
):
    """Dev/test convenience only; production AML data must never be bulk-reset."""
    if settings.is_production:
        raise HTTPException(
            403,
            "DELETE /incidents/reset is disabled in production because AML records "
            "are subject to mandatory retention requirements.",
        )

    context = resolve_tenant_context(db, user, tenant_id)
    incident_ids = [
        incident_id
        for (incident_id,) in apply_tenant_scope(
            db.query(Incident.id), Incident, user, context
        ).all()
    ]
    if incident_ids:
        # Delete dependent records first: both tables hold Incident foreign keys.
        db.query(MLPredictionAudit).filter(MLPredictionAudit.incident_id.in_(incident_ids)).delete(
            synchronize_session=False
        )
        db.query(Feedback).filter(Feedback.incident_id.in_(incident_ids)).delete(
            synchronize_session=False
        )
    deleted = apply_tenant_scope(db.query(Incident), Incident, user, context).delete(
        synchronize_session=False
    )
    db.commit()
    return {"deleted": deleted}


@router.post("/analyze-batch")
async def analyze_batch(
    tenant_id: str | None = None,
    db: Session = Depends(get_db), user: User = Depends(require_permission(INCIDENTS_INVESTIGATE))
):
    """Populate dashboard fields without serial LLM calls for every upload row.

    Full semantic retrieval and narrative generation stay available for an
    analyst-selected incident via ``/{incident_id}/analyze``. Doing that for
    every row in a large upload can otherwise take hours.
    """
    context = resolve_tenant_context(db, user, tenant_id)
    incidents = apply_tenant_scope(db.query(Incident), Incident, user, context)
    if context.tenant_id:
        incidents = filter_to_active_source(incidents, db, context.tenant_id)
    incidents = [
        incident for incident in incidents.all()
        if not (incident.analysis_json or {}).get("data_provenance")
    ]
    for incident in incidents:
        result = await intelligence_service.analyze(
            db,
            incident.tenant_id,
            incident,
            evidence_override=[],
            allow_external_enrichment=False,
        )
        for key, value in result.items():
            setattr(incident, key, value)
    db.commit()
    return {"analyzed": len(incidents), "analysis_mode": "fast_rule_based"}


@router.get("/{incident_id}/mapping-explanation")
def get_mapping_explanation(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_READ)),
):
    incident = _incident_for_active_workspace(db, incident_id, user)
    if not incident:
        raise HTTPException(404, "Incident not found")
    analysis = incident.analysis_json or {}
    if not analysis:
        raise HTTPException(
            409,
            "Framework mappings are available only after investigation analysis has been persisted.",
        )
    # This endpoint is a read model of the persisted investigation. Do not
    # recreate mappings from the incident risk score for display consumers.
    return {
        "mitre": [
            item for item in (analysis.get("mitre") or [])
            if item.get("status") == "evidence_backed" and item.get("supporting_evidence")
        ],
        "nist": [
            item for item in (analysis.get("nist") or [])
            if item.get("status") == "evidence_backed" and item.get("supporting_evidence")
        ],
        "rationale": analysis.get("risk_rationale") or [],
    }


@router.get("/{incident_id}/evidence")
def get_incident_evidence(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_READ)),
):
    incident = _incident_for_active_workspace(db, incident_id, user)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return {"evidence": intelligence_service.retrieve_evidence(db, incident.tenant_id, incident)}


@router.post("/evidence", response_model=EvidenceOut)
def ingest_evidence(
    payload: IngestEvidenceIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_INVESTIGATE)),
):
    context = resolve_tenant_context(db, user)
    dataset = None
    if payload.dataset_id:
        dataset_query = db.query(IncidentDataset).filter(IncidentDataset.id == payload.dataset_id)
        if context.tenant_id:
            dataset_query = dataset_query.filter(or_(
                IncidentDataset.tenant_id == context.tenant_id,
                IncidentDataset.tenant_id.is_(None),
            ))
        dataset = dataset_query.first()
        if dataset is None:
            raise HTTPException(404, "Dataset not found")
    evidence_tenant_id = context.tenant_id or (dataset.tenant_id if dataset else None)
    if not evidence_tenant_id:
        raise HTTPException(400, "Select a tenant before adding evidence.")
    chunk = EvidenceChunk(
        tenant_id=evidence_tenant_id,
        dataset_source=dataset.source_type if dataset else SHARED,
        dataset_id=dataset.id if dataset else None,
        source=payload.source,
        framework_id=payload.framework_id,
        text=payload.text,
    )
    db.add(chunk)
    embedded_count = embed_evidence_chunks(db, [chunk])
    db.commit()
    return EvidenceOut(
        evidence_id=str(chunk.id),
        source=chunk.source,
        framework_id=chunk.framework_id,
        text=chunk.text,
        metadata_json=chunk.metadata_json,
        embedding_model=chunk.embedding_model,
        embedded_at=chunk.embedded_at.isoformat() if chunk.embedded_at else None,
    )


@router.get("/{incident_id}/prediction-audit")
def get_prediction_audit(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_READ)),
):
    incident = _incident_for_active_workspace(db, incident_id, user)
    if not incident:
        raise HTTPException(404, "Incident not found")
    audit = (
        apply_tenant_scope(
            db.query(MLPredictionAudit).filter(MLPredictionAudit.incident_id == incident_id),
            MLPredictionAudit,
            user,
        )
        .order_by(MLPredictionAudit.created_at.desc())
        .first()
    )
    if not audit:
        return {
            "has_audit_record": False,
            "reason": "risk_score/anomaly_score were supplied in the upload, not model-computed.",
        }
    return {
        "has_audit_record": True,
        "model_version": audit.model_version,
        "risk_score": audit.risk_score,
        "anomaly_score": audit.anomaly_score,
        "confidence": audit.confidence,
        "feature_values": audit.feature_values,
        "feature_contributions": audit.feature_contributions,
        "created_at": audit.created_at.isoformat(),
    }


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_READ)),
):
    incident = _incident_for_active_workspace(db, incident_id, user)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


def _read_upload_file(filename: str, raw: bytes) -> pd.DataFrame:
    name = (filename or "").lower()
    if name.endswith((".xlsx", ".xls")):
        return pd.read_excel(io.BytesIO(raw))
    if name.endswith(".json"):
        return pd.read_json(io.BytesIO(raw))
    return pd.read_csv(io.BytesIO(raw))


def _get_risk_model_or_none():
    try:
        from app.ml.risk_model import get_risk_model

        return get_risk_model()
    except (FileNotFoundError, ImportError):
        logger.warning(
            "No trained risk model found; upload_incidents will require risk_score/anomaly_score columns in uploaded files."
        )
        return None


def _validate_row(row: pd.Series, scores_supplied: bool) -> tuple[dict | None, str | None]:
    """Return safely bounded row values, or a reason to skip the row."""
    try:
        user_id = str(row["user_id"]).strip()
        amount = float(row["amount"])
    except (TypeError, ValueError):
        return None, "user_id or amount could not be parsed"
    if not user_id or len(user_id) > MAX_STRING_FIELD_LEN:
        return None, "user_id is empty or too long"
    if not math.isfinite(amount) or amount < 0 or amount > MAX_REASONABLE_AMOUNT:
        return None, "amount is not within the accepted range"

    cleaned = {
        "user_id": user_id,
        "amount": amount,
        "transaction_type": str(row.get("transaction_type", "TRANSFER"))[:MAX_STRING_FIELD_LEN],
        "device_id": str(row.get("device_id", ""))[:MAX_STRING_FIELD_LEN],
    }
    if scores_supplied:
        try:
            risk_score = float(row["risk_score"])
            anomaly_score = float(row["anomaly_score"])
        except (TypeError, ValueError):
            return None, "supplied scores could not be parsed"
        if not all(
            math.isfinite(score) and 0 <= score <= 1 for score in (risk_score, anomaly_score)
        ):
            return None, "supplied scores must be finite values from 0 to 1"
        cleaned.update(risk_score=risk_score, anomaly_score=anomaly_score)
    return cleaned, None


def _score_incidents_with_model(frame: pd.DataFrame, risk_model, device_history) -> pd.DataFrame:
    scored_frame = frame.copy()
    scored_frame["risk_score"] = None
    scored_frame["anomaly_score"] = None
    scored_frame["_model_prediction"] = None
    scored_frame["_feature_values"] = None

    for idx, row in scored_frame.iterrows():
        user_id = str(row["user_id"])
        amount = float(row["amount"])
        transaction_type = str(row.get("transaction_type", "TRANSFER"))
        device_id = str(row.get("device_id", ""))
        vector, feature_values = build_features_for_row(
            device_history, user_id, amount, transaction_type, device_id
        )
        prediction = risk_model.predict(vector)
        device_history.observe(device_id, user_id, amount)
        scored_frame.at[idx, "risk_score"] = prediction.risk_score
        scored_frame.at[idx, "anomaly_score"] = prediction.anomaly_score
        scored_frame.at[idx, "_model_prediction"] = prediction
        scored_frame.at[idx, "_feature_values"] = feature_values

    return scored_frame


@router.post("/upload")
async def upload_incidents(
    file: UploadFile,
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_INVESTIGATE)),
):
    enforce_upload_rate_limit(user.id)
    if file.size is not None and file.size > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Upload exceeds the {MAX_UPLOAD_BYTES // 1_048_576} MB limit.")
    raw = await file.read()
    filename = file.filename or ""

    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Upload exceeds the {MAX_UPLOAD_BYTES // 1_048_576} MB limit.")

    try:
        df = _read_upload_file(filename, raw)
    except Exception as exc:
        raise HTTPException(
            400,
            f"Unable to parse uploaded file: {filename}. Supported formats are CSV, Excel, and JSON.",
        ) from exc

    if len(df) > MAX_UPLOAD_ROWS:
        raise HTTPException(413, f"Upload exceeds the {MAX_UPLOAD_ROWS:,}-row limit.")

    normalized_df, column_map = normalize_upload_dataframe(df)
    required = {"user_id", "amount"}
    missing = required - set(normalized_df.columns)
    if missing:
        raise HTTPException(400, f"Uploaded file missing required columns: {sorted(missing)}")

    scores_supplied = {"risk_score", "anomaly_score"}.issubset(normalized_df.columns)
    risk_model = None if scores_supplied else _get_risk_model_or_none()
    if not scores_supplied and risk_model is None:
        raise HTTPException(
            400,
            "Uploaded file is missing risk_score/anomaly_score, and no trained classifier is available to compute them. Either include those columns in the upload, or train a model first (`python -m app.ml.train`).",
        )

    context = resolve_tenant_context(db, user, tenant_id)
    if context.is_global or not context.tenant_id:
        raise HTTPException(400, "A tenant_id is required when a platform owner uploads incidents.")
    target_tenant_id = context.tenant_id
    target_tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id).first()
    dataset_source = (
        USER_TEST
        if target_tenant and target_tenant.tenant_type == TenantType.DEMO.value
        else TENANT_DATASET
    )
    dataset_id = str(uuid.uuid4())
    dataset_name = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] or "Uploaded dataset"
    dataset = IncidentDataset(
        id=dataset_id,
        tenant_id=target_tenant_id,
        source_type=dataset_source,
        name=dataset_name,
        version="1",
        record_count=0,
        synthetic=False,
        original_filename=dataset_name,
    )
    db.add(dataset)
    db.flush()
    transaction_history = TransactionHistory(db, target_tenant_id) if risk_model else None
    existing = {
        (i.user_id, round(i.amount, 2), round(i.risk_score, 3), round(i.anomaly_score, 3))
        for i in db.query(Incident).filter(
            Incident.tenant_id == target_tenant_id,
            Incident.dataset_source == dataset_source,
        ).all()
    }

    created, skipped, invalid = 0, 0, 0
    created_incidents: list[Incident] = []
    for _, row in normalized_df.iterrows():
        cleaned, reason = _validate_row(row, scores_supplied)
        if reason:
            invalid += 1
            logger.info("Skipping invalid upload row for tenant %s: %s", user.tenant_id, reason)
            continue
        user_id = cleaned["user_id"]
        amount = cleaned["amount"]
        transaction_type = cleaned["transaction_type"]
        device_id = cleaned["device_id"]
        if scores_supplied:
            risk_score = cleaned["risk_score"]
            anomaly_score = cleaned["anomaly_score"]
            model_prediction = None
            feature_values = None
        else:
            vector, feature_values = build_features_for_row(
                transaction_history, user_id, amount, transaction_type, device_id
            )
            model_prediction = risk_model.predict(vector)
            transaction_history.observe(device_id, user_id, amount)
            risk_score = model_prediction.risk_score
            anomaly_score = model_prediction.anomaly_score

        key = (user_id, round(amount, 2), round(risk_score, 3), round(anomaly_score, 3))
        if key in existing:
            skipped += 1
            continue

        incident = Incident(
            tenant_id=target_tenant_id,
            user_id=user_id,
            amount=amount,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            transaction_type=transaction_type,
            device_id=device_id,
            raw_payload=row.get("_raw_row") or {},
            dataset_source=dataset_source,
            dataset_id=dataset_id,
            dataset_name=dataset_name,
            dataset_version="1",
            dataset_record_count=0,
            normalization_metadata={
                "column_map": column_map,
                "normalized_columns": list(normalized_df.columns),
            },
            risk_score_source="uploaded" if scores_supplied else "model",
            anomaly_score_source="uploaded" if scores_supplied else "model",
            model_version=(
                model_prediction.model_version if model_prediction is not None else None
            ),
        )
        db.add(incident)
        created_incidents.append(incident)
        if model_prediction is not None:
            db.flush()
            db.add(
                MLPredictionAudit(
                    tenant_id=target_tenant_id,
                    incident_id=incident.id,
                    model_version=model_prediction.model_version,
                    risk_score=model_prediction.risk_score,
                    anomaly_score=model_prediction.anomaly_score,
                    confidence=model_prediction.confidence,
                    feature_values=feature_values or {},
                    feature_contributions=model_prediction.feature_contributions,
                )
            )
        existing.add(key)
        created += 1
    dataset.record_count = created
    for incident in created_incidents:
        incident.dataset_record_count = created
    if target_tenant and target_tenant.tenant_type == TenantType.DEMO.value:
        _set_demo_data_mode(db, target_tenant_id, "user_data")
    db.commit()
    return {
        "created": created,
        "skipped_duplicates": skipped,
        "skipped_invalid": invalid,
        "scored_by_model": risk_model is not None,
        "dataset_id": dataset_id,
        "dataset_source": dataset_source,
        "dataset_name": dataset_name,
    }


@router.post("/{incident_id}/analyze", response_model=IncidentOut)
async def analyze_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_INVESTIGATE)),
):
    incident = _incident_for_active_workspace(db, incident_id, user)
    if not incident:
        raise HTTPException(404, "Incident not found")

    result = await intelligence_service.analyze(db, incident.tenant_id, incident)
    for key, value in result.items():
        setattr(incident, key, value)
    db.add(
        AuditEvent(
            actor_user_id=user.id,
            tenant_id=incident.tenant_id,
            action="incident.analyzed",
            resource_type="incident",
            resource_id=incident.id,
            metadata_json={"actor_role": user.role, "access_mode": "owner_workspace" if user.role == "owner" else "tenant"},
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.post("/{incident_id}/authoritative-label")
def submit_authoritative_label(
    incident_id: str,
    payload: AuthoritativeLabelIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_INVESTIGATE)),
):
    """Record the real ground truth for an incident, separate from analyst opinion."""
    incident = _incident_for_active_workspace(db, incident_id, user)
    if not incident:
        raise HTTPException(404, "Incident not found")

    audit = (
        apply_tenant_scope(
            db.query(MLPredictionAudit).filter(MLPredictionAudit.incident_id == incident_id),
            MLPredictionAudit,
            user,
        )
        .order_by(MLPredictionAudit.created_at.desc())
        .first()
    )
    if not audit:
        raise HTTPException(
            400,
            "Cannot create authoritative label: no MLPredictionAudit. This incident was uploaded with manual scores, not model-scored.",
        )

    existing = (
        db.query(AuthoritativeLabel)
        .filter(
            AuthoritativeLabel.incident_id == incident_id,
            AuthoritativeLabel.tenant_id == incident.tenant_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(409, f"Already labelled as {existing.label} by {existing.labelled_by}.")

    label = AuthoritativeLabel(
        tenant_id=incident.tenant_id,
        incident_id=incident.id,
        label=payload.label,
        label_source=payload.label_source,
        model_version_at_incident=audit.model_version,
        feature_values=audit.feature_values,
        feature_contributions=audit.feature_contributions,
        amount=incident.amount,
        transaction_type=incident.transaction_type,
        labelled_by=user.email,
    )
    db.add(label)
    db.add(
        AuditEvent(
            actor_user_id=user.id,
            tenant_id=incident.tenant_id,
            action="authoritative_label.created",
            resource_type="incident",
            resource_id=incident_id,
            metadata_json={
                "label": payload.label,
                "model_version_at_incident": audit.model_version,
                "reason": payload.reason,
                "actor_role": user.role,
                "access_mode": "owner_workspace" if user.role == "owner" else "tenant",
            },
        )
    )
    db.commit()

    real_count = (
        db.query(AuthoritativeLabel)
        .filter(
            AuthoritativeLabel.tenant_id == incident.tenant_id,
            AuthoritativeLabel.label.in_(["confirmed_fraud", "confirmed_legitimate"]),
        )
        .count()
    )
    fraud_count = (
        db.query(AuthoritativeLabel)
        .filter(
            AuthoritativeLabel.tenant_id == incident.tenant_id,
            AuthoritativeLabel.label == "confirmed_fraud",
        )
        .count()
    )
    return {
        "status": "recorded",
        "incident_id": incident_id,
        "label": payload.label,
        "real_dataset_progress": {
            "total": real_count,
            "fraud": fraud_count,
            "ready_for_retrain": (
                real_count >= settings.model_min_label_count
                and fraud_count >= settings.model_min_fraud_label_count
            ),
        },
    }


@router.put("/{incident_id}/authoritative-label")
def override_authoritative_label(
    incident_id: str,
    payload: AuthoritativeLabelIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(USERS_MANAGE)),
):
    """Allow managers to override recorded ground truth."""
    q = db.query(AuthoritativeLabel).filter(AuthoritativeLabel.incident_id == incident_id)
    q = apply_tenant_scope(q, AuthoritativeLabel, user)
    existing = q.first()
    if not existing:
        raise HTTPException(404, "No authoritative label to override")

    existing.label = payload.label
    existing.label_source = payload.label_source
    existing.labelled_by = user.email
    existing.labelled_at = datetime.utcnow()
    db.add(
        AuditEvent(
            actor_user_id=user.id,
            tenant_id=existing.tenant_id,
            action="authoritative_label.overridden",
            resource_type="incident",
            resource_id=incident_id,
            metadata_json={"new_label": payload.label, "reason": payload.reason, "actor_role": user.role, "access_mode": "owner_workspace" if user.role == "owner" else "tenant"},
        )
    )
    db.commit()
    return {"status": "overridden", "label": payload.label}


@router.get("/{incident_id}/authoritative-label")
def get_authoritative_label(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_READ)),
):
    label = apply_tenant_scope(
        db.query(AuthoritativeLabel).filter(AuthoritativeLabel.incident_id == incident_id),
        AuthoritativeLabel,
        user,
    ).first()
    if not label:
        return {"has_label": False}
    return {
        "has_label": True,
        "label": label.label,
        "label_source": label.label_source,
        "model_version_at_incident": label.model_version_at_incident,
        "labelled_by": label.labelled_by,
        "labelled_at": label.labelled_at.isoformat(),
        "feature_values": label.feature_values,
    }


@router.post("/{incident_id}/feedback")
def submit_feedback(
    incident_id: str,
    payload: FeedbackIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(INCIDENTS_INVESTIGATE)),
):
    incident = _incident_for_active_workspace(db, incident_id, user)
    if not incident:
        raise HTTPException(404, "Incident not found")

    db.add(Feedback(incident_id=incident.id, analyst_email=user.email, label=payload.label))
    db.add(
        AuditEvent(
            actor_user_id=user.id,
            tenant_id=incident.tenant_id,
            action="feedback.created",
            resource_type="incident",
            resource_id=incident_id,
            metadata_json={"label": payload.label, "actor_role": user.role, "access_mode": "owner_workspace" if user.role == "owner" else "tenant"},
        )
    )
    db.commit()
    return {"status": "recorded"}

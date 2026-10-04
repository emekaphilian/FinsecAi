import random

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.authorization import (
    TENANTS_MANAGE,
    apply_enterprise_scope,
    apply_tenant_scope,
    is_platform_owner,
    require_permission,
    resolve_tenant_context,
)
from app.db.models import (
    AuthoritativeLabel,
    Incident,
    ReportJob,
    Tenant,
    TenantProvenance,
    TenantStatus,
    TenantType,
    User,
)
from app.db.session import get_db
from app.schemas import AnalyticsSummary, EnterpriseSummary
from app.services import evaluation_service
from app.services.dataset_provenance import filter_to_active_source

router = APIRouter(prefix="/analytics", tags=["analytics"])


def _tenant_incidents(
    db: Session,
    user: User,
    tenant_id: str | None = None,
    *,
    max_rows: int | None = None,
) -> list[Incident]:
    context = resolve_tenant_context(db, user, tenant_id)
    query = apply_tenant_scope(db.query(Incident), Incident, user, context)
    if context.tenant_id:
        query = filter_to_active_source(query, db, context.tenant_id)
    if max_rows is not None:
        query = query.order_by(Incident.created_at.desc()).limit(max_rows)
    return query.all()


def _tenant_incident_query(db: Session, user: User, tenant_id: str | None = None):
    """Return the active dataset query without materialising its rows."""
    context = resolve_tenant_context(db, user, tenant_id)
    query = apply_tenant_scope(db.query(Incident), Incident, user, context)
    if context.tenant_id:
        query = filter_to_active_source(query, db, context.tenant_id)
    return query


@router.get("/summary", response_model=AnalyticsSummary)
def summary(
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = _tenant_incident_query(db, user, tenant_id)
    total, avg_risk, analyzed_count, avg_confidence, high_risk_count, flagged_count = (
        query.with_entities(
            func.count(Incident.id),
            func.avg(Incident.risk_score),
            func.count(Incident.confidence),
            func.avg(Incident.confidence),
            func.coalesce(func.sum(case((Incident.risk_score > 0.7, 1), else_=0)), 0),
            func.coalesce(
                func.sum(
                    case(
                        (
                            Incident.governance_flags.is_not(None)
                            & (Incident.governance_flags != ""),
                            1,
                        ),
                        else_=0,
                    )
                ),
                0,
            ),
        ).one()
    )

    return AnalyticsSummary(
        total_incidents=total,
        analyzed_count=analyzed_count,
        avg_risk=round(float(avg_risk or 0), 3),
        avg_confidence=round(float(avg_confidence or 0), 3),
        high_risk_count=int(high_risk_count),
        governance_flags_count=int(flagged_count),
    )


@router.get("/enterprise-summary", response_model=EnterpriseSummary)
def enterprise_summary(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(TENANTS_MANAGE)),
):
    """Return platform metrics; historical non-customer rows are never reclassified."""
    if not is_platform_owner(user):
        raise HTTPException(status_code=403, detail="Platform owner required")

    legitimate_provenance = (
        TenantProvenance.LEGITIMATE_DEMO.value,
        TenantProvenance.LEGITIMATE_CUSTOMER.value,
    )

    return EnterpriseSummary(
        total_tenants=db.query(Tenant.id).filter(Tenant.provenance.in_(legitimate_provenance)).count(),
        active_customer_tenants=(
            db.query(Tenant.id)
            .filter(
                Tenant.tenant_type == TenantType.CUSTOMER.value,
                Tenant.provenance == TenantProvenance.LEGITIMATE_CUSTOMER.value,
                Tenant.status == TenantStatus.ACTIVE.value,
            )
            .count()
        ),
        demo_tenants=db.query(Tenant.id).filter(
            Tenant.tenant_type == TenantType.DEMO.value,
            Tenant.provenance == TenantProvenance.LEGITIMATE_DEMO.value,
        ).count(),
        total_incidents=apply_enterprise_scope(db.query(Incident.id), Incident).count(),
        high_risk_incidents=apply_enterprise_scope(
            db.query(Incident.id).filter(Incident.risk_score > 0.7), Incident
        ).count(),
        reports_generated=apply_enterprise_scope(
            db.query(ReportJob.id).filter(ReportJob.status == "completed"), ReportJob
        ).count(),
    )


@router.get("/precision-recall")
def precision_recall(
    threshold: float = 0.5,
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    incidents = _tenant_incidents(db, user, tenant_id, max_rows=10_000)

    incident_ids = [incident.id for incident in incidents]
    tenant_ids = {incident.tenant_id for incident in incidents if incident.tenant_id}
    labels = (
        db.query(AuthoritativeLabel)
        .filter(
            AuthoritativeLabel.incident_id.in_(incident_ids),
            AuthoritativeLabel.tenant_id.in_(tenant_ids),
            AuthoritativeLabel.label.in_(
                ["confirmed_fraud", "confirmed_legitimate"]
            ),
        )
        .all()
        if incident_ids and tenant_ids
        else []
    )
    labels_by_incident = {label.incident_id: label for label in labels}
    labelled_incidents = [
        incident for incident in incidents if incident.id in labels_by_incident
    ]

    if labelled_incidents:
        y_true = [
            1 if labels_by_incident[incident.id].label == "confirmed_fraud" else 0
            for incident in labelled_incidents
        ]
        y_pred = evaluation_service.predict_labels(
            [incident.risk_score for incident in labelled_incidents],
            threshold,
        )
        metrics = evaluation_service.evaluate_classification(y_true, y_pred)
        metrics.update(
            {
                "evaluation_mode": "validated",
                "ground_truth_source": "authoritative_labels",
                "evaluated_count": len(labelled_incidents),
                "total_incidents": len(incidents),
                "label_coverage": round(len(labelled_incidents) / len(incidents), 3)
                if incidents
                else 0.0,
                "evaluation_note": (
                    "Validated model performance using authoritative incident "
                    "outcomes. Unlabelled incidents are excluded."
                ),
            }
        )
        return metrics

    # No authoritative outcomes exist yet. Preserve the deterministic
    # synthetic evaluation as a pipeline-health indicator, not accuracy.
    random.seed(42)
    y_true = [random.randint(0, 1) for _ in incidents]
    y_pred = evaluation_service.predict_labels(
        [incident.risk_score for incident in incidents],
        threshold,
    )
    metrics = evaluation_service.evaluate_classification(y_true, y_pred)
    metrics.update(
        {
            "evaluation_mode": "synthetic",
            "ground_truth_source": "synthetic_seeded",
            "evaluated_count": len(incidents),
            "total_incidents": len(incidents),
            "label_coverage": 0.0,
            "evaluation_note": (
                "Synthetic ground truth is used because no authoritative "
                "incident outcomes are available. Treat these metrics as "
                "pipeline-health checks, not validated production accuracy."
            ),
        }
    )
    return metrics


@router.get("/fairness")
def fairness(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incidents = _tenant_incidents(db, user, tenant_id, max_rows=10_000)
    y_pred = evaluation_service.predict_labels([i.risk_score for i in incidents])
    return evaluation_service.fairness_by_segment([i.amount for i in incidents], y_pred)


@router.get("/drift")
def drift(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incidents = sorted(_tenant_incidents(db, user, tenant_id, max_rows=10_000), key=lambda i: i.created_at)
    y_pred = evaluation_service.predict_labels([i.risk_score for i in incidents])
    mid = len(y_pred) // 2
    return evaluation_service.compute_drift(y_pred[:mid], y_pred[mid:])


@router.get("/calibration")
def calibration(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incidents = [i for i in _tenant_incidents(db, user, tenant_id, max_rows=10_000) if i.confidence is not None]
    random.seed(42)
    y_true = [random.randint(0, 1) for _ in incidents]
    return evaluation_service.calibration_curve(y_true, [i.confidence for i in incidents])


@router.get("/governance")
def governance(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incidents = _tenant_incidents(db, user, tenant_id, max_rows=10_000)
    flag_lists = [i.governance_flags.split(", ") if i.governance_flags else [] for i in incidents]
    return evaluation_service.governance_compliance(flag_lists)


@router.get("/flag-breakdown")
def flag_breakdown(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    counts: dict[str, int] = {}
    flag_rows = (
        _tenant_incident_query(db, user, tenant_id)
        .filter(Incident.governance_flags.is_not(None), Incident.governance_flags != "")
        .with_entities(Incident.governance_flags, func.count(Incident.id))
        .group_by(Incident.governance_flags)
        .all()
    )
    for flags, count in flag_rows:
        if not flags:
            continue
        for flag in flags.split(", "):
            flag = flag.strip()
            if flag:
                counts[flag] = counts.get(flag, 0) + count
    return counts

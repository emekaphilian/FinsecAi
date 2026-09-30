import random

from fastapi import APIRouter, Depends, HTTPException
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
from app.db.models import Incident, ReportJob, Tenant, TenantProvenance, TenantStatus, TenantType, User
from app.db.session import get_db
from app.schemas import AnalyticsSummary, EnterpriseSummary
from app.services import evaluation_service
from app.services.dataset_provenance import filter_to_active_source

router = APIRouter(prefix="/analytics", tags=["analytics"])


def _tenant_incidents(db: Session, user: User, tenant_id: str | None = None) -> list[Incident]:
    context = resolve_tenant_context(db, user, tenant_id)
    query = apply_tenant_scope(db.query(Incident), Incident, user, context)
    if context.tenant_id:
        query = filter_to_active_source(query, db, context.tenant_id)
    return query.all()


@router.get("/summary", response_model=AnalyticsSummary)
def summary(
    tenant_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    incidents = _tenant_incidents(db, user, tenant_id)
    analyzed = [i for i in incidents if i.confidence is not None]

    return AnalyticsSummary(
        total_incidents=len(incidents),
        analyzed_count=len(analyzed),
        avg_risk=round(sum(i.risk_score for i in incidents) / len(incidents), 3)
        if incidents
        else 0.0,
        avg_confidence=round(sum(i.confidence for i in analyzed) / len(analyzed), 3)
        if analyzed
        else 0.0,
        high_risk_count=sum(1 for i in incidents if i.risk_score > 0.7),
        governance_flags_count=sum(1 for i in incidents if i.governance_flags),
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
    incidents = _tenant_incidents(db, user, tenant_id)
    # NOTE: ground truth is synthetic pending real analyst-labeled outcomes — flagged in the UI.
    random.seed(42)
    y_true = [random.randint(0, 1) for _ in incidents]
    y_pred = evaluation_service.predict_labels([i.risk_score for i in incidents], threshold)
    return evaluation_service.evaluate_classification(y_true, y_pred)


@router.get("/fairness")
def fairness(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incidents = _tenant_incidents(db, user, tenant_id)
    y_pred = evaluation_service.predict_labels([i.risk_score for i in incidents])
    return evaluation_service.fairness_by_segment([i.amount for i in incidents], y_pred)


@router.get("/drift")
def drift(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incidents = sorted(_tenant_incidents(db, user, tenant_id), key=lambda i: i.created_at)
    y_pred = evaluation_service.predict_labels([i.risk_score for i in incidents])
    mid = len(y_pred) // 2
    return evaluation_service.compute_drift(y_pred[:mid], y_pred[mid:])


@router.get("/calibration")
def calibration(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incidents = [i for i in _tenant_incidents(db, user, tenant_id) if i.confidence is not None]
    random.seed(42)
    y_true = [random.randint(0, 1) for _ in incidents]
    return evaluation_service.calibration_curve(y_true, [i.confidence for i in incidents])


@router.get("/governance")
def governance(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incidents = _tenant_incidents(db, user, tenant_id)
    flag_lists = [i.governance_flags.split(", ") if i.governance_flags else [] for i in incidents]
    return evaluation_service.governance_compliance(flag_lists)


@router.get("/flag-breakdown")
def flag_breakdown(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    incidents = _tenant_incidents(db, user, tenant_id)
    counts: dict[str, int] = {}
    for incident in incidents:
        if not incident.governance_flags:
            continue
        for flag in incident.governance_flags.split(", "):
            flag = flag.strip()
            if flag:
                counts[flag] = counts.get(flag, 0) + 1
    return counts

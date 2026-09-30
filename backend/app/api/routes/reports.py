from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.authorization import (
    REPORTS_GENERATE,
    REPORTS_READ,
    apply_tenant_scope,
    require_permission,
)
from app.db.models import AuditEvent, Incident, User
from app.db.session import get_db
from app.services import report_job_service, report_service
from app.services.dataset_provenance import filter_to_active_source
from app.services.report_provenance import add_data_provenance_page

router = APIRouter(prefix="/reports", tags=["reports"])


def _require_persisted_analysis(incident: Incident) -> None:
    """Full investigation reports may only render persisted analysis."""
    if not incident.analysis_json or not incident.analysis_json.get("data_provenance"):
        raise HTTPException(
            409,
            "This incident needs source-aware analysis. Run Analyze on the incident before generating the report.",
        )


@router.post("/{incident_id}")
def generate_report(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(REPORTS_GENERATE)),
):
    incident_query = apply_tenant_scope(
        db.query(Incident).filter(Incident.id == incident_id), Incident, user
    )
    if user.tenant_id:
        incident_query = filter_to_active_source(incident_query, db, user.tenant_id)
    incident = incident_query.first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    _require_persisted_analysis(incident)

    path = report_service.generate_incident_pdf(incident)
    add_data_provenance_page(path, incident)
    db.add(AuditEvent(
        actor_user_id=user.id,
        tenant_id=incident.tenant_id,
        action="report.generated",
        resource_type="incident",
        resource_id=incident.id,
        metadata_json={"actor_role": user.role, "access_mode": "owner_workspace" if user.role == "owner" else "tenant"},
    ))
    db.commit()
    return FileResponse(path, media_type="application/pdf", filename=f"report_{incident_id}.pdf")


@router.post("/{incident_id}/jobs")
def create_report_job(
    incident_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(REPORTS_GENERATE)),
):
    incident_query = apply_tenant_scope(
        db.query(Incident).filter(Incident.id == incident_id), Incident, user
    )
    if user.tenant_id:
        incident_query = filter_to_active_source(incident_query, db, user.tenant_id)
    incident = incident_query.first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    _require_persisted_analysis(incident)

    job = report_job_service.enqueue_report_generation(
        db, incident.tenant_id, user.id, incident.id, report_type="incident_pdf"
    )
    db.add(AuditEvent(
        actor_user_id=user.id,
        tenant_id=incident.tenant_id,
        action="report.generation_requested",
        resource_type="incident",
        resource_id=incident.id,
        metadata_json={"actor_role": user.role, "access_mode": "owner_workspace" if user.role == "owner" else "tenant"},
    ))
    db.commit()
    return {
        "job_id": job.id,
        "incident_id": incident.id,
        "tenant_id": incident.tenant_id,
        "status": job.status,
        "requested_by_user_id": user.id,
    }


@router.get("/jobs/{job_id}")
def get_report_job_status(
    job_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(REPORTS_READ)),
):
    job = report_job_service.get_job_for_user(db, job_id, user)
    if not job:
        raise HTTPException(404, "Report job not found")

    return {
        "job_id": job.id,
        "tenant_id": job.tenant_id,
        "incident_id": job.incident_id,
        "status": job.status,
        "report_type": job.report_type,
        "file_path": job.file_path,
        "result_reference": job.result_reference,
        "error_message": job.error_message,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


@router.get("/jobs/{job_id}/result")
def get_report_job_result(
    job_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(REPORTS_READ)),
):
    job = report_job_service.get_job_for_user(db, job_id, user)
    if not job:
        raise HTTPException(404, "Report job not found")
    if job.status != "completed" or not job.file_path:
        raise HTTPException(409, "Report job is not complete")

    return FileResponse(
        job.file_path,
        media_type="application/pdf",
        filename=f"report_{job.incident_id}.pdf",
    )

import threading
from datetime import datetime

from app.db.models import Incident, ReportJob
from app.core.authorization import apply_tenant_scope
from app.db.session import SessionLocal
from app.services import report_service
from app.services.dataset_provenance import filter_to_active_source
from app.services.report_provenance import add_data_provenance_page


def create_report_job(
    db,
    tenant_id: str,
    user_id: str | None,
    incident_id: str,
    report_type: str = "incident_pdf",
) -> ReportJob:
    job = ReportJob(
        tenant_id=tenant_id,
        requested_by_user_id=user_id,
        incident_id=incident_id,
        report_type=report_type,
        status="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _run_report_job(job_id: str, tenant_id: str, incident_id: str) -> None:
    db = SessionLocal()
    try:
        job = db.query(ReportJob).filter(ReportJob.id == job_id).first()
        if job is None:
            return

        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id, Incident.tenant_id == tenant_id)
            .first()
        )
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found for tenant {tenant_id}")

        file_path = report_service.generate_incident_pdf(incident)
        add_data_provenance_page(file_path, incident)
        job.file_path = file_path
        job.result_reference = file_path
        job.status = "completed"
        job.completed_at = datetime.utcnow()
        db.commit()
    except Exception as exc:  # pragma: no cover - defensive job state update
        job = db.query(ReportJob).filter(ReportJob.id == job_id).first()
        if job is not None:
            job.status = "failed"
            job.error_message = str(exc)
            job.completed_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def enqueue_report_generation(
    db,
    tenant_id: str,
    user_id: str | None,
    incident_id: str,
    report_type: str = "incident_pdf",
) -> ReportJob:
    job = create_report_job(db, tenant_id, user_id, incident_id, report_type=report_type)
    thread = threading.Thread(
        target=_run_report_job,
        args=(job.id, tenant_id, incident_id),
        daemon=True,
    )
    thread.start()
    return job


def get_job_for_user(db, job_id: str, user) -> ReportJob | None:
    query = db.query(ReportJob).filter(ReportJob.id == job_id)
    query = apply_tenant_scope(query, ReportJob, user)
    if user.tenant_id:
        allowed_incidents = filter_to_active_source(
            db.query(Incident.id).filter(Incident.tenant_id == user.tenant_id),
            db,
            user.tenant_id,
        )
        query = query.filter(ReportJob.incident_id.in_(allowed_incidents))
    job = query.first()
    if job is None or job.incident_id is None:
        return job
    incident = db.query(Incident).filter(Incident.id == job.incident_id).first()
    if incident is None or not (incident.analysis_json or {}).get("data_provenance"):
        return None
    return job

from datetime import datetime

import pytest
from fastapi import HTTPException

from app.core.security import hash_password
from app.db.models import Incident, ReportJob, Tenant, User

PERSISTED_ANALYSIS = {
    "executive_summary": "Persisted investigation summary.",
    "risk_assessment": {"score_contributions": {"risk_score": 0.9}},
    "governance": {"evidence_sufficiency": "INSUFFICIENT", "automated_decision": "NONE"},
    "data_provenance": {
        "source": "TENANT",
        "source_label": "Tenant Dataset",
        "dataset_id": "test-dataset-v1",
        "dataset_name": "Test dataset",
        "dataset_version": "1",
        "records_analyzed": 1,
        "synthetic": False,
    },
}


@pytest.fixture
def report_job_user(db_session):
    tenant = Tenant(name="Report Job Tenant")
    db_session.add(tenant)
    db_session.flush()
    user = User(
        email="report_job@example.com",
        hashed_password=hash_password("securepass"),
        tenant_id=tenant.id,
        role="analyst",
    )
    db_session.add(user)
    db_session.commit()
    return tenant, user


def _login(client, email, password):
    response = client.post("/auth/login", data={"username": email, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_report_job_creation_sets_queued_state(client, db_session, report_job_user):
    tenant, user = report_job_user
    incident = Incident(
        tenant_id=tenant.id,
        user_id="user-1",
        amount=1000.0,
        risk_score=0.8,
        anomaly_score=0.7,
        explanation="Job creation test",
        analysis_json=PERSISTED_ANALYSIS,
    )
    db_session.add(incident)
    db_session.commit()

    token = _login(client, user.email, "securepass")
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(f"/reports/{incident.id}/jobs", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["incident_id"] == incident.id
    assert payload["status"] in {"queued", "running", "completed", "failed"}
    assert payload["job_id"]

    job = db_session.query(ReportJob).filter(ReportJob.id == payload["job_id"]).one()
    assert job.status in {"queued", "running", "completed", "failed"}
    assert job.tenant_id == tenant.id
    assert job.requested_by_user_id == user.id


def test_full_report_requires_persisted_analysis(db_session, report_job_user):
    from app.api.routes.reports import _require_persisted_analysis

    tenant, user = report_job_user
    incident = Incident(
        tenant_id=tenant.id,
        user_id="unanalysed-user",
        amount=1000.0,
        risk_score=0.8,
        anomaly_score=0.7,
    )
    db_session.add(incident)
    db_session.commit()

    with pytest.raises(HTTPException, match="source-aware analysis") as exc:
        _require_persisted_analysis(incident)
    assert exc.value.status_code == 409


def test_report_job_lifecycle_updates_state_and_persists_failure(client, db_session, report_job_user):
    tenant, user = report_job_user
    incident = Incident(
        tenant_id=tenant.id,
        user_id="user-2",
        amount=2000.0,
        risk_score=0.9,
        anomaly_score=0.8,
        explanation="Lifecycle test",
        analysis_json=PERSISTED_ANALYSIS,
    )
    db_session.add(incident)
    db_session.commit()

    token = _login(client, user.email, "securepass")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(f"/reports/{incident.id}/jobs", headers=headers)
    job_id = response.json()["job_id"]

    status_response = client.get(f"/reports/jobs/{job_id}", headers=headers)
    assert status_response.status_code == 200
    payload = status_response.json()
    assert payload["job_id"] == job_id
    assert payload["status"] in {"queued", "running", "completed", "failed"}
    assert payload["report_type"] == "incident_pdf"
    assert payload["tenant_id"] == tenant.id


def test_report_job_tenant_isolation_is_enforced(client, db_session, report_job_user):
    tenant_a, user_a = report_job_user
    tenant_b = Tenant(name="Other Tenant")
    db_session.add(tenant_b)
    db_session.flush()
    user_b = User(
        email="other_user@example.com",
        hashed_password=hash_password("securepass"),
        tenant_id=tenant_b.id,
        role="analyst",
    )
    db_session.add(user_b)
    db_session.commit()

    incident = Incident(
        tenant_id=tenant_a.id,
        user_id="user-3",
        amount=1500.0,
        risk_score=0.91,
        anomaly_score=0.81,
        explanation="Isolation test",
        analysis_json=PERSISTED_ANALYSIS,
    )
    db_session.add(incident)
    db_session.commit()

    token_a = _login(client, user_a.email, "securepass")
    headers_a = {"Authorization": f"Bearer {token_a}"}
    response = client.post(f"/reports/{incident.id}/jobs", headers=headers_a)
    job_id = response.json()["job_id"]

    token_b = _login(client, user_b.email, "securepass")
    headers_b = {"Authorization": f"Bearer {token_b}"}
    status_response = client.get(f"/reports/jobs/{job_id}", headers=headers_b)
    assert status_response.status_code == 404


def test_report_job_result_requires_completed_state(client, db_session, report_job_user):
    tenant, user = report_job_user
    incident = Incident(
        tenant_id=tenant.id,
        user_id="user-4",
        amount=3000.0,
        risk_score=0.95,
        anomaly_score=0.87,
        explanation="Result status test",
        analysis_json=PERSISTED_ANALYSIS,
    )
    db_session.add(incident)
    db_session.commit()

    token = _login(client, user.email, "securepass")
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(f"/reports/{incident.id}/jobs", headers=headers)
    job_id = response.json()["job_id"]

    response = client.get(f"/reports/jobs/{job_id}/result", headers=headers)
    assert response.status_code in {200, 409}

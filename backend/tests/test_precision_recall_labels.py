from app.core.security import hash_password
from app.db.models import AuthoritativeLabel, Incident, Tenant, User


def _authenticated_headers(client, user):
    response = client.post(
        "/auth/login",
        data={"username": user.email, "password": "securepass"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": "Bearer " + token}


def _tenant_user(db_session, email="evaluation-analyst@test"):
    tenant = Tenant(
        name=f"Evaluation tenant {email}",
        tenant_type="CUSTOMER",
        provenance="LEGITIMATE_CUSTOMER",
        status="ACTIVE",
    )
    db_session.add(tenant)
    db_session.flush()
    user = User(
        email=email,
        hashed_password=hash_password("securepass"),
        role="analyst",
        tenant_id=tenant.id,
    )
    db_session.add(user)
    db_session.flush()
    return tenant, user


def _incident(db_session, tenant_id, user_id, risk_score):
    incident = Incident(
        tenant_id=tenant_id,
        user_id=user_id,
        amount=100,
        risk_score=risk_score,
        anomaly_score=0.1,
    )
    db_session.add(incident)
    db_session.flush()
    return incident


def _label(db_session, tenant_id, incident, label, user):
    db_session.add(
        AuthoritativeLabel(
            tenant_id=tenant_id,
            incident_id=incident.id,
            label=label,
            model_version_at_incident="test-model",
            feature_values={},
            amount=incident.amount,
            transaction_type=incident.transaction_type,
            labelled_by=user.email,
        )
    )


def test_precision_recall_marks_synthetic_fallback(client, db_session):
    tenant, user = _tenant_user(db_session)
    _incident(db_session, tenant.id, "one", 0.9)
    _incident(db_session, tenant.id, "two", 0.1)
    db_session.commit()

    response = client.get(
        "/analytics/precision-recall",
        headers=_authenticated_headers(client, user),
    )

    assert response.status_code == 200
    metrics = response.json()
    assert metrics["evaluation_mode"] == "synthetic"
    assert metrics["ground_truth_source"] == "synthetic_seeded"
    assert metrics["evaluated_count"] == 2
    assert metrics["total_incidents"] == 2
    assert metrics["label_coverage"] == 0.0
    assert "pipeline-health checks" in metrics["evaluation_note"]


def test_precision_recall_uses_only_confirmed_labels_and_excludes_inconclusive(
    client, db_session
):
    tenant, user = _tenant_user(db_session)
    fraud = _incident(db_session, tenant.id, "fraud", 0.9)
    legitimate = _incident(db_session, tenant.id, "legitimate", 0.8)
    inconclusive = _incident(db_session, tenant.id, "inconclusive", 0.1)
    unlabelled = _incident(db_session, tenant.id, "unlabelled", 0.99)
    _label(db_session, tenant.id, fraud, "confirmed_fraud", user)
    _label(db_session, tenant.id, legitimate, "confirmed_legitimate", user)
    _label(db_session, tenant.id, inconclusive, "inconclusive", user)
    db_session.commit()

    response = client.get(
        "/analytics/precision-recall",
        headers=_authenticated_headers(client, user),
    )

    assert response.status_code == 200
    metrics = response.json()
    assert metrics["evaluation_mode"] == "validated"
    assert metrics["ground_truth_source"] == "authoritative_labels"
    assert metrics["evaluated_count"] == 2
    assert metrics["total_incidents"] == 4
    assert metrics["label_coverage"] == 0.5
    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["recall"] == 1.0


def test_precision_recall_reports_full_authoritative_coverage(client, db_session):
    tenant, user = _tenant_user(db_session)
    fraud = _incident(db_session, tenant.id, "fraud", 0.9)
    legitimate = _incident(db_session, tenant.id, "legitimate", 0.1)
    _label(db_session, tenant.id, fraud, "confirmed_fraud", user)
    _label(db_session, tenant.id, legitimate, "confirmed_legitimate", user)
    db_session.commit()

    response = client.get(
        "/analytics/precision-recall",
        headers=_authenticated_headers(client, user),
    )

    assert response.status_code == 200
    metrics = response.json()
    assert metrics["evaluation_mode"] == "validated"
    assert metrics["evaluated_count"] == 2
    assert metrics["total_incidents"] == 2
    assert metrics["label_coverage"] == 1.0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0

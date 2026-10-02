from datetime import datetime, timedelta

from app.core.security import hash_password
from app.db.models import Incident, Tenant, TenantType, User
from app.services.transaction_history import build_transaction_history


def _incident(tenant_id, user_id, created_at, *, dataset_id="upload-v1", amount=100.0, payload=None):
    return Incident(
        tenant_id=tenant_id,
        user_id=user_id,
        amount=amount,
        transaction_type="WITHDRAWAL",
        device_id="DEV-1",
        risk_score=0.3,
        anomaly_score=0.2,
        created_at=created_at,
        raw_payload=payload or {},
        dataset_source="USER_TEST",
        dataset_id=dataset_id,
    )


def test_history_builds_baseline_timeline_and_findings_from_scoped_rows(db_session):
    tenant = Tenant(name="History Demo", tenant_type=TenantType.DEMO.value)
    other_tenant = Tenant(name="Other History Demo", tenant_type=TenantType.DEMO.value)
    db_session.add_all([tenant, other_tenant])
    db_session.flush()
    now = datetime(2026, 9, 30, 12)

    prior_rows = [
        _incident(
            tenant.id,
            "U1034",
            now - timedelta(days=day),
            amount=amount,
            payload={"channel": "USSD", "origin_city": "Warri", "origin_country": "NG", "transaction_id": f"TXN-{day}"},
        )
        for day, amount in ((10, 20_000), (20, 24_000), (30, 28_000))
    ]
    current = _incident(
        tenant.id,
        "U1034",
        now,
        amount=22_000,
        payload={"channel": "MOBILE_APP", "origin_city": "Dubai", "origin_country": "AE", "transaction_id": "TXN-CURRENT"},
    )
    outside_tenant = _incident(other_tenant.id, "U1034", now - timedelta(days=1), amount=1)
    outside_user = _incident(tenant.id, "U9999", now - timedelta(days=1), amount=2)
    outside_dataset = _incident(tenant.id, "U1034", now - timedelta(days=1), dataset_id="other-upload", amount=3)
    outside_window = _incident(tenant.id, "U1034", now - timedelta(days=91), amount=4)
    db_session.add_all([*prior_rows, current, outside_tenant, outside_user, outside_dataset, outside_window])
    db_session.commit()

    result = build_transaction_history(db_session, current)

    assert result["lookback_days"] == 90
    assert result["historical_transaction_count"] == 3
    assert [row["transaction_id"] for row in result["transactions"]] == ["TXN-30", "TXN-20", "TXN-10", "TXN-CURRENT"]
    assert result["baseline"]["comparable_transaction_count"] == 3
    assert result["baseline"]["average_amount"] == 24_000
    assert result["baseline"]["amount_variance_percent"] == round((22_000 - 24_000) / 24_000 * 100, 2)
    assert result["baseline"]["current_location"] == "Dubai, AE"
    assert result["baseline"]["channel_usage"]["USSD"] == {"count": 3, "percent": 100.0}
    assert result["findings"][1]["status"] == "location_change"
    assert result["profile"]["transaction_count"] == 4
    assert len(result["activity"]["daily_counts"]) == 4
    assert result["activity"]["velocity_24h_series"][-1]["count"] == 1
    assert result["activity"]["velocity_24h_series"][-1]["is_incident"] is True


def test_history_endpoint_is_active_tenant_scoped(client, db_session):
    tenant = Tenant(name="History Route Tenant", tenant_type=TenantType.CUSTOMER.value)
    db_session.add(tenant)
    db_session.flush()
    user = User(
        email="history-route@example.com",
        hashed_password=hash_password("securepass"),
        role="analyst",
        tenant_id=tenant.id,
    )
    incident = _incident(tenant.id, "U-ROUTE", datetime.utcnow())
    incident.dataset_source = "TENANT"
    db_session.add_all([user, incident])
    db_session.commit()

    login = client.post(
        "/auth/login",
        data={"username": user.email, "password": "securepass"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    response = client.get(f"/incidents/{incident.id}/history?lookback_days=30", headers=headers)

    assert response.status_code == 200
    assert response.json()["lookback_days"] == 30
    assert response.json()["historical_transaction_count"] == 0
    assert response.json()["transactions"][0]["is_incident"] is True

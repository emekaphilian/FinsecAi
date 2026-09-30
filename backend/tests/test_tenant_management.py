from app.core.security import hash_password
from app.db.models import AuditEvent, Tenant, TenantProvenance, User


def add_user(db_session, email, role, tenant_id=None):
    user = User(
        email=email,
        hashed_password=hash_password("securepass"),
        role=role,
        tenant_id=tenant_id,
    )
    db_session.add(user)
    db_session.commit()
    return user


def login(client, email):
    response = client.post(
        "/auth/login", data={"username": email, "password": "securepass"}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def create_payload(company_name):
    return {
        "company_name": company_name,
        "initial_administrator": {
            "email": f"admin@{company_name.replace(' ', '').lower()}.test",
            "password": "securepass",
            "role": "admin",
        },
    }


def test_only_owner_can_create_tenant(client, db_session):
    tenant = Tenant(name="Home Tenant")
    db_session.add(tenant)
    db_session.flush()
    owner = add_user(db_session, "platform-owner@test", "owner")
    analyst = add_user(db_session, "tenant-analyst@test", "analyst", tenant.id)

    response = client.post("/tenants", json=create_payload("Customer API"), headers=login(client, owner.email))
    assert response.status_code == 201
    created_id = response.json()["id"]
    assert response.json()["tenant_type"] == "CUSTOMER"

    denied = client.post("/tenants", json=create_payload("Rejected API"), headers=login(client, analyst.email))
    assert denied.status_code == 403
    assert db_session.query(Tenant).filter(Tenant.name == "Rejected API").count() == 0
    assert db_session.query(AuditEvent).filter(AuditEvent.resource_id == created_id).count() >= 1


def test_tenant_idor_and_user_management_boundaries(client, db_session):
    tenant_a = Tenant(
        name="Tenant A",
        provenance=TenantProvenance.LEGITIMATE_CUSTOMER.value,
    )
    tenant_b = Tenant(
        name="Tenant B",
        provenance=TenantProvenance.LEGITIMATE_CUSTOMER.value,
    )
    db_session.add_all([tenant_a, tenant_b])
    db_session.flush()
    owner = add_user(db_session, "owner-boundary@test", "owner")
    admin_a = add_user(db_session, "admin-a@test", "admin", tenant_a.id)
    analyst_a = add_user(db_session, "analyst-a@test", "analyst", tenant_a.id)
    user_b = add_user(db_session, "user-b@test", "viewer", tenant_b.id)

    admin_headers = login(client, admin_a.email)
    assert client.get(f"/tenants/{tenant_a.id}", headers=admin_headers).status_code == 200
    assert client.get(f"/tenants/{tenant_b.id}", headers=admin_headers).status_code == 404
    assert client.get(f"/tenants/{tenant_b.id}/users", headers=admin_headers).status_code == 404
    assert client.patch(
        f"/tenants/{tenant_b.id}/users/{user_b.id}",
        json={"status": "DISABLED"},
        headers=admin_headers,
    ).status_code == 404

    analyst_headers = login(client, analyst_a.email)
    assert client.post(
        f"/tenants/{tenant_a.id}/users",
        json={"email": "blocked@test", "password": "securepass", "role": "viewer"},
        headers=analyst_headers,
    ).status_code == 403

    owner_headers = login(client, owner.email)
    assert client.get("/tenants", headers=owner_headers).status_code == 200
    created = client.post(
        f"/tenants/{tenant_b.id}/users",
        json={"email": "owner-created@test", "password": "securepass", "role": "analyst"},
        headers=owner_headers,
    )
    assert created.status_code == 201
    assert "hashed_password" not in created.json()


def test_owner_lifecycle_changes_are_audited(client, db_session):
    tenant = Tenant(
        name="Lifecycle Tenant",
        provenance=TenantProvenance.LEGITIMATE_CUSTOMER.value,
    )
    db_session.add(tenant)
    db_session.flush()
    owner = add_user(db_session, "lifecycle-owner@test", "owner")
    headers = login(client, owner.email)

    suspended = client.post(f"/tenants/{tenant.id}/suspend", headers=headers)
    assert suspended.status_code == 200
    assert suspended.json()["status"] == "SUSPENDED"
    deactivated = client.post(f"/tenants/{tenant.id}/deactivate", headers=headers)
    assert deactivated.status_code == 200
    assert deactivated.json()["status"] == "INACTIVE"
    reactivated = client.post(f"/tenants/{tenant.id}/reactivate", headers=headers)
    assert reactivated.status_code == 200
    assert reactivated.json()["status"] == "ACTIVE"

    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.resource_id == tenant.id)
        .order_by(AuditEvent.created_at)
        .all()
    )
    assert [event.action for event in events] == [
        "tenant.status.changed",
        "tenant.status.changed",
        "tenant.status.changed",
    ]
    assert events[0].metadata_json["old_status"] == "ACTIVE"
    assert events[0].metadata_json["new_status"] == "SUSPENDED"

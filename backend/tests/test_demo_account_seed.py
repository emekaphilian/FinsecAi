from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.security import verify_password
from app.db.models import (
    AuditEvent,
    Incident,
    IncidentDataset,
    SuspiciousTransactionReport,
    Tenant,
    TenantConfiguration,
    TenantType,
    User,
)
from app.db.session import Base
from app.seed import (
    ensure_default_demo_dataset,
    migrate_legacy_demo_account,
    seed_if_empty,
)


def test_seed_creates_only_canonical_demo_account(db_session, monkeypatch):
    monkeypatch.setattr("app.seed.embed_evidence_chunks", lambda db, chunks: 0)

    seed_if_empty(db_session)

    users = db_session.query(User).all()
    assert [user.email for user in users] == ["demo@finsecai.com"]
    demo_user = users[0]
    assert demo_user.role == "analyst"
    assert demo_user.tenant_id is not None
    assert verify_password("demo", demo_user.hashed_password)


def test_legacy_demo_account_is_migrated_and_duplicates_removed(db_session):
    tenant = Tenant(name="Acme Corp", tenant_type=TenantType.DEMO.value)
    db_session.add(tenant)
    db_session.flush()

    canonical = User(
        email="demo@finsecai.com",
        hashed_password="old-hash",
        role="viewer",
        tenant_id=tenant.id,
    )
    legacy = User(
        email="analyst@acme.test",
        hashed_password="legacy-hash",
        role="analyst",
        tenant_id=tenant.id,
    )
    db_session.add_all([canonical, legacy])
    db_session.flush()

    customer = Tenant(name="Customer tenant", tenant_type=TenantType.CUSTOMER.value)
    db_session.add(customer)
    db_session.flush()
    customer_legacy_address = User(
        email="[analyst@acme.test](mailto\\:analyst@acme.test)",
        hashed_password="customer-hash",
        role="analyst",
        tenant_id=customer.id,
    )
    db_session.add(customer_legacy_address)
    db_session.flush()

    event = AuditEvent(
        actor_user_id=legacy.id,
        tenant_id=tenant.id,
        action="legacy.demo.login",
        resource_type="user",
        resource_id=legacy.id,
    )
    report = SuspiciousTransactionReport(
        tenant_id=tenant.id,
        incident_id="legacy-incident",
        narrative="Legacy demo report",
        created_by_user_id=legacy.id,
    )
    db_session.add_all([event, report])
    db_session.commit()

    migrate_legacy_demo_account(db_session)

    assert db_session.query(User).filter_by(email="analyst@acme.test").count() == 0
    assert db_session.query(User).filter_by(id=customer_legacy_address.id).one().tenant_id == customer.id
    assert db_session.query(User).filter_by(email="demo@finsecai.com").count() == 1
    assert canonical.role == "analyst"
    assert canonical.tenant_id == tenant.id
    assert verify_password("demo", canonical.hashed_password)
    assert db_session.query(AuditEvent).one().actor_user_id == canonical.id
    assert db_session.query(SuspiciousTransactionReport).one().created_by_user_id == canonical.id


def test_legacy_demo_account_is_renamed_when_canonical_account_is_missing(db_session):
    tenant = Tenant(name="Acme Corp", tenant_type=TenantType.DEMO.value)
    db_session.add(tenant)
    db_session.flush()
    db_session.add(
        User(
            email="analyst@acme.test",
            hashed_password="legacy-hash",
            role="analyst",
            tenant_id=tenant.id,
        )
    )
    db_session.commit()

    migrate_legacy_demo_account(db_session)

    migrated = db_session.query(User).one()
    assert migrated.email == "demo@finsecai.com"
    assert migrated.role == "analyst"
    assert migrated.tenant_id == tenant.id
    assert verify_password("demo", migrated.hashed_password)


def test_startup_migrates_legacy_demo_account_when_seeding_disabled(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    tenant = Tenant(name="Acme Corp")
    session.add(tenant)
    session.flush()
    session.add(
        User(
            email="analyst@acme.test",
            hashed_password="legacy-hash",
            role="analyst",
            tenant_id=tenant.id,
        )
    )
    session.commit()
    session.close()

    import app.main as main_module

    monkeypatch.setattr(main_module, "engine", engine)
    monkeypatch.setattr(main_module, "SessionLocal", session_factory)
    monkeypatch.setattr(main_module.settings, "seed_demo_data", False)
    monkeypatch.setattr("app.seed.embed_evidence_chunks", lambda db, chunks: 0)

    main_module.on_startup()

    session = session_factory()
    try:
        migrated = session.query(User).filter_by(email="demo@finsecai.com").one()
        assert session.query(User).filter_by(email="analyst@acme.test").count() == 0
        assert migrated.tenant_id == tenant.id
        assert verify_password("demo", migrated.hashed_password)
        assert session.query(Tenant).filter_by(id=tenant.id).one().tenant_type == TenantType.DEMO.value
    finally:
        session.close()
        engine.dispose()


def test_seed_replaces_legacy_incidents_with_the_60_row_fixture(db_session, monkeypatch):
    from app.seed import default_demo_incidents

    monkeypatch.setattr("app.seed.embed_evidence_chunks", lambda db, chunks: 0)
    tenant = Tenant(
        name="Acme Corp",
        tenant_type=TenantType.DEMO.value,
    )
    db_session.add(tenant)
    db_session.flush()
    db_session.add_all(
        [
            Incident(
                tenant_id=tenant.id,
                user_id=f"LEGACY-{index}",
                amount=100 + index,
                risk_score=0.5,
                anomaly_score=0.5,
                dataset_source="DEMO",
                dataset_id=f"LEGACY-{tenant.id}-DEMO",
                dataset_name="Preserved legacy incident dataset",
            )
            for index in range(3)
        ]
    )
    db_session.add(
        IncidentDataset(
            id=f"LEGACY-{tenant.id}-DEMO",
            tenant_id=tenant.id,
            source_type="DEMO",
            name="Preserved legacy incident dataset",
            version="legacy",
            record_count=3,
            synthetic=True,
        )
    )
    db_session.commit()

    restored = ensure_default_demo_dataset(db_session)

    assert restored == 60
    incidents = db_session.query(Incident).filter_by(tenant_id=tenant.id).all()
    assert len(incidents) == 60
    assert {incident.dataset_id for incident in incidents} == {"FINSECAI_DEMO_V1"}
    assert {incident.user_id for incident in incidents} == {
        incident.user_id for incident in default_demo_incidents(tenant.id)
    }
    dataset = db_session.query(IncidentDataset).filter_by(id="FINSECAI_DEMO_V1").one()
    assert dataset.record_count == 60
    assert db_session.query(IncidentDataset).filter_by(
        id=f"LEGACY-{tenant.id}-DEMO"
    ).count() == 0

    # Startup is idempotent and must not duplicate or rewrite the fixture.
    existing_ids = {incident.id for incident in incidents}
    assert ensure_default_demo_dataset(db_session) == 0
    assert {incident.id for incident in db_session.query(Incident).filter_by(tenant_id=tenant.id)} == existing_ids


def test_seed_does_not_replace_uploaded_demo_workspace_data(db_session):
    tenant = Tenant(name="Acme Corp", tenant_type=TenantType.DEMO.value)
    db_session.add(tenant)
    db_session.flush()
    db_session.add(
        TenantConfiguration(
            tenant_id=tenant.id,
            configuration={"data_mode": "user_data"},
        )
    )
    uploaded = Incident(
        tenant_id=tenant.id,
        user_id="UPLOADED-1",
        amount=123,
        risk_score=0.2,
        anomaly_score=0.3,
        dataset_source="USER_TEST",
        dataset_id="UPLOAD-1",
    )
    legacy = Incident(
        tenant_id=tenant.id,
        user_id="LEGACY-1",
        amount=456,
        risk_score=0.7,
        anomaly_score=0.8,
        dataset_source="DEMO",
        dataset_id=f"LEGACY-{tenant.id}-DEMO",
    )
    db_session.add_all([uploaded, legacy])
    db_session.commit()

    assert ensure_default_demo_dataset(db_session) == 0
    assert db_session.query(Incident).filter_by(id=uploaded.id).one()
    assert db_session.query(Incident).filter_by(id=legacy.id).one()
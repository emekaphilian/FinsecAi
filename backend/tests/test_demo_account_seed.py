from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.security import verify_password
from app.db.models import (
    AuditEvent,
    SuspiciousTransactionReport,
    Tenant,
    TenantType,
    User,
)
from app.db.session import Base
from app.seed import migrate_legacy_demo_account, seed_if_empty


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
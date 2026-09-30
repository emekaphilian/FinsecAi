import csv
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.db.models import (
    EvidenceChunk,
    Incident,
    IncidentDataset,
    Tenant,
    TenantConfiguration,
    TenantStatus,
    TenantProvenance,
    TenantType,
    User,
)
from app.services.evidence_ingestion import embed_evidence_chunks
from app.core.config import settings
from app.services.dataset_provenance import DEMO


def ensure_evidence_seeded(db: Session) -> int:
    """Backfill reference evidence only for explicitly marked demo tenants."""
    # Migration/backfill: replace old seeded CASE-* rows with a richer reference corpus.
    # This operation is idempotent and narrowly scoped: it only affects rows where
    # `framework_id` begins with 'CASE-' and `source` is one of the original tiers.
    def _migrate_old_seeded_corpus() -> int:
        migrated = 0
        for tenant in db.query(Tenant).filter(Tenant.tenant_type == TenantType.DEMO.value).all():
            old_rows = (
                db.query(EvidenceChunk)
                .filter(EvidenceChunk.tenant_id == tenant.id)
                .filter(EvidenceChunk.framework_id.ilike("CASE-%"))
                .filter(EvidenceChunk.source.in_(["high", "medium", "low"]))
                .all()
            )

            if not old_rows:
                continue

            db.query(EvidenceChunk).filter(
                EvidenceChunk.tenant_id == tenant.id,
                EvidenceChunk.framework_id.ilike("CASE-%"),
                EvidenceChunk.source.in_(["high", "medium", "low"]),
            ).delete(synchronize_session=False)

            chunks: list[EvidenceChunk] = []
            for tier, texts in _EVIDENCE_CORPUS.items():
                for i, text in enumerate(texts):
                    chunk = EvidenceChunk(
                        tenant_id=tenant.id,
                        source=f"reference_{tier}",
                        framework_id=f"REF-{tier.upper()}-{i}",
                        text=text,
                        metadata_json={
                            "synthetic": True,
                            "evidence_type": "reference_guidance",
                            "seed_migration_v1": True,
                        },
                    )
                    db.add(chunk)
                    chunks.append(chunk)

            embed_evidence_chunks(db, chunks)
            db.commit()
            migrated += 1

        return migrated

    _migrate_old_seeded_corpus()

    seeded_count = 0
    for tenant in db.query(Tenant).filter(Tenant.tenant_type == TenantType.DEMO.value).all():
        # Re-index legacy reference rows after upgrading from tier-based
        # retrieval. This is tenant-scoped and only touches missing vectors.
        unembedded = db.query(EvidenceChunk).filter(
            EvidenceChunk.tenant_id == tenant.id,
            EvidenceChunk.embedding.is_(None),
        ).all()
        if unembedded:
            embed_evidence_chunks(db, unembedded)

        existing = db.query(EvidenceChunk).filter(
            EvidenceChunk.tenant_id == tenant.id).count()
        if existing == 0:
            chunks = []
            for tier, texts in _EVIDENCE_CORPUS.items():
                for i, text in enumerate(texts):
                    chunk = EvidenceChunk(
                            tenant_id=tenant.id,
                            source=f"reference_{tier}",
                            framework_id=f"REF-{tier.upper()}-{i}",
                            text=text,
                        )
                    # mark as synthetic/reference guidance for clarity
                    chunk.metadata_json = {
                        "synthetic": True,
                        "evidence_type": "reference_guidance",
                    }
                    db.add(chunk)
                    chunks.append(chunk)
            embed_evidence_chunks(db, chunks)
            seeded_count += 1
    db.commit()
    return seeded_count


_EVIDENCE_CORPUS = {
    "high": [
        "Account takeover with rapid outbound transfer to an unverified beneficiary account within 30 minutes of credential compromise.",
        "Unauthorized push payment where credentials were phished and funds moved through an intermediatory account to a mule network.",
        "Multiple high-value transfers initiated after a successful MFA bypass and device spoofing; funds split across several wallets.",
    ],
    "medium": [
        "Unusual login from multiple countries within a short window; behavioral signals show device and IP anomaly but no confirmed loss.",
        "Suspicious sequence of small withdrawals from newly linked payees following social-engineering contact.",
        "Account exhibited credential stuffing indicators with intermittent transaction spikes and mismatched geolocation headers.",
    ],
    "low": [
        "Repeated low-value payments to newly created accounts consistent with reconnaissance or account testing patterns.",
        "Single off-pattern login from a rarely used device with minimal follow-on activity; low confidence of fraud.",
        "Unverified profile changes including new contact information and beneficiary addition without immediate high-value transfers.",
    ],
}


def default_demo_incidents(tenant_id: str) -> list[Incident]:
    """Load the versioned 60-row demonstration fixture without losing source fields."""
    fixture = Path(__file__).resolve().parent / "data" / "demo_finsecai_v1.csv"
    incidents: list[Incident] = []
    with fixture.open("r", encoding="utf-8-sig", newline="") as source_file:
        for row in csv.DictReader(source_file):
            timestamp = None
            if row.get("timestamp"):
                try:
                    timestamp = datetime.fromisoformat(row["timestamp"])
                except ValueError:
                    pass
            incidents.append(Incident(
                tenant_id=tenant_id,
                user_id=row["user_id"],
                amount=float(row["amount"]),
                transaction_type=row.get("transaction_type") or "TRANSFER",
                device_id=row.get("device_id") or row.get("device_name") or "",
                risk_score=float(row["risk_score"]),
                anomaly_score=float(row["anomaly_score"]),
                created_at=timestamp or datetime.utcnow(),
                raw_payload=row,
                dataset_source=DEMO,
                dataset_id="FINSECAI_DEMO_V1",
                dataset_name="FinSecAI Demonstration Dataset",
                dataset_version="V1",
                dataset_record_count=60,
            ))
    return incidents


def ensure_demo_dataset_record(db: Session) -> IncidentDataset:
    dataset = db.query(IncidentDataset).filter(IncidentDataset.id == "FINSECAI_DEMO_V1").first()
    if dataset is None:
        dataset = IncidentDataset(
            id="FINSECAI_DEMO_V1",
            source_type=DEMO,
            name="FinSecAI Demonstration Dataset",
            version="V1",
            record_count=60,
            synthetic=True,
            original_filename="demo_finsecai_v1.csv",
        )
        db.add(dataset)
    return dataset


def seed_if_empty(db: Session) -> None:
    # If no tenants exist, create demo tenant, hashed demo user, and sample incidents.
    if db.query(Tenant).count() == 0:
        tenant = Tenant(
            name="Acme Corp",
            description="Default demo tenant",
            tenant_type=TenantType.DEMO.value,
            provenance=TenantProvenance.LEGITIMATE_DEMO.value,
            status=TenantStatus.ACTIVE.value,
        )
        db.add(tenant)
        db.flush()
        db.add(
            TenantConfiguration(
                tenant_id=tenant.id,
                configuration={
                    "display_name": "Acme Corp Demo",
                    "default_severity": "medium",
                    "enabled_frameworks": ["mitre", "nist"],
                    "report": {"format": "pdf"},
                    "notifications": {"enabled": False},
                    "feature_flags": {},
                },
            )
        )

        user = User(
            email="demo@finsecai.com",
            hashed_password=hash_password("demo"),
            tenant_id=tenant.id,
            role="analyst",
        )
        db.add(user)

        chunks = []
        for tier, texts in _EVIDENCE_CORPUS.items():
            for i, text in enumerate(texts):
                chunk = EvidenceChunk(
                        tenant_id=tenant.id,
                        source=f"reference_{tier}",
                        framework_id=f"REF-{tier.upper()}-{i}",
                        text=text,
                    )
                chunk.metadata_json = {
                    "synthetic": True,
                    "evidence_type": "reference_guidance",
                }
                db.add(chunk)
                chunks.append(chunk)
        embed_evidence_chunks(db, chunks)

        ensure_demo_dataset_record(db)
        db.add_all(default_demo_incidents(tenant.id))
        db.commit()

    # Preserve the known Acme demo boundary when upgrading an older local DB
    # whose tenant classification columns did not exist yet.
    acme_tenant = db.query(Tenant).filter(Tenant.name == "Acme Corp").first()
    if acme_tenant and acme_tenant.tenant_type is None:
        acme_tenant.tenant_type = TenantType.DEMO.value
        acme_tenant.provenance = TenantProvenance.LEGITIMATE_DEMO.value
        acme_tenant.status = TenantStatus.ACTIVE.value
        db.commit()

    # Existing installations may contain the original malformed demo email
    # or the previous demo password. Repair the known demo analyst account.
    seeded_email = "demo@finsecai.com"
    malformed_email = r"[analyst@acme.test](mailto\:analyst@acme.test)"

    user = (
        db.query(User)
        .filter(User.email.in_([seeded_email, "analyst@acme.test", malformed_email]))
        .first()
    )
    if user:
        user.email = seeded_email
        user.hashed_password = hash_password("demo")
        db.add(user)
        db.commit()


def ensure_owner_seeded(db: Session) -> None:
    """Create the configured platform owner without relying on demo seeding."""
    if not settings.owner_email or not settings.owner_password:
        return
    email = settings.owner_email.strip().lower()
    owner = db.query(User).filter(User.email == email).first()
    if owner is None:
        db.add(
            User(
                email=email,
                hashed_password=hash_password(settings.owner_password),
                role="owner",
                tenant_id=None,
                must_change_password=False,
            )
        )
        db.commit()
        return

    # The documented development owner account is an immediately usable local
    # bootstrap account, not a temporary tenant-admin credential.  Preserve a
    # password an operator has changed, but clear the legacy forced-change flag
    # when the account still uses the configured bootstrap password.
    if owner.role == "owner" and verify_password(settings.owner_password, owner.hashed_password):
        if owner.must_change_password:
            owner.must_change_password = False
            db.commit()

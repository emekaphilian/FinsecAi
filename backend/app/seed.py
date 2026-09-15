from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.db.models import (
    EvidenceChunk,
    Incident,
    Tenant,
    TenantConfiguration,
    TenantStatus,
    TenantProvenance,
    TenantType,
    User,
)
from app.services.evidence_ingestion import embed_evidence_chunks
from app.core.config import settings


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
    """Build the repeatable incident set shown in the default demo workspace."""
    return [
        Incident(
            tenant_id=tenant_id,
            user_id="USER-0001",
            amount=18250,
            transaction_type="TRANSFER",
            device_id="DEV-11",
            risk_score=0.91,
            anomaly_score=0.88,
            confidence=0.87,
            explanation="High-risk transfer with matching velocity anomaly and device mismatch.",
            limitations="Synthetic routing context used for demo purposes.",
            governance_flags="Suspicious geolocation mismatch",
            mitre_techniques="T1102",
            nist_controls="IR-1",
        ),
        Incident(
            tenant_id=tenant_id,
            user_id="USER-0002",
            amount=4210,
            transaction_type="WITHDRAWAL",
            device_id="DEV-12",
            risk_score=0.58,
            anomaly_score=0.49,
            confidence=0.64,
            explanation="Moderate-risk activity with marginal anomaly score.",
            limitations="Requires analyst review for confirmation.",
            governance_flags="",
            mitre_techniques="T1078",
            nist_controls="PR.AC-1",
        ),
        Incident(
            tenant_id=tenant_id,
            user_id="USER-0003",
            amount=980,
            transaction_type="PAYMENT",
            device_id="DEV-13",
            risk_score=0.22,
            anomaly_score=0.18,
            confidence=0.74,
            explanation="Low-risk payment with no unusual velocity pattern.",
            limitations="No remediation needed.",
            governance_flags="",
            mitre_techniques="",
            nist_controls="",
        ),
    ]


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

"""Dataset source classification and incident/report provenance helpers."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.db.models import (
    Incident,
    IncidentDataset,
    Tenant,
    TenantConfiguration,
    TenantType,
)

DEMO = "DEMO"
USER_TEST = "USER_TEST"
TENANT = "TENANT"
SHARED = "SHARED"
SOURCE_LABELS = {
    DEMO: "Demo Data",
    USER_TEST: "User Test Data",
    TENANT: "Tenant Dataset",
}


def active_dataset_source(db: Session, tenant_id: str | None) -> str | None:
    """Return the source selected by a tenant's current workspace mode."""
    if not tenant_id:
        return None
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if tenant is None:
        return TENANT
    if tenant.tenant_type == TenantType.DEMO.value:
        config = (
            db.query(TenantConfiguration)
            .filter(TenantConfiguration.tenant_id == tenant_id)
            .first()
        )
        mode = (config.configuration or {}).get("data_mode", "demo_default") if config else "demo_default"
        return USER_TEST if mode == "user_data" else DEMO
    return TENANT


def filter_to_active_source(query, db: Session, tenant_id: str | None):
    source = active_dataset_source(db, tenant_id)
    return query.filter(Incident.dataset_source == source) if source else query


def incident_provenance(incident: Incident, tenant_name: str | None = None) -> dict:
    source = incident.dataset_source or TENANT
    return {
        "source": source,
        "source_label": SOURCE_LABELS.get(source, "Tenant Dataset"),
        "dataset_id": incident.dataset_id,
        "dataset_name": incident.dataset_name or "Existing dataset",
        "dataset_version": incident.dataset_version or "legacy",
        "records_analyzed": incident.dataset_record_count,
        "synthetic": source == DEMO,
        "tenant_name": tenant_name,
    }


def migrate_legacy_incident_provenance(db: Session) -> int:
    """Classify old rows and create registry records without deleting incidents."""
    rows = db.query(Incident).filter(Incident.dataset_source.is_(None)).all()
    if not rows:
        return 0
    grouped: dict[tuple[str | None, str], list[Incident]] = {}
    sources_by_tenant: dict[str | None, str] = {}
    for incident in rows:
        if incident.tenant_id not in sources_by_tenant:
            sources_by_tenant[incident.tenant_id] = active_dataset_source(db, incident.tenant_id) or TENANT
        source = sources_by_tenant[incident.tenant_id]
        grouped.setdefault((incident.tenant_id, source), []).append(incident)

    for (tenant_id, source), incidents in grouped.items():
        dataset_id = f"LEGACY-{tenant_id or 'GLOBAL'}-{source}"
        dataset = db.query(IncidentDataset).filter(IncidentDataset.id == dataset_id).first()
        if dataset is None:
            dataset = IncidentDataset(
                id=dataset_id,
                tenant_id=tenant_id,
                source_type=source,
                name="Preserved legacy incident dataset",
                version="legacy",
                record_count=len(incidents),
                synthetic=(source == DEMO),
            )
            db.add(dataset)
        else:
            dataset.record_count = max(dataset.record_count, len(incidents))
        for incident in incidents:
            incident.dataset_source = source
            incident.dataset_id = dataset_id
            incident.dataset_name = dataset.name
            incident.dataset_version = dataset.version
            incident.dataset_record_count = len(incidents)

    db.commit()
    return len(rows)

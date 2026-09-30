import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import audit, analytics, auth, compliance, copilot, incidents, mi_ops, reports, tenants
from app.core.config import settings
from app.db.models import User
from app.db.session import (
    Base,
    SessionLocal,
    engine,
    _ensure_report_job_schema_compatibility,
    _ensure_sqlite_schema_compatibility,
    _ensure_dataset_provenance_schema_compatibility,
    _ensure_user_credential_schema_compatibility,
)
from sqlalchemy import text
from app.seed import (
    ensure_evidence_seeded,
    ensure_owner_seeded,
    migrate_legacy_demo_account,
    seed_if_empty,
)
from app.services.dataset_provenance import migrate_legacy_incident_provenance

logger = logging.getLogger("finsecai.startup")

@asynccontextmanager
async def lifespan(app: FastAPI):
    on_startup()
    yield


app = FastAPI(
    title="FinSecAI SOC Command Center",
    version="1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(incidents.router)
app.include_router(analytics.router)
app.include_router(mi_ops.router)
app.include_router(reports.router)
app.include_router(copilot.router)
app.include_router(compliance.router)
app.include_router(tenants.router)
app.include_router(audit.router)


def on_startup():
    _ensure_sqlite_schema_compatibility(engine)
    _ensure_dataset_provenance_schema_compatibility(engine)
    _ensure_report_job_schema_compatibility(engine)
    _ensure_user_credential_schema_compatibility(engine)
    if engine.dialect.name == "postgresql":
        # pgvector is a hard production dependency for semantic RAG.
        with engine.begin() as connection:
            connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        migrate_legacy_incident_provenance(db)
        if settings.seed_demo_data:
            seed_if_empty(db)
        else:
            migrate_legacy_demo_account(db)
            if db.query(User).count() == 0:
                logger.warning(
                    "No users exist and demo seeding is disabled; login will not be available."
                )
        ensure_owner_seeded(db)
        ensure_evidence_seeded(db)
    finally:
        db.close()


@app.get("/")
def root():
    return {"status": "ok", "service": "FinSecAI", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}

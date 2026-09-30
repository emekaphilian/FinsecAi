import logging
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings

logger = logging.getLogger("finsecai.db")


def _ensure_sqlite_schema_compatibility(engine) -> None:
    """Backfill missing columns for older SQLite dev DBs without forcing a reset.

    This keeps local developer databases compatible with newer model additions
    such as `analysis_json` while preserving existing data.
    """
    if getattr(engine.dialect, "name", "") != "sqlite":
        return

    try:
        with engine.connect() as conn:
            inspector = inspect(conn)
            table_names = set(inspector.get_table_names())
            if "incidents" in table_names:
                columns = {col["name"] for col in inspector.get_columns("incidents")}
                additions = {
                    "analysis_json": "JSON",
                    "str_filed_at": "DATETIME",
                    "str_reference": "VARCHAR",
                    "risk_score_source": "VARCHAR",
                    "anomaly_score_source": "VARCHAR",
                    "model_version": "VARCHAR",
                    "dataset_source": "VARCHAR",
                    "dataset_id": "VARCHAR",
                    "dataset_name": "VARCHAR",
                    "dataset_version": "VARCHAR",
                    "dataset_record_count": "INTEGER",
                }
                for name, sql_type in additions.items():
                    if name not in columns:
                        conn.execute(text(f"ALTER TABLE incidents ADD COLUMN {name} {sql_type}"))
            if "evidence_chunks" in table_names:
                evidence_columns = {col["name"] for col in inspector.get_columns("evidence_chunks")}
                for name, sql_type in {
                    "metadata_json": "JSON",
                    "embedding_model": "VARCHAR",
                    "embedded_at": "DATETIME",
                    "dataset_source": "VARCHAR NOT NULL DEFAULT 'SHARED'",
                    "dataset_id": "VARCHAR",
                }.items():
                    if name not in evidence_columns:
                        conn.execute(text(f"ALTER TABLE evidence_chunks ADD COLUMN {name} {sql_type}"))
                conn.commit()
            if "users" in table_names:
                user_info = inspector.get_columns("users")
                user_columns = {col["name"] for col in user_info}
                if "status" not in user_columns:
                    conn.execute(text(
                        "ALTER TABLE users ADD COLUMN status VARCHAR NOT NULL DEFAULT 'ACTIVE'"
                    ))
                user_columns.add("status")
                if "must_change_password" not in user_columns:
                    conn.execute(text(
                        "ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0"
                    ))
                    conn.commit()
                tenant_column = next(
                    (column for column in user_info if column["name"] == "tenant_id"),
                    None,
                )
                if tenant_column and tenant_column["nullable"] is False:
                    conn.execute(text("PRAGMA foreign_keys=OFF"))
                    conn.execute(text("ALTER TABLE users RENAME TO users_legacy"))
                    conn.execute(text(
                        """CREATE TABLE users (
                            id VARCHAR PRIMARY KEY,
                            email VARCHAR NOT NULL UNIQUE,
                            hashed_password VARCHAR NOT NULL,
                            role VARCHAR NOT NULL DEFAULT 'analyst',
                            tenant_id VARCHAR NULL,
                            status VARCHAR NOT NULL DEFAULT 'ACTIVE',
                            must_change_password BOOLEAN NOT NULL DEFAULT 0
                        )"""
                    ))
                    conn.execute(text(
                        """INSERT INTO users
                        (id, email, hashed_password, role, tenant_id, status, must_change_password)
                        SELECT id, email, hashed_password, role, tenant_id, status,
                               must_change_password
                        FROM users_legacy"""
                    ))
                    conn.execute(text("DROP TABLE users_legacy"))
                    conn.execute(text("CREATE INDEX ix_users_email ON users (email)"))
                    conn.execute(text("PRAGMA foreign_keys=ON"))
                    conn.commit()
            if "tenants" in table_names:
                tenant_columns = {col["name"] for col in inspector.get_columns("tenants")}
                additions = {
                    "tenant_type": "VARCHAR",
                    "provenance": "VARCHAR NOT NULL DEFAULT 'UNKNOWN'",
                    "status": "VARCHAR NOT NULL DEFAULT 'ACTIVE'",
                    "industry": "VARCHAR NOT NULL DEFAULT ''",
                    "website": "VARCHAR NOT NULL DEFAULT ''",
                    "contact_email": "VARCHAR NOT NULL DEFAULT ''",
                    "contact_phone": "VARCHAR NOT NULL DEFAULT ''",
                    "country": "VARCHAR NOT NULL DEFAULT ''",
                    "timezone": "VARCHAR NOT NULL DEFAULT 'UTC'",
                    "created_at": "DATETIME",
                    "updated_at": "DATETIME",
                }
                for name, sql_type in additions.items():
                    if name not in tenant_columns:
                        conn.execute(text(f"ALTER TABLE tenants ADD COLUMN {name} {sql_type}"))
                conn.commit()
    except Exception:
        # Best-effort compatibility guard. If the schema cannot be inspected,
        # startup should still continue and let the app serve the request.
        return


def _ensure_dataset_provenance_schema_compatibility(engine) -> None:
    """Add source columns to deployed databases before ORM queries use them."""
    try:
        with engine.connect() as conn:
            inspector = inspect(conn)
            table_names = set(inspector.get_table_names())
            for table, additions in {
                "incidents": {
                    "dataset_source": "VARCHAR",
                    "dataset_id": "VARCHAR",
                    "dataset_name": "VARCHAR",
                    "dataset_version": "VARCHAR",
                    "dataset_record_count": "INTEGER",
                },
                "evidence_chunks": {
                    "dataset_source": "VARCHAR NOT NULL DEFAULT 'SHARED'",
                    "dataset_id": "VARCHAR",
                },
            }.items():
                if table not in table_names:
                    continue
                columns = {column["name"] for column in inspector.get_columns(table)}
                for name, sql_type in additions.items():
                    if name in columns:
                        continue
                    if engine.dialect.name == "postgresql":
                        conn.execute(text(
                            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {name} {sql_type}"
                        ))
                    else:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))
            conn.commit()
    except Exception:
        logger.exception("Dataset provenance schema migration failed")
        raise


def _ensure_report_job_schema_compatibility(engine) -> None:
    """Add missing report_jobs columns to pre-existing DBs without resetting data."""
    try:
        with engine.connect() as conn:
            inspector = inspect(conn)
            if "report_jobs" not in inspector.get_table_names():
                return
            columns = {col["name"] for col in inspector.get_columns("report_jobs")}
            additions = {
                "requested_by_user_id": "VARCHAR",
                "report_type": "VARCHAR DEFAULT 'incident_pdf'",
                "result_reference": "VARCHAR",
                "error_message": "TEXT",
                "started_at": "TIMESTAMP",
                "completed_at": "TIMESTAMP",
            }
            for name, sql_type in additions.items():
                if name not in columns:
                    conn.execute(text(f"ALTER TABLE report_jobs ADD COLUMN {name} {sql_type}"))
            conn.commit()
    except Exception:
        return


def _ensure_user_credential_schema_compatibility(engine) -> None:
    """Add temporary-password state to existing databases without resetting users."""
    try:
        with engine.connect() as conn:
            inspector = inspect(conn)
            if "users" not in inspector.get_table_names():
                return
            columns = {col["name"] for col in inspector.get_columns("users")}
            if "must_change_password" not in columns:
                if engine.dialect.name == "postgresql":
                    conn.execute(text(
                        "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
                        "must_change_password BOOLEAN NOT NULL DEFAULT FALSE"
                    ))
                else:
                    conn.execute(text(
                        "ALTER TABLE users ADD COLUMN must_change_password "
                        "BOOLEAN NOT NULL DEFAULT 0"
                    ))
                conn.commit()
    except Exception:
        return


# Local development may fall back to SQLite. Production must fail loudly.
def _create_engine_with_fallback():
    try:
        engine = create_engine(settings.database_url, pool_pre_ping=True)
        # try an immediate connect to validate credentials/availability
        with engine.connect():
            pass
        return engine
    except (SQLAlchemyError, ImportError):
        if settings.is_production:
            logger.critical(
                "Could not connect to the configured production database. "
                "Refusing SQLite fallback; fix the database configuration and restart."
            )
            raise
        logger.warning(
            "Configured database unavailable; using local SQLite fallback. "
            "Set ENVIRONMENT=production to disable this fallback."
        )
        fallback_db = Path(__file__).resolve().parents[2] / "tmp" / "finsecai_dev.db"
        fallback_db.parent.mkdir(parents=True, exist_ok=True)
        sqlite_url = f"sqlite:///{fallback_db.as_posix()}"
        engine = create_engine(
            sqlite_url, connect_args={"check_same_thread": False}, pool_pre_ping=True
        )
        _ensure_sqlite_schema_compatibility(engine)
        return engine


engine = _create_engine_with_fallback()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

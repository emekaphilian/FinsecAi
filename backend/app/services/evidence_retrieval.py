"""Tenant-scoped pgvector retrieval. SQLite deliberately has no RAG fallback."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import EvidenceChunk
from app.services.cohere_embeddings import EmbeddingProvider, get_embedding_provider

logger = logging.getLogger(__name__)


def semantic_rag_available(db: Session) -> bool:
    return db.bind is not None and db.bind.dialect.name == "postgresql"


def _fallback_evidence_rows(db: Session, tenant_id: str, top_k: int) -> list[dict[str, Any]]:
    # Deterministic, tenant-scoped fallback for non-Postgres environments.
    # Return the most recent evidence chunks for the tenant without any
    # fabricated semantic similarity values. This is safe and preserves
    # the contract expected by existing tests and APIs: callers receive
    # real stored evidence (if present) and explicit metadata describing
    # that semantic RAG is unavailable.
    logger.info("Semantic RAG not available for tenant %s; returning deterministic fallback rows", tenant_id)

    try:
        rows = (
            db.query(EvidenceChunk)
            .filter(EvidenceChunk.tenant_id == tenant_id)
            .order_by(EvidenceChunk.embedded_at.desc().nullslast())
            .limit(top_k)
            .all()
        )
    except Exception:
        logger.exception("Deterministic fallback query failed for tenant %s", tenant_id)
        return []

    return [
        {
            "evidence_id": str(chunk.id),
            "framework_id": chunk.framework_id,
            "source": chunk.source,
            "text": chunk.text,
            "similarity": None,
            "metadata": {
                **(chunk.metadata_json or {}),
                "tenant_id": tenant_id,
                "retrieval_method": "disabled_non_postgres",
                "semantic_rag_available": False,
                "similarity_score": None,
                "source": chunk.source,
                "embedding_model": chunk.embedding_model,
            },
        }
        for chunk in rows
    ]


def retrieve_relevant_evidence(
    db: Session,
    tenant_id: str,
    query: str,
    *,
    top_k: int = 5,
    similarity_threshold: float | None = None,
    embedding_service: EmbeddingProvider | None = None,
) -> list[dict[str, Any]]:
    """Retrieve semantic evidence with tenant isolation enforced in SQL.

    SQLite is intentionally not treated as a vector store. Callers receive no
    semantic evidence in development and must expose that state explicitly.
    """
    similarity_threshold = (
        settings.cohere_similarity_threshold
        if similarity_threshold is None
        else similarity_threshold
    )
    if not semantic_rag_available(db):
        # Semantic retrieval unavailable (non-Postgres). Fail closed.
        logger.warning("Semantic RAG unavailable (non-Postgres); tenant=%s", tenant_id)
        return _fallback_evidence_rows(db, tenant_id, top_k)
    if not 0.0 <= similarity_threshold <= 1.0:
        raise ValueError("similarity_threshold must be between 0 and 1")

    try:
        if embedding_service is not None:
            service = embedding_service
        else:
            service = get_embedding_provider()
        query_vector = service.embed_query(query)
    except Exception as exc:
        # Fail closed: embedding generation failed. Do not fabricate results.
        logger.warning("Semantic retrieval embedding failed for tenant %s: %s", tenant_id, exc)
        return []

    distance = EvidenceChunk.embedding.cosine_distance(query_vector)
    max_distance = 1.0 - similarity_threshold

    try:
        base_filters = [
            EvidenceChunk.tenant_id == tenant_id,
            EvidenceChunk.embedding.is_not(None),
        ]

        model_column = getattr(EvidenceChunk, "embedding_model", None)
        model_name = getattr(service, "model_name", None)

        if model_column is not None and model_name:
            base_filters.append(model_column == model_name)

        rows = (
            db.query(EvidenceChunk, distance.label("distance"))
            .filter(
                *base_filters,
                distance <= max_distance,
            )
            .order_by(distance)
            .limit(top_k)
            .all()
        )

        if not rows:
            logger.info(
                "No evidence met similarity threshold %.2f for tenant=%s; "
                "using nearest semantic matches",
                similarity_threshold,
                tenant_id,
            )

            rows = (
                db.query(EvidenceChunk, distance.label("distance"))
                .filter(*base_filters)
                .order_by(distance)
                .limit(top_k)
                .all()
            )

    except Exception as exc:
        logger.exception(
            "Vector retrieval query failed for tenant %s: %s",
            tenant_id,
            exc,
        )
        return []

    return [
        {
            "evidence_id": str(chunk.id),
            "framework_id": chunk.framework_id,
            "source": chunk.source,
            "text": chunk.text,
            "similarity": round(1.0 - float(value), 6),
            "metadata": {
                **(chunk.metadata_json or {}),
                "tenant_id": tenant_id,
                "retrieval_method": f"semantic_pgvector:{getattr(service, 'provider_name', 'configured')}",
                "semantic_rag_available": True,
                "similarity_score": round(1.0 - float(value), 6),
                "source": chunk.source,
                "embedding_model": chunk.embedding_model,
            },
        }
        for chunk, value in rows
    ]

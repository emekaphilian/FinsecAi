"""Tenant-scoped semantic retrieval using pgvector or persisted JSON vectors."""

from __future__ import annotations

import logging
import math
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import EvidenceChunk
from app.services.cohere_embeddings import EmbeddingProvider, get_embedding_provider

logger = logging.getLogger(__name__)


def semantic_rag_available(db: Session) -> bool:
    return db.bind is not None and db.bind.dialect.name == "postgresql"


def _dataset_filter(dataset_source: str | None, dataset_id: str | None):
    if not dataset_source:
        return None
    from sqlalchemy import and_, or_

    return or_(
        and_(EvidenceChunk.dataset_source == "SHARED", EvidenceChunk.dataset_id.is_(None)),
        and_(
            EvidenceChunk.dataset_source == dataset_source,
            or_(EvidenceChunk.dataset_id.is_(None), EvidenceChunk.dataset_id == dataset_id),
        ),
    )


def _python_vector_evidence_rows(
    db: Session, tenant_id: str, top_k: int,
    query_vector: list[float], model_name: str,
    dataset_source: str | None = None, dataset_id: str | None = None,
    similarity_threshold: float = 0.0,
) -> list[dict[str, Any]]:
    try:
        filters = [EvidenceChunk.tenant_id == tenant_id]
        dataset_filter = _dataset_filter(dataset_source, dataset_id)
        if dataset_filter is not None:
            filters.append(dataset_filter)
        rows = (
            db.query(EvidenceChunk)
            .filter(*filters, EvidenceChunk.embedding.is_not(None), EvidenceChunk.embedding_model == model_name)
            .order_by(EvidenceChunk.embedded_at.desc().nullslast())
            .limit(5000)
            .all()
        )
    except Exception:
        logger.exception("Deterministic fallback query failed for tenant %s", tenant_id)
        return []

    def cosine_similarity(vector: list[float]) -> float | None:
        if len(vector) != len(query_vector) or not vector:
            return None
        dot = sum(float(a) * float(b) for a, b in zip(vector, query_vector))
        norm_a = math.sqrt(sum(float(a) ** 2 for a in vector))
        norm_b = math.sqrt(sum(float(b) ** 2 for b in query_vector))
        return dot / (norm_a * norm_b) if norm_a and norm_b else None

    ranked = []
    for chunk in rows:
        score = cosine_similarity(chunk.embedding or [])
        if score is not None:
            ranked.append((chunk, score))
    ranked = sorted(ranked, key=lambda item: item[1], reverse=True)[:top_k]
    above_threshold = [item for item in ranked if item[1] >= similarity_threshold]
    if above_threshold:
        ranked = above_threshold
    return [
        {
            "evidence_id": str(chunk.id),
            "framework_id": chunk.framework_id,
            "source": chunk.source,
            "text": chunk.text,
            "similarity": round(score, 6),
            "metadata": {
                **(chunk.metadata_json or {}),
                "tenant_id": tenant_id,
                "dataset_source": getattr(chunk, "dataset_source", None),
                "dataset_id": getattr(chunk, "dataset_id", None),
                "retrieval_method": f"semantic_python:{getattr(settings, 'embedding_provider', 'configured')}",
                "semantic_rag_available": True,
                "similarity_score": round(score, 6),
                "source": chunk.source,
                "embedding_model": chunk.embedding_model,
            },
        }
        for chunk, score in ranked
    ]


def _non_postgres_fallback_rows(
    db: Session,
    tenant_id: str,
    top_k: int,
    dataset_source: str | None = None,
    dataset_id: str | None = None,
) -> list[dict[str, Any]]:
    """Deterministic compatibility fallback for non-PostgreSQL stores.

    This path is intentionally not semantic retrieval. PostgreSQL/Neon
    remains the production semantic-RAG path.
    """
    try:
        filters = [EvidenceChunk.tenant_id == tenant_id]
        dataset_filter = _dataset_filter(dataset_source, dataset_id)
        if dataset_filter is not None:
            filters.append(dataset_filter)

        rows = (
            db.query(EvidenceChunk)
            .filter(*filters)
            .order_by(EvidenceChunk.embedded_at.desc())
            .limit(top_k)
            .all()
        )
    except Exception:
        logger.exception(
            "Non-PostgreSQL evidence fallback failed for tenant %s",
            tenant_id,
        )
        return []

    return [
        {
            "evidence_id": str(chunk.id),
            "framework_id": chunk.framework_id,
            "source": chunk.source,
            "text": chunk.text,
            "similarity": 0.0,
            "metadata": {
                **(chunk.metadata_json or {}),
                "tenant_id": tenant_id,
                "dataset_source": getattr(chunk, "dataset_source", None),
                "dataset_id": getattr(chunk, "dataset_id", None),
                "retrieval_method": "disabled_non_postgres",
                "semantic_rag_available": False,
                "similarity_score": 0.0,
                "source": chunk.source,
                "embedding_model": getattr(chunk, "embedding_model", None),
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
    dataset_source: str | None = None,
    dataset_id: str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve semantically ranked evidence while enforcing tenant scope in SQL."""
    similarity_threshold = (
        settings.cohere_similarity_threshold
        if similarity_threshold is None
        else similarity_threshold
    )
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

    if not semantic_rag_available(db):
        rows = _python_vector_evidence_rows(
            db,
            tenant_id,
            top_k,
            query_vector,
            service.model_name,
            dataset_source,
            dataset_id,
            similarity_threshold,
        )

        if rows:
            return rows

        return _non_postgres_fallback_rows(
            db,
            tenant_id,
            top_k,
            dataset_source,
            dataset_id,
        )

    distance = EvidenceChunk.embedding.cosine_distance(query_vector)
    max_distance = 1.0 - similarity_threshold

    try:
        base_filters = [
            EvidenceChunk.tenant_id == tenant_id,
            EvidenceChunk.embedding.is_not(None),
        ]
        dataset_filter = _dataset_filter(dataset_source, dataset_id)
        if dataset_filter is not None:
            base_filters.append(dataset_filter)

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
                "dataset_source": getattr(chunk, "dataset_source", None),
                "dataset_id": getattr(chunk, "dataset_id", None),
                "retrieval_method": f"semantic_pgvector:{getattr(service, 'provider_name', 'configured')}",
                "semantic_rag_available": True,
                "similarity_score": round(1.0 - float(value), 6),
                "source": chunk.source,
                "embedding_model": chunk.embedding_model,
            },
        }
        for chunk, value in rows
    ]

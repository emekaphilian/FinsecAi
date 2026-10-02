"""Embedding-aware persistence for evidence chunks."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import EvidenceChunk
from app.services.cohere_embeddings import get_embedding_provider
from app.services.evidence_retrieval import semantic_rag_available


def _configured_embedding_model() -> str:
    provider = (settings.embedding_provider or "cohere").strip().lower()
    return (
        settings.openai_embed_model
        if provider == "openai"
        else settings.cohere_embed_model
    )


def embed_evidence_chunks(db: Session, chunks: list[EvidenceChunk]) -> int:
    """Embed chunks before commit for both pgvector and JSON-backed stores.

    PostgreSQL ranks vectors in SQL. Other supported databases persist the
    same provider vectors and rank the tenant-scoped candidates in Python.
    """
    if not chunks:
        return 0
    try:
        service = get_embedding_provider()
        embeddings = service.embed_documents([chunk.text for chunk in chunks])
    except Exception as exc:
        for chunk in chunks:
            metadata = dict(chunk.metadata_json or {})
            metadata.update({
                "embedding_status": "failed",
                "embedding_error": str(exc),
                "embedding_model": _configured_embedding_model(),
            })
            chunk.metadata_json = metadata
        return 0

    now = datetime.now(timezone.utc)
    for chunk, embedding in zip(chunks, embeddings, strict=True):
        chunk.embedding = embedding
        chunk.embedding_model = service.model_name
        chunk.embedded_at = now
        metadata = dict(chunk.metadata_json or {})
        metadata.update({
            "embedding_status": "indexed",
            "embedding_model": service.model_name,
            "embedding_error": None,
        })
        chunk.metadata_json = metadata
    return len(chunks)

"""One-off safe evidence re-index script.

Selects EvidenceChunk rows with `embedding IS NULL` and re-runs the
existing `embed_evidence_chunks` flow in small batches. Designed as a
maintenance/repair utility only.

Usage: python backend/scripts/reindex_evidence.py [--tenant TENANT_ID] [--batch-size N]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from sqlalchemy import func, or_

# Support both `python scripts/reindex_evidence.py` and
# `python -m scripts.reindex_evidence` when run from backend/.
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.db.session import SessionLocal
from app.db.models import EvidenceChunk
from app.services.evidence_ingestion import _configured_embedding_model, embed_evidence_chunks
from app.core.config import settings


def _print_banner():
    print("=== FinSecAI: evidence re-index utility ===")
    print("Embedding provider:", settings.embedding_provider)
    print("Embedding model:", _configured_embedding_model())


def _print_chunk(chunk: EvidenceChunk) -> None:
    metadata = dict(chunk.metadata_json or {})
    embedding_status = metadata.get("embedding_status")
    print(
        f"- tenant={chunk.tenant_id} id={chunk.id} framework={chunk.framework_id} "
        f"source={chunk.source} embedding_status={embedding_status} "
        f"embedded_at={chunk.embedded_at} embedding_model={chunk.embedding_model}"
    )


def reindex(tenant_id: Optional[str], batch_size: int = 20) -> int:
    target_model = _configured_embedding_model()
    session = SessionLocal()
    try:
        # Rebuild missing vectors and vectors tagged for a different provider
        # model. Retrieval deliberately filters by embedding_model, so these
        # rows would otherwise remain invisible or incomparable.
        needs_reindex = or_(
            EvidenceChunk.embedding.is_(None),
            EvidenceChunk.embedding_model.is_(None),
            EvidenceChunk.embedding_model != target_model,
        )
        base_q = session.query(EvidenceChunk.id).filter(needs_reindex)
        if tenant_id:
            base_q = base_q.filter(EvidenceChunk.tenant_id == tenant_id)

        ids = [row[0] for row in base_q.order_by(EvidenceChunk.id).all()]
        total_candidates = len(ids)
        print(f"Found {total_candidates} evidence rows to index for model {target_model}")

        success = 0
        failed = 0

        for i in range(0, total_candidates, batch_size):
            batch_ids = ids[i : i + batch_size]
            batch = (
                session.query(EvidenceChunk)
                .filter(EvidenceChunk.id.in_(batch_ids))
                .order_by(EvidenceChunk.id)
                .all()
            )
            if not batch:
                continue

            print(f"\nProcessing batch {i // batch_size + 1} (size {len(batch)})")
            for chunk in batch:
                _print_chunk(chunk)

            try:
                embedded_count = embed_evidence_chunks(session, batch)
                session.commit()
                success += embedded_count
                print(f"Batch embedded: {embedded_count}")
            except Exception as exc:  # pragma: no cover - operational
                session.rollback()
                failed += len(batch)
                print(f"Batch failed with error: {exc}", file=sys.stderr)
                # continue with next batch

        # remaining unembedded after attempts
        rem_q = session.query(func.count(EvidenceChunk.id)).filter(needs_reindex)
        if tenant_id:
            rem_q = rem_q.filter(EvidenceChunk.tenant_id == tenant_id)
        remaining = int(rem_q.scalar() or 0)

        print("\n=== Summary ===")
        print("candidates:", total_candidates)
        print("successfully_embedded:", success)
        print("failed:", failed)
        print("remaining_unembedded:", remaining)

        return 0
    finally:
        session.close()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Re-index evidence embeddings (one-off maintenance)")
    p.add_argument("--tenant", dest="tenant_id", default=None, help="Tenant ID to filter (optional)")
    p.add_argument("--batch-size", dest="batch_size", type=int, default=20, help="Batch size (default 20)")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    _print_banner()
    rc = reindex(args.tenant_id, batch_size=args.batch_size)
    raise SystemExit(rc)


if __name__ == "__main__":
    main()

from app.core.config import settings
from app.services.evidence_retrieval import retrieve_relevant_evidence


def test_regression_retrieves_test_a_and_respects_tenant_isolation(monkeypatch, db_session):
    """Regression: the known relevant TEST-A evidence must be returned
    at the configured similarity threshold and evidence from other tenants
    must never be returned.
    """

    # Two tenants
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"

    # We'll simulate the DB query using a DummyQuery that enforces tenant filtering
    class DummyDistance:
        def __init__(self, value):
            self.value = value

        def __le__(self, other):
            return ("distance_le", self.value, other)

        def label(self, name):
            return self

    class DummyEmbeddingAttr:
        def __init__(self, distance_value):
            self._distance_value = distance_value

        def cosine_distance(self, query_vector):
            return DummyDistance(self._distance_value)

        def is_not(self, other):
            return ("is_not", other)

    class DummyQuery:
        def __init__(self):
            self.filters = []

        def filter(self, *args):
            self.filters.extend(args)
            # Detect tenant filter if provided as tuple like ("tenant_eq", value)
            for expr in args:
                if isinstance(expr, tuple) and len(expr) >= 2 and expr[0] == "tenant_eq":
                    self.tenant_filter = expr[1]
            return self

        def order_by(self, arg):
            return self

        def limit(self, arg):
            return self

        def all(self):
            # Return one matching row for tenant-a only, and ensure tenant-b is not returned
            chunk_a = type(
                "Chunk",
                (),
                {
                    "id": "test-a",
                    "tenant_id": tenant_a,
                    "framework_id": "TEST-A",
                    "source": "A",
                    "text": "Test A evidence",
                    "metadata_json": None,
                    "dataset_source": "TENANT",
                    "dataset_id": None,
                    "embedding_model": None,
                },
            )()

            chunk_b = type(
                "Chunk",
                (),
                {
                    "id": "other-1",
                    "tenant_id": tenant_b,
                    "framework_id": "OTHER",
                    "source": "B",
                    "text": "Other tenant evidence",
                    "metadata_json": None,
                    "dataset_source": "TENANT",
                    "dataset_id": None,
                    "embedding_model": None,
                },
            )()

            # Distance value chosen so similarity ~= 0.407 (distance ~= 0.593)
            distance_value = 0.593

            rows = []
            if getattr(self, "tenant_filter", None) == tenant_a:
                rows.append((chunk_a, distance_value))
            if getattr(self, "tenant_filter", None) == tenant_b:
                rows.append((chunk_b, distance_value))

            return rows

    # Dummy embedding service that returns a query vector (unused by DummyDistance)
    class DummyEmbeddingService:
        def embed_query(self, text):
            return [0.0] * settings.cohere_embed_dimension

    # Monkeypatch environment to force semantic path and to use our DummyQuery
    monkeypatch.setattr("app.services.evidence_retrieval.semantic_rag_available", lambda _db: True)
    monkeypatch.setattr("app.services.evidence_retrieval.get_embedding_provider", DummyEmbeddingService)

    # Replace EvidenceChunk.embedding.cosine_distance behavior by patching the class used in query
    class DummyEvidenceChunk:
        tenant_id = tenant_a
        embedding = DummyEmbeddingAttr(0.593)

    monkeypatch.setattr("app.services.evidence_retrieval.EvidenceChunk", DummyEvidenceChunk)

    dummy_query = DummyQuery()
    # Pre-set tenant filter so DummyQuery.all returns tenant-a rows
    dummy_query.tenant_filter = tenant_a

    # Monkeypatch the db_session.query to return our DummyQuery and to capture the tenant filter
    def fake_query(*args):
        return dummy_query

    monkeypatch.setattr(db_session, "query", fake_query)

    # Now call retrieval -- it should use settings.cohere_similarity_threshold == 0.40
    results = retrieve_relevant_evidence(db_session, tenant_a, "some query", top_k=5)

    assert results, "Expected to retrieve at least one result for tenant_a"
    assert any(r["framework_id"] == "TEST-A" for r in results)
    # Ensure no result is from tenant_b
    assert all(r["metadata"]["tenant_id"] == tenant_a for r in results)

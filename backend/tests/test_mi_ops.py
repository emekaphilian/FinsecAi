from types import SimpleNamespace


def test_platform_drift_binarizes_scores_before_psi(monkeypatch):
    from app.api.routes import mi_ops

    captured = {}

    def fake_compute_drift(baseline, current):
        captured["baseline"] = baseline
        captured["current"] = current
        return {"drift_score": 0.0, "mean_shift": 0.0, "status": "low"}

    class Query:
        def order_by(self, *_args):
            return self

        def all(self):
            return [
                SimpleNamespace(risk_score=0.2),
                SimpleNamespace(risk_score=0.8),
                SimpleNamespace(risk_score=0.9),
                SimpleNamespace(risk_score=0.1),
            ]

    class Database:
        def query(self, *_args):
            return Query()

        def add(self, *_args):
            pass

        def commit(self):
            pass

    monkeypatch.setattr(mi_ops.evaluation_service, "compute_drift", fake_compute_drift)
    monkeypatch.setattr(mi_ops.model_registry, "get_active_version", lambda: "model-v1")
    # This unit test covers score binarization; enterprise query scoping is
    # exercised by the authorization and tenant-boundary tests.
    monkeypatch.setattr(mi_ops, "apply_enterprise_scope", lambda query, _model: query)
    result = mi_ops.platform_drift(
        request=None,
        db=Database(),
        user=SimpleNamespace(id="owner", tenant_id="platform", role="owner"),
    )

    assert captured == {"baseline": [0, 1], "current": [1, 0]}
    assert result["drift"]["status"] == "low"

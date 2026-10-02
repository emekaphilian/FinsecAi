"""Build the controlled facts package used for investigation generation."""

from __future__ import annotations

from typing import Any


def _risk_tier_label(score: float | None) -> str:
    if score is None:
        return "risk score unknown"
    if score > 0.85:
        return "high risk transaction"
    if score > 0.7:
        return "elevated risk transaction"
    if score > 0.4:
        return "moderate risk transaction"
    return "low risk transaction"


def _anomaly_language(score: float | None) -> str:
    if score is None:
        return "anomaly score unknown"
    if score > 0.8:
        return "strong anomalous activity"
    if score > 0.6:
        return "elevated anomalous activity"
    if score > 0.4:
        return "moderate anomalous activity"
    return "typical activity"


def _extract_scalar_context(payload: dict | None, max_chars: int = 500) -> str:
    if not payload:
        return ""
    parts: list[str] = []
    for k, v in payload.items():
        if not isinstance(k, str):
            continue
        # skip obvious identifiers to avoid dominating the semantic content
        if k.lower().endswith("id") or k.lower() in ("user_id", "device_id"):
            continue
        if isinstance(v, (str, int, float, bool)):
            s = f"{k}: {v}"
            parts.append(s)
        # stop collecting when we reach the cap
        if sum(len(p) for p in parts) > max_chars:
            break
    joined = ", ".join(parts)
    if len(joined) > max_chars:
        return joined[: max_chars - 3] + "..."
    return joined

from sqlalchemy.orm import Session

from app.db.models import AuthoritativeLabel, Feedback, Incident, MLPredictionAudit


def build_investigation_query(incident: Incident, audit: MLPredictionAudit | None) -> str:
    parts: list[str] = []
    # concise, investigation-focused lead
    parts.append("Investigate a financial transaction.")

    # Transaction type is an important retrieval token
    if incident.transaction_type:
        parts.append(f"Type: {incident.transaction_type}.")

    # Risk / anomaly descriptive language (prefer human labels)
    parts.append(_risk_tier_label(incident.risk_score))
    parts.append(_anomaly_language(incident.anomaly_score))
    # include numeric scores as supporting signals (not dominant)
    parts.append(f"risk_score:{incident.risk_score}")
    parts.append(f"anomaly_score:{incident.anomaly_score}")

    # Model version if available
    model_ver = audit.model_version if audit else (incident.model_version or "not model-scored")
    if model_ver:
        parts.append(f"model_version:{model_ver}")

    # Feature-derived semantic tokens (labels only, no identifiers or raw dumps)
    feature_values = audit.feature_values if audit and getattr(audit, "feature_values", None) else {}
    semantic_tokens: list[str] = []
    for k, v in feature_values.items():
        if not isinstance(k, str):
            continue
        key = k.lower()
        # do not emit raw ids or full strings that look like identifiers
        if key.endswith("id") or key in ("user_id", "device_id"):
            continue
        if isinstance(v, bool) and v:
            semantic_tokens.append(key.replace("_", " "))
        elif isinstance(v, str) and 0 < len(v) <= 40:
            # short descriptive string values are useful (e.g., country)
            semantic_tokens.append(f"{key}:{v}")
        elif isinstance(v, (int, float)):
            # numeric feature pivots only when small integers (counts)
            if abs(v) < 1000:
                semantic_tokens.append(f"{key}:{v}")
    if semantic_tokens:
        parts.append("features: " + ", ".join(semantic_tokens) + ".")

    # Feature contribution labels (names only)
    contributions = audit.feature_contributions if audit else []
    contrib_names: list[str] = []
    for item in contributions:
        if isinstance(item, dict):
            label = item.get("feature") or item.get("name") or item.get("label")
            if isinstance(label, str) and label:
                contrib_names.append(label.replace("_", " "))
        elif isinstance(item, str) and item:
            contrib_names.append(item)
    if contrib_names:
        parts.append("contributors: " + ", ".join(contrib_names) + ".")

    # Keep the query concise and bounded for pgvector
    joined = " ".join(parts)
    max_len = 500
    if len(joined) > max_len:
        return joined[: max_len - 3] + "..."
    return joined


def build_investigation_context(
    db: Session,
    tenant_id: str,
    incident: Incident,
    evidence: list[dict[str, Any]],
    historical_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    audit = (
        db.query(MLPredictionAudit)
        .filter(MLPredictionAudit.tenant_id == tenant_id, MLPredictionAudit.incident_id == incident.id)
        .order_by(MLPredictionAudit.created_at.desc())
        .first()
    )
    labels = (
        db.query(AuthoritativeLabel)
        .filter(AuthoritativeLabel.tenant_id == tenant_id, AuthoritativeLabel.incident_id == incident.id)
        .all()
    )
    feedback = db.query(Feedback).filter(Feedback.incident_id == incident.id).all()
    return {
        "incident": {
            "id": str(incident.id), "user_id": incident.user_id, "amount": incident.amount,
            "transaction_type": incident.transaction_type, "device_id": incident.device_id,
            "timestamp": incident.created_at.isoformat() if incident.created_at else None,
        },
        "ml_assessment": {
            "risk_score": incident.risk_score, "anomaly_score": incident.anomaly_score,
            "risk_score_source": incident.risk_score_source,
            "anomaly_score_source": incident.anomaly_score_source,
            "model_version": audit.model_version if audit else incident.model_version,
            "feature_values": audit.feature_values if audit else {},
            "feature_contributions": audit.feature_contributions if audit else [],
        },
        "authoritative_labels": [{"label": item.label, "source": item.label_source} for item in labels],
        "feedback": [{"label": item.label, "created_at": item.created_at.isoformat()} for item in feedback],
        "retrieved_evidence": evidence,
        "historical_analysis": (
            {
                "lookback_days": historical_analysis["lookback_days"],
                "historical_transaction_count": historical_analysis["historical_transaction_count"],
                "truncated": historical_analysis["truncated"],
                "baseline": historical_analysis["baseline"],
                "profile": historical_analysis["profile"],
                "recent_transactions": historical_analysis["transactions"][-10:],
                "findings": historical_analysis["findings"],
            }
            if historical_analysis is not None
            else None
        ),
    }

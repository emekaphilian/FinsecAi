"""Tenant- and dataset-scoped historical transaction evidence."""

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import Incident

MAX_HISTORY_ROWS = 5_000


def _payload_value(payload: dict[str, Any], *keys: str) -> Any:
    """Read uploaded fields despite casing, spaces, or underscore variants."""
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return value
    normalized_payload = {
        "".join(char for char in str(key).casefold() if char.isalnum()): value
        for key, value in payload.items()
    }
    for key in keys:
        value = normalized_payload.get(
            "".join(char for char in key.casefold() if char.isalnum())
        )
        if value not in (None, ""):
            return value
    return None


def _transaction_view(row: Incident, incident_id: str) -> dict[str, Any]:
    payload = row.raw_payload or {}
    city = _payload_value(payload, "origin_city", "source_city", "city", "location")
    country = _payload_value(payload, "origin_country", "source_country", "country")
    return {
        "incident_id": row.id,
        "transaction_id": _payload_value(payload, "transaction_id", "txn_id", "id") or row.id,
        "user_id": row.user_id,
        "timestamp": row.created_at.isoformat() if row.created_at else None,
        "amount": float(row.amount),
        "currency": _payload_value(payload, "currency"),
        "transaction_type": row.transaction_type,
        "channel": _payload_value(payload, "channel", "transaction_channel"),
        "device_id": row.device_id or _payload_value(payload, "device_id"),
        "device_name": _payload_value(payload, "device_name", "device_model"),
        "origin_city": city,
        "origin_country": country,
        "location": ", ".join(str(value) for value in (city, country) if value) or None,
        "ip_address": _payload_value(payload, "ip_address", "ip", "source_ip"),
        "source_account": _payload_value(payload, "source_account", "source_account_id", "from_account"),
        "destination_account": _payload_value(payload, "destination_account", "destination_account_id", "to_account"),
        "account_age_days": _payload_value(payload, "account_age_days", "account_age"),
        "risk_score": float(row.risk_score),
        "anomaly_score": float(row.anomaly_score),
        "is_incident": row.id == incident_id,
    }


def build_transaction_history(
    db: Session,
    incident: Incident,
    *,
    lookback_days: int = 90,
) -> dict[str, Any]:
    """Build the single historical baseline used by analysis and the incident UI.

    Rows are restricted to the incident's tenant, user, active dataset source,
    and (when present) its dataset id. Future-dated transactions are excluded
    to avoid leaking information that would not have been available then.
    """
    timestamp = incident.created_at or datetime.utcnow()
    cutoff = timestamp - timedelta(days=lookback_days)
    filters = [
        Incident.tenant_id == incident.tenant_id,
        Incident.user_id == incident.user_id,
        Incident.created_at >= cutoff,
        Incident.created_at <= timestamp,
    ]
    if incident.dataset_source is None:
        filters.append(Incident.dataset_source.is_(None))
    else:
        filters.append(Incident.dataset_source == incident.dataset_source)
    if incident.dataset_id:
        filters.append(Incident.dataset_id == incident.dataset_id)

    rows = (
        db.query(Incident)
        .filter(*filters)
        .order_by(Incident.created_at.desc(), Incident.id.asc())
        .limit(MAX_HISTORY_ROWS + 1)
        .all()
    )
    truncated = len(rows) > MAX_HISTORY_ROWS
    rows = list(reversed(rows[:MAX_HISTORY_ROWS]))
    transactions = [_transaction_view(row, incident.id) for row in rows]
    historical = [item for item in transactions if not item["is_incident"]]

    daily_activity = Counter(
        row.created_at.date().isoformat()
        for row in rows
        if row.created_at is not None
    )
    incident_activity_dates = {
        row.created_at.date().isoformat()
        for row in rows
        if row.created_at is not None and row.id == incident.id
    }
    velocity_series: list[dict[str, Any]] = []
    velocity_window: deque[tuple[datetime, dict[str, Any]]] = deque()
    for row, transaction in zip(rows, transactions):
        if row.created_at is None:
            continue
        row_time = row.created_at
        if row_time.tzinfo is not None:
            row_time = row_time.astimezone(timezone.utc).replace(tzinfo=None)
        while velocity_window and row_time - velocity_window[0][0] > timedelta(hours=24):
            velocity_window.popleft()
        velocity_window.append((row_time, transaction))
        velocity_series.append({
            "transaction_id": transaction["transaction_id"],
            "timestamp": transaction["timestamp"],
            "count": len(velocity_window),
            "is_incident": transaction["is_incident"],
        })

    incident_type = (incident.transaction_type or "").strip().casefold()
    comparable = [
        item for item in historical
        if (item["transaction_type"] or "").strip().casefold() == incident_type
    ]
    amount_average = (
        sum(item["amount"] for item in comparable) / len(comparable)
        if comparable else None
    )
    amount_variance = (
        (float(incident.amount) - amount_average) / amount_average * 100
        if amount_average else None
    )

    channels = Counter(item["channel"] for item in historical if item["channel"])
    all_channels = Counter(item["channel"] for item in transactions if item["channel"])
    channel_count = sum(channels.values())
    channel_usage = {
        channel: {
            "count": count,
            "percent": round(count / channel_count * 100, 1) if channel_count else None,
        }
        for channel, count in channels.items()
    }
    channel_percent = (
        channels.get(_payload_value(incident.raw_payload or {}, "channel", "transaction_channel"), 0)
        / channel_count * 100
        if channel_count else None
    )
    origins = Counter(item["location"] for item in historical if item["location"])
    top_origins = origins.most_common(5)
    current_location = next((item["location"] for item in transactions if item["is_incident"]), None)
    current_channel = _payload_value(incident.raw_payload or {}, "channel", "transaction_channel")

    similar = comparable[-5:]
    prior_24h = [
        item for item in historical
        if item["timestamp"]
        and datetime.fromisoformat(item["timestamp"]) >= timestamp - timedelta(hours=24)
    ]
    profiles = {
        "account_name": _payload_value(
            incident.raw_payload or {}, "user_full_name", "client_name", "customer_name", "full_name", "name"
        ),
        "account_age_days": _payload_value(incident.raw_payload or {}, "account_age_days", "account_age"),
        "source_accounts": sorted({item["source_account"] for item in transactions if item["source_account"]}),
        "devices": sorted({item["device_name"] or item["device_id"] for item in transactions if item["device_name"] or item["device_id"]}),
        "known_ips": sorted({item["ip_address"] for item in transactions if item["ip_address"]}),
        "transaction_count": len(transactions),
        "transaction_volume": round(sum(item["amount"] for item in transactions), 2),
        "average_transaction": round(sum(item["amount"] for item in transactions) / len(transactions), 2) if transactions else None,
        "transaction_types": dict(Counter(item["transaction_type"] for item in transactions if item["transaction_type"])),
        "channels": dict(all_channels),
        "typical_locations": [{"location": location, "count": count} for location, count in top_origins],
    }

    findings: list[dict[str, Any]] = []
    if comparable:
        ids = [item["transaction_id"] for item in similar]
        findings.append({
            "finding": "Transaction amount compared with same-type historical activity",
            "status": "supported" if len(comparable) >= 3 else "limited_history",
            "summary": (
                f"Current {incident.transaction_type} amount {float(incident.amount):,.2f}; "
                f"historical mean {amount_average:,.2f} across {len(comparable)} prior same-type transactions."
            ),
            "historical_mean": round(amount_average, 2) if amount_average is not None else None,
            "variance_percent": round(amount_variance, 2) if amount_variance is not None else None,
            "supporting_transaction_ids": ids,
        })
    else:
        findings.append({
            "finding": "Insufficient same-type history for an amount baseline",
            "status": "insufficient_history",
            "summary": "No prior transaction of this type was found in the selected dataset and lookback window.",
            "historical_mean": None,
            "variance_percent": None,
            "supporting_transaction_ids": [],
        })

    if current_location and top_origins:
        typical_locations = {location for location, _ in top_origins}
        differs = current_location not in typical_locations
        findings.append({
            "finding": "Transaction origin compared with historical locations",
            "status": "location_change" if differs else "consistent_with_history",
            "summary": (
                f"Current origin is {current_location}; historical origins are "
                f"{', '.join(location for location, _ in top_origins)}."
            ),
            "historical_origins": [location for location, _ in top_origins],
            "current_origin": current_location,
            "supporting_transaction_ids": [
                item["transaction_id"] for item in historical if item["location"] in typical_locations
            ][-5:],
        })

    return {
        "lookback_days": lookback_days,
        "cutoff": cutoff.isoformat(),
        "as_of": timestamp.isoformat(),
        "tenant_id": incident.tenant_id,
        "dataset_source": incident.dataset_source,
        "dataset_id": incident.dataset_id,
        "historical_transaction_count": len(historical),
        "transaction_count": len(historical) + 1,
        "truncated": truncated,
        "transactions": transactions,
        "activity": {
            "daily_counts": [
                {
                    "date": day,
                    "count": count,
                    "contains_incident": day in incident_activity_dates,
                }
                for day, count in sorted(daily_activity.items())
            ],
            "velocity_24h_series": velocity_series,
        },
        "baseline": {
            "comparable_transaction_count": len(comparable),
            "transaction_type": incident.transaction_type,
            "average_amount": round(amount_average, 2) if amount_average is not None else None,
            "current_amount": float(incident.amount),
            "amount_variance_percent": round(amount_variance, 2) if amount_variance is not None else None,
            "channel_counts": dict(channels),
            "channel_usage": channel_usage,
            "current_channel": current_channel,
            "current_channel_percent": round(channel_percent, 1) if channel_percent is not None else None,
            "typical_locations": [{"location": location, "count": count} for location, count in top_origins],
            "current_location": current_location,
            "velocity_24h": len(prior_24h),
            "similar_transactions": similar,
        },
        "profile": profiles,
        "findings": findings,
    }

from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, g

from auth_middleware import token_required
from database import security_logs_collection


security_bp = Blueprint(
    "security",
    __name__,
    url_prefix="/api/security"
)


@security_bp.route("/logs", methods=["GET"])
@token_required
def get_security_logs():
    logs_cursor = security_logs_collection.find(
        {"user_id": g.current_user["id"]}
    ).sort("timestamp", -1).limit(100)

    logs = []

    for record in logs_cursor:
        timestamp = record.get("timestamp")

        logs.append({
            "event": record.get("event", "UNKNOWN"),
            "file_id": record.get("file_id"),
            "timestamp": timestamp.isoformat() if timestamp else None,
            "details": record.get("details", "")
        })

    return jsonify({
        "message": "Security logs retrieved successfully.",
        "count": len(logs),
        "logs": logs
    }), 200


@security_bp.route("/alerts", methods=["GET"])
@token_required
def get_security_alerts():
    user_id = g.current_user["id"]

    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=10)

    recent_events = list(
        security_logs_collection.find({
            "user_id": user_id,
            "timestamp": {"$gte": cutoff_time}
        })
    )

    denied_attempts = [
        event for event in recent_events
        if event.get("event") == "FILE_ACCESS_DENIED"
    ]

    integrity_failures = [
        event for event in recent_events
        if event.get("event") == "FILE_INTEGRITY_FAILURE"
    ]

    alerts = []

    if len(denied_attempts) >= 3:
        alerts.append({
            "type": "REPEATED_ACCESS_DENIAL",
            "severity": "HIGH",
            "count": len(denied_attempts),
            "message": (
                "Three or more file-access attempts were denied "
                "within the last 10 minutes."
            )
        })

    if integrity_failures:
        alerts.append({
            "type": "FILE_INTEGRITY_FAILURE",
            "severity": "HIGH",
            "count": len(integrity_failures),
            "message": (
                "One or more file-integrity failures were recorded "
                "within the last 10 minutes."
            )
        })

    return jsonify({
        "message": "Threat detection completed.",
        "checked_events": len(recent_events),
        "alert_count": len(alerts),
        "alerts": alerts
    }), 200
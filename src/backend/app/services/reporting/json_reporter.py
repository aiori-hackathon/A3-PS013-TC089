"""Forensic JSON report generator."""

import json
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from app.config import settings
from app.models.models import (
    Investigation,
    EvidenceFile,
    Event,
    DetectionAlert,
    InvestigationReport,
    generate_uuid,
)


def generate_json_report(investigation_id: str, db: Session) -> InvestigationReport:
    """Export complete investigation data to a forensic JSON report."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise ValueError(f"Investigation {investigation_id} not found.")

    evidence_items = db.query(EvidenceFile).filter(EvidenceFile.investigation_id == investigation_id).all()
    events = (
        db.query(Event)
        .filter(Event.investigation_id == investigation_id)
        .order_by(Event.normalized_timestamp.asc().nulls_last())
        .all()
    )
    alerts = db.query(DetectionAlert).filter(DetectionAlert.investigation_id == investigation_id).all()

    report_data = {
        "report_metadata": {
            "platform": "VIGILANCE Digital Forensics",
            "report_format": "JSON",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "version": "1.0",
        },
        "investigation": {
            "id": inv.id,
            "name": inv.name,
            "description": inv.description,
            "category": inv.category,
            "status": inv.status,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
            "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
        },
        "evidence_inventory": [
            {
                "id": ev.id,
                "original_filename": ev.original_filename,
                "file_size": ev.file_size,
                "sha256_hash": ev.sha256_hash,
                "upload_timestamp": ev.upload_timestamp.isoformat() if ev.upload_timestamp else None,
                "source_system": ev.source_system,
                "source_category": ev.source_category,
                "file_format": ev.file_format,
                "processing_status": ev.processing_status,
                "timezone_hint": ev.timezone_hint,
            }
            for ev in evidence_items
        ],
        "detection_alerts": [
            {
                "id": a.id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "explanation": a.explanation,
                "alert_type": a.alert_type,
                "event_ids": json.loads(a.event_ids) if a.event_ids else [],
                "ip_addresses": json.loads(a.ip_addresses) if a.ip_addresses else [],
                "usernames": json.loads(a.usernames) if a.usernames else [],
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in alerts
        ],
        "timeline_events": [
            {
                "id": e.id,
                "evidence_id": e.evidence_id,
                "source_system": e.source_system,
                "original_timestamp": e.original_timestamp,
                "normalized_timestamp": e.normalized_timestamp.isoformat() if e.normalized_timestamp else None,
                "timestamp_status": e.timestamp_status,
                "event_type": e.event_type,
                "event_category": e.event_category,
                "username": e.username,
                "source_ip": e.source_ip,
                "dest_ip": e.dest_ip,
                "severity": e.severity,
                "description": e.description,
                "parsing_status": e.parsing_status,
                "extra_fields": json.loads(e.extra_fields) if e.extra_fields else None,
            }
            for e in events
        ],
    }

    reports_dir = Path(settings.REPORTS_PATH)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_filename = f"report_{inv.id[:8]}_{timestamp_str}.json"
    report_path = reports_dir / report_filename

    json_str = json.dumps(report_data, indent=2, default=str)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(json_str)

    report_record = InvestigationReport(
        id=generate_uuid(),
        investigation_id=investigation_id,
        format="json",
        file_path=str(report_path.resolve()),
        generated_at=datetime.utcnow(),
        file_size=len(json_str.encode("utf-8")),
    )
    db.add(report_record)
    db.commit()
    db.refresh(report_record)

    return report_record

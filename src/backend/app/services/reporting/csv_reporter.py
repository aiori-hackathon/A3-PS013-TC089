"""Forensic CSV report generator for chronological event exports."""

import csv
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from app.config import settings
from app.models.models import (
    Investigation,
    Event,
    InvestigationReport,
    generate_uuid,
)


def generate_csv_report(investigation_id: str, db: Session) -> InvestigationReport:
    """Export complete forensic timeline to a standard CSV report."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise ValueError(f"Investigation {investigation_id} not found.")

    events = (
        db.query(Event)
        .filter(Event.investigation_id == investigation_id)
        .order_by(Event.normalized_timestamp.asc().nulls_last())
        .all()
    )

    reports_dir = Path(settings.REPORTS_PATH)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_filename = f"report_{inv.id[:8]}_{timestamp_str}.csv"
    report_path = reports_dir / report_filename

    fieldnames = [
        "event_id",
        "normalized_timestamp_utc",
        "timestamp_status",
        "original_timestamp",
        "severity",
        "event_category",
        "event_type",
        "source_ip",
        "dest_ip",
        "username",
        "source_system",
        "description",
        "parsing_status",
        "raw_record",
    ]

    with open(report_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in events:
            writer.writerow({
                "event_id": e.id,
                "normalized_timestamp_utc": e.normalized_timestamp.isoformat() if e.normalized_timestamp else "",
                "timestamp_status": e.timestamp_status,
                "original_timestamp": e.original_timestamp or "",
                "severity": e.severity,
                "event_category": e.event_category,
                "event_type": e.event_type or "",
                "source_ip": e.source_ip or "",
                "dest_ip": e.dest_ip or "",
                "username": e.username or "",
                "source_system": e.source_system or "",
                "description": e.description or "",
                "parsing_status": e.parsing_status,
                "raw_record": e.raw_record or "",
            })

    file_size = report_path.stat().st_size
    report_record = InvestigationReport(
        id=generate_uuid(),
        investigation_id=investigation_id,
        format="csv",
        file_path=str(report_path.resolve()),
        generated_at=datetime.utcnow(),
        file_size=file_size,
    )
    db.add(report_record)
    db.commit()
    db.refresh(report_record)

    return report_record

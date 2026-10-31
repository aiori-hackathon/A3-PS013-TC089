"""Forensic analysis, correlation, and detection alerts API routes."""

import json
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Investigation, DetectionAlert, AuditLog
from app.schemas.schemas import DetectionAlertResponse, AnalyzeResponse
from app.services.analysis.rule_engine import run_all_rules

router = APIRouter(tags=["Analysis & Alerts"])


def _alert_to_response(alert: DetectionAlert) -> DetectionAlertResponse:
    """Helper to convert DetectionAlert ORM model to response schema."""
    return DetectionAlertResponse(
        id=alert.id,
        investigation_id=alert.investigation_id,
        rule_name=alert.rule_name,
        severity=alert.severity,
        explanation=alert.explanation,
        event_ids=json.loads(alert.event_ids) if alert.event_ids else [],
        ip_addresses=json.loads(alert.ip_addresses) if alert.ip_addresses else [],
        usernames=json.loads(alert.usernames) if alert.usernames else [],
        created_at=alert.created_at,
        alert_type=alert.alert_type,
    )


@router.post("/investigations/{investigation_id}/analyze", response_model=AnalyzeResponse)
def analyze_investigation(investigation_id: str, db: Session = Depends(get_db)):
    """Execute all 7 cyber forensic correlation rules across unified investigation events."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' was not found."
        )

    alerts = run_all_rules(investigation_id, db)

    # Log audit
    audit = AuditLog(
        investigation_id=investigation_id,
        action="ANALYSIS_EXECUTED",
        actor="INVESTIGATOR",
        timestamp=datetime.utcnow(),
        details=json.dumps({
            "rules_evaluated": 7,
            "alerts_generated": len(alerts),
            "alert_severities": [a.severity for a in alerts],
        }),
    )
    db.add(audit)
    db.commit()

    return AnalyzeResponse(
        investigation_id=investigation_id,
        rules_evaluated=7,
        alerts_generated=len(alerts),
        alerts=[_alert_to_response(a) for a in alerts],
    )


@router.get("/investigations/{investigation_id}/alerts", response_model=List[DetectionAlertResponse])
def list_investigation_alerts(investigation_id: str, db: Session = Depends(get_db)):
    """List all correlation alerts generated for an investigation."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' was not found."
        )

    alerts = (
        db.query(DetectionAlert)
        .filter(DetectionAlert.investigation_id == investigation_id)
        .order_by(DetectionAlert.created_at.desc())
        .all()
    )
    return [_alert_to_response(a) for a in alerts]


@router.get("/alerts/{alert_id}", response_model=DetectionAlertResponse)
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    """Retrieve full details of a specific detection alert."""
    alert = db.query(DetectionAlert).filter(DetectionAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' was not found."
        )
    return _alert_to_response(alert)

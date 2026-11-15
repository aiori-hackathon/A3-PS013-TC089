"""Tests for the heuristic human-triage time estimator."""

from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.models import (
    DetectionAlert,
    Event,
    EvidenceFile,
    Investigation,
    ProcessingJob,
    generate_uuid,
)
from app.services.triage.human_estimator import HumanTriageEstimator
from app.services.triage.triage_service import TriageService


def _setup_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_estimate_scales_with_records_and_complexity():
    db = _setup_db()
    inv_id = generate_uuid()
    db.add(Investigation(id=inv_id, name="Estimator Test", status="ACTIVE"))

    evidence = EvidenceFile(
        id=generate_uuid(),
        investigation_id=inv_id,
        original_filename="app_events.json",
        stored_filename="stored.json",
        file_size=4096,
        sha256_hash="a" * 64,
        file_format="json",
        processing_status="COMPLETED",
        timezone_hint="+05:30",
    )
    db.add(evidence)

    started = datetime(2026, 1, 1, 12, 0, 0)
    job = ProcessingJob(
        id=generate_uuid(),
        evidence_id=evidence.id,
        investigation_id=inv_id,
        started_at=started,
        completed_at=started + timedelta(seconds=2),
        status="PARTIAL",
        total_records=1000,
        parsed_ok=995,
        parsed_partial=2,
        parsed_failed=0,
        missing_timestamps=3,
    )
    db.add(job)

    for status in ("CLOCK_SKEW_ADJUSTED", "SYSLOG_NO_YEAR", "UNCERTAIN"):
        db.add(
            Event(
                id=generate_uuid(),
                investigation_id=inv_id,
                evidence_id=evidence.id,
                timestamp_status=status,
                severity="HIGH",
                raw_record="test record",
            )
        )

    db.add(
        DetectionAlert(
            id=generate_uuid(),
            investigation_id=inv_id,
            rule_name="Test Rule",
            severity="HIGH",
            explanation="test alert",
            alert_type="TEST",
        )
    )
    db.commit()

    estimator = HumanTriageEstimator(db)
    estimate = estimator.estimate(inv_id)

    assert estimate["available"] is True
    assert estimate["records"] == 1000
    assert estimate["sources"] == 1
    assert estimate["findings"] == 1
    assert estimate["complexity"] == "HIGH"
    assert estimate["estimated_seconds"] > 0
    assert len(estimate["breakdown"]) == 6
    assert estimator.measured_pipeline_seconds(inv_id) == 2.0

    comparison = TriageService(db).calculate_comparison(inv_id)
    assert comparison["manual_is_estimated"] is True
    assert comparison["vigilance_is_estimated"] is True
    assert comparison["manual_duration_seconds"] == estimate["estimated_seconds"]
    assert comparison["vigilance_duration_seconds"] == 2.0
    assert comparison["estimation_method"] == estimate["method"]


def test_estimate_unavailable_without_evidence():
    db = _setup_db()
    inv_id = generate_uuid()
    db.add(Investigation(id=inv_id, name="Empty Estimator Test", status="ACTIVE"))
    db.commit()

    estimate = HumanTriageEstimator(db).estimate(inv_id)
    assert estimate["available"] is False
    assert estimate["estimated_seconds"] == 0.0
    assert HumanTriageEstimator(db).measured_pipeline_seconds(inv_id) is None

"""Triage performance measurement and benchmarking service."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.models import TriageMeasurement, generate_uuid
from app.schemas.schemas import TriageMeasurementCreate
from app.services.triage.human_estimator import HumanTriageEstimator


class TriageService:
    """Manages triage performance tracking and benchmark comparisons."""

    def __init__(self, db: Session):
        self.db = db

    def record_measurement(
        self,
        investigation_id: str,
        data: TriageMeasurementCreate
    ) -> TriageMeasurement:
        """Create a new triage time and accuracy measurement."""
        duration = max(0.0, (data.end_time - data.start_time).total_seconds())

        measurement = TriageMeasurement(
            id=generate_uuid(),
            investigation_id=investigation_id,
            method=data.method.upper(),
            scenario=data.scenario,
            start_time=data.start_time,
            end_time=data.end_time,
            duration_seconds=duration,
            events_identified=data.events_identified,
            records_processed=data.records_processed,
            notes=data.notes,
            created_at=datetime.utcnow(),
        )
        self.db.add(measurement)
        self.db.commit()
        self.db.refresh(measurement)
        return measurement

    def get_measurements(self, investigation_id: str) -> List[TriageMeasurement]:
        """List all measurements for an investigation."""
        return (
            self.db.query(TriageMeasurement)
            .filter(TriageMeasurement.investigation_id == investigation_id)
            .order_by(TriageMeasurement.created_at.asc())
            .all()
        )

    def calculate_comparison(self, investigation_id: str) -> Dict[str, Any]:
        """Compute comparative time reduction and speedup factor between MANUAL and VIGILANCE triage.

        If a MANUAL measurement has not been supplied, a transparent human-effort
        estimate is derived from the ingested logs. If a VIGILANCE measurement has
        not been supplied, the real ingestion/parsing duration is used instead.
        """
        measurements = self.get_measurements(investigation_id)

        manual = next((m for m in reversed(measurements) if m.method == "MANUAL"), None)
        vigilance = next((m for m in reversed(measurements) if m.method == "VIGILANCE"), None)

        estimator = HumanTriageEstimator(self.db)
        estimate = estimator.estimate(investigation_id)
        measured_pipeline = estimator.measured_pipeline_seconds(investigation_id)

        manual_sec = (
            manual.duration_seconds
            if manual
            else (estimate["estimated_seconds"] if estimate.get("available") else None)
        )
        vig_sec = vigilance.duration_seconds if vigilance else measured_pipeline

        manual_is_estimated = manual is None and manual_sec is not None
        vigilance_is_estimated = vigilance is None and vig_sec is not None

        scenario_name = (
            manual.scenario
            if manual
            else (vigilance.scenario if vigilance else "Auto-estimated manual triage")
        )

        manual_events = (
            manual.events_identified
            if manual
            else (estimate.get("findings") if estimate.get("available") else None)
        )
        vigilance_events = (
            vigilance.events_identified
            if vigilance
            else (estimate.get("findings") if estimate.get("available") else None)
        )

        comparison: Dict[str, Any] = {
            "scenario": scenario_name,
            "investigation_id": investigation_id,
            "manual_duration_seconds": round(manual_sec, 2) if manual_sec is not None else None,
            "vigilance_duration_seconds": round(vig_sec, 2) if vig_sec is not None else None,
            "time_saved_seconds": None,
            "speedup_factor": None,
            "efficiency_gain_percent": None,
            "manual_events_identified": manual_events,
            "vigilance_events_identified": vigilance_events,
            "manual_is_estimated": manual_is_estimated,
            "vigilance_is_estimated": vigilance_is_estimated,
            "estimation_method": (
                estimate.get("method") if manual_is_estimated else None
            ),
        }

        if manual_sec is None or vig_sec is None:
            return comparison

        time_saved = max(0.0, manual_sec - vig_sec)
        speedup = round(manual_sec / vig_sec, 2) if vig_sec > 0 else 1.0
        efficiency_gain = round((time_saved / manual_sec) * 100.0, 1) if manual_sec > 0 else 0.0

        comparison.update(
            {
                "time_saved_seconds": round(time_saved, 2),
                "speedup_factor": speedup,
                "efficiency_gain_percent": efficiency_gain,
            }
        )
        return comparison

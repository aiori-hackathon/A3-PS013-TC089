"""Triage performance measurement and benchmarking service."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.models import TriageMeasurement, generate_uuid
from app.schemas.schemas import TriageMeasurementCreate


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
        """Compute comparative time reduction and speedup factor between MANUAL and VIGILANCE triage."""
        measurements = self.get_measurements(investigation_id)

        manual = next((m for m in reversed(measurements) if m.method == "MANUAL"), None)
        vigilance = next((m for m in reversed(measurements) if m.method == "VIGILANCE"), None)

        scenario_name = manual.scenario if manual else (vigilance.scenario if vigilance else "Investigation Triage")

        if not manual or not vigilance:
            return {
                "scenario": scenario_name,
                "investigation_id": investigation_id,
                "manual_duration_seconds": manual.duration_seconds if manual else None,
                "vigilance_duration_seconds": vigilance.duration_seconds if vigilance else None,
                "time_saved_seconds": None,
                "speedup_factor": None,
                "efficiency_gain_percent": None,
                "manual_events_identified": manual.events_identified if manual else None,
                "vigilance_events_identified": vigilance.events_identified if vigilance else None,
            }

        manual_sec = manual.duration_seconds
        vig_sec = vigilance.duration_seconds

        time_saved = max(0.0, manual_sec - vig_sec)
        speedup = round(manual_sec / vig_sec, 2) if vig_sec > 0 else 1.0
        efficiency_gain = round((time_saved / manual_sec) * 100.0, 1) if manual_sec > 0 else 0.0

        return {
            "scenario": scenario_name,
            "investigation_id": investigation_id,
            "manual_duration_seconds": manual_sec,
            "vigilance_duration_seconds": vig_sec,
            "time_saved_seconds": round(time_saved, 2),
            "speedup_factor": speedup,
            "efficiency_gain_percent": efficiency_gain,
            "manual_events_identified": manual.events_identified,
            "vigilance_events_identified": vigilance.events_identified,
        }

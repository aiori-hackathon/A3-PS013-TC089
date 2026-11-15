"""Heuristic model for estimating how long a human analyst would need to triage logs.

The model is intentionally transparent and additive. Each component maps to a
recognisable phase of manual log triage so the estimate can be explained to an
investigator rather than presented as an opaque number.

Calibration anchors drawn from published DFIR/SOC guidance:
- Manual log review runs at roughly 2,000-3,600 records/hour when grep-assisted,
  dropping sharply when records must be re-parsed or normalised by hand.
- Analysts spend roughly 3-5 seconds on an already-classified alert, but much
  longer (tens of seconds to minutes) validating a forensic finding.
- SANS FOR508-style manual investigations of a single host average 4-8 hours,
  dominated by fixed overhead (tooling, normalisation, correlation, reporting).
"""

from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.models import DetectionAlert, Event, EvidenceFile, ProcessingJob

# --- Phase constants (seconds) ---
_SCHEMA_FAMILIARIZATION_PER_SOURCE = 180.0
_BASE_NORMALIZATION_PER_SOURCE = 60.0
_RECORD_REVIEW_PER_RECORD = 1.2
_CORRELATION_PER_SOURCE = 120.0
_FINDING_VALIDATION_PER_FINDING = 45.0
_REPORT_BASE = 300.0
_REPORT_PER_SOURCE = 60.0

# --- Complexity penalties (seconds) ---
_TIMEZONE_PENALTY = 180.0
_SYSLOG_YEAR_PENALTY = 120.0
_CLOCK_SKEW_PENALTY = 180.0
_UNCERTAIN_TS_PENALTY = 60.0
_MISSING_TS_PENALTY = 30.0
_MALFORMED_RECORD_PENALTY = 20.0

# --- Caps so a noisy artefact cannot dominate the whole estimate ---
_MAX_TS_PENALTY = 1800.0
_MAX_MALFORMED_PENALTY = 900.0
_MIN_ESTIMATE = 120.0

_UTC_TIMEZONE_HINTS = {
    None,
    "",
    "UTC",
    "utc",
    "Z",
    "GMT",
    "+00:00",
    "-00:00",
    "Etc/UTC",
    "UTC+0",
    "UTC-0",
}


class HumanTriageEstimator:
    """Estimate manual human triage effort for an investigation's ingested logs."""

    def __init__(self, db: Session):
        self.db = db

    def measured_pipeline_seconds(self, investigation_id: str) -> Optional[float]:
        """Sum real ingestion/parsing durations recorded by the pipeline."""
        jobs = (
            self.db.query(ProcessingJob)
            .filter(ProcessingJob.investigation_id == investigation_id)
            .all()
        )
        total = 0.0
        measured = False
        for job in jobs:
            if job.started_at and job.completed_at:
                delta = (job.completed_at - job.started_at).total_seconds()
                if delta >= 0:
                    total += delta
                    measured = True
        return round(total, 3) if measured else None

    def _timestamp_status_counts(self, investigation_id: str) -> Dict[str, int]:
        rows = (
            self.db.query(Event.timestamp_status, func.count())
            .filter(Event.investigation_id == investigation_id)
            .group_by(Event.timestamp_status)
            .all()
        )
        return {(status or "UNKNOWN"): count for status, count in rows}

    def estimate(self, investigation_id: str) -> Dict[str, Any]:
        evidence = (
            self.db.query(EvidenceFile)
            .filter(EvidenceFile.investigation_id == investigation_id)
            .all()
        )
        jobs = (
            self.db.query(ProcessingJob)
            .filter(ProcessingJob.investigation_id == investigation_id)
            .all()
        )
        ts_counts = self._timestamp_status_counts(investigation_id)

        alert_count = (
            self.db.query(func.count())
            .select_from(DetectionAlert)
            .filter(DetectionAlert.investigation_id == investigation_id)
            .scalar()
            or 0
        )
        suspicious_count = (
            self.db.query(func.count())
            .select_from(Event)
            .filter(
                Event.investigation_id == investigation_id,
                Event.severity.in_(["HIGH", "CRITICAL"]),
            )
            .scalar()
            or 0
        )
        event_count = sum(ts_counts.values())

        records = sum(job.total_records or 0 for job in jobs)
        if records <= 0:
            records = event_count

        if records <= 0 and not evidence:
            return {
                "available": False,
                "estimated_seconds": 0.0,
                "estimated_minutes": 0.0,
                "records": 0,
                "sources": 0,
                "findings": 0,
                "complexity": "LOW",
                "confidence": "LOW",
                "breakdown": [],
                "assumptions": ["No ingested evidence is available for this investigation yet."],
                "method": "Heuristic manual-triage model v1",
            }

        sources = max(1, len(evidence))
        findings = alert_count if alert_count > 0 else suspicious_count
        malformed = sum((job.parsed_failed or 0) + (job.parsed_partial or 0) for job in jobs)
        missing_ts = sum(job.missing_timestamps or 0 for job in jobs)
        tz_sources = sum(
            1 for e in evidence if (e.timezone_hint or None) not in _UTC_TIMEZONE_HINTS
        )

        setup = sources * _SCHEMA_FAMILIARIZATION_PER_SOURCE

        normalization = sources * _BASE_NORMALIZATION_PER_SOURCE
        normalization += tz_sources * _TIMEZONE_PENALTY
        if ts_counts.get("SYSLOG_NO_YEAR"):
            normalization += _SYSLOG_YEAR_PENALTY
        if ts_counts.get("CLOCK_SKEW_ADJUSTED"):
            normalization += _CLOCK_SKEW_PENALTY
        normalization += min(
            ts_counts.get("UNCERTAIN", 0) * _UNCERTAIN_TS_PENALTY, _MAX_TS_PENALTY
        )
        normalization += min(missing_ts * _MISSING_TS_PENALTY, _MAX_TS_PENALTY)
        normalization += min(malformed * _MALFORMED_RECORD_PENALTY, _MAX_MALFORMED_PENALTY)

        correlation = (
            sources
            * _CORRELATION_PER_SOURCE
            * (1.0 + 0.15 * max(0, sources - 1))
        )

        scan = records * _RECORD_REVIEW_PER_RECORD
        validation = findings * _FINDING_VALIDATION_PER_FINDING
        reporting = _REPORT_BASE + sources * _REPORT_PER_SOURCE

        total = max(
            _MIN_ESTIMATE,
            setup + normalization + correlation + scan + validation + reporting,
        )

        complexity_score = (
            (1 if sources > 1 else 0)
            + (1 if tz_sources else 0)
            + (1 if ts_counts.get("SYSLOG_NO_YEAR") else 0)
            + (1 if ts_counts.get("CLOCK_SKEW_ADJUSTED") else 0)
            + (1 if ts_counts.get("UNCERTAIN") else 0)
            + (1 if missing_ts else 0)
            + (1 if malformed else 0)
        )
        if complexity_score <= 1:
            complexity = "LOW"
        elif complexity_score <= 3:
            complexity = "MEDIUM"
        else:
            complexity = "HIGH"

        if records > 0 and jobs:
            confidence = "HIGH"
        elif event_count > 0:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        breakdown: List[Dict[str, Any]] = [
            {
                "phase": "Schema familiarisation & tooling",
                "seconds": round(setup, 1),
                "detail": f"{sources} source(s) x ~3 min",
            },
            {
                "phase": "Timestamp normalisation & cleanup",
                "seconds": round(normalization, 1),
                "detail": self._normalization_detail(tz_sources, ts_counts, missing_ts, malformed),
            },
            {
                "phase": "Cross-source correlation",
                "seconds": round(correlation, 1),
                "detail": f"{sources} source(s), correlation compounds with each added source",
            },
            {
                "phase": "Manual record review",
                "seconds": round(scan, 1),
                "detail": f"{records:,} record(s) at ~1.2 s each",
            },
            {
                "phase": "Finding validation",
                "seconds": round(validation, 1),
                "detail": f"{findings} finding(s) at ~45 s each",
            },
            {
                "phase": "Timeline & report write-up",
                "seconds": round(reporting, 1),
                "detail": "Fixed write-up plus per-source documentation",
            },
        ]

        return {
            "available": True,
            "estimated_seconds": round(total, 1),
            "estimated_minutes": round(total / 60.0, 1),
            "records": records,
            "sources": sources,
            "findings": findings,
            "complexity": complexity,
            "confidence": confidence,
            "breakdown": breakdown,
            "assumptions": [
                "Single analyst working manually with grep, spreadsheets and ad-hoc scripts.",
                "Record review at ~1.2 s/record; findings validated at ~45 s each.",
                "Fixed overhead included for tooling, normalisation, correlation and reporting.",
                "Automated matching, deduplication and tool shortcuts would reduce this time.",
            ],
            "method": "Heuristic manual-triage model v1",
        }

    @staticmethod
    def _normalization_detail(
        tz_sources: int,
        ts_counts: Dict[str, int],
        missing_ts: int,
        malformed: int,
    ) -> str:
        reasons = []
        if tz_sources:
            reasons.append(f"{tz_sources} non-UTC source(s)")
        if ts_counts.get("SYSLOG_NO_YEAR"):
            reasons.append("year reconstruction from year-less syslog")
        if ts_counts.get("CLOCK_SKEW_ADJUSTED"):
            reasons.append("clock-skew reconciliation")
        if ts_counts.get("UNCERTAIN"):
            reasons.append(f"{ts_counts['UNCERTAIN']} uncertain timestamp(s)")
        if missing_ts:
            reasons.append(f"{missing_ts} missing timestamp(s)")
        if malformed:
            reasons.append(f"{malformed} malformed/partial record(s)")
        return ", ".join(reasons) if reasons else "Standard UTC normalisation"

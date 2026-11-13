"""Forensic timeline aggregation and query builder."""

import json
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc, asc

from app.models.models import Event


class TimelineBuilder:
    """Constructs and queries unified forensic timelines across disparate evidence sources."""

    def __init__(self, db: Session):
        self.db = db

    def query_timeline(
        self,
        investigation_id: str,
        search: Optional[str] = None,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        source_system: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        sort_asc: bool = True,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[Event], int, int]:
        """Query unified timeline with multi-dimensional forensic filtering and pagination.

        Returns: (events, total_count, total_pages)
        """
        query = self.db.query(Event).filter(Event.investigation_id == investigation_id)

        # Filters
        if search:
            search_pattern = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    Event.description.ilike(search_pattern),
                    Event.raw_record.ilike(search_pattern),
                    Event.username.ilike(search_pattern),
                    Event.source_ip.ilike(search_pattern),
                    Event.dest_ip.ilike(search_pattern),
                    Event.event_type.ilike(search_pattern),
                )
            )

        if source_ip:
            query = query.filter(Event.source_ip == source_ip.strip())

        if username:
            query = query.filter(Event.username == username.strip())

        if category:
            query = query.filter(Event.event_category == category.strip())

        if severity:
            query = query.filter(Event.severity == severity.strip().upper())

        if source_system:
            query = query.filter(Event.source_system == source_system.strip())

        if start_date:
            query = query.filter(Event.normalized_timestamp >= start_date)

        if end_date:
            query = query.filter(Event.normalized_timestamp <= end_date)

        # Sorting: primary normalized_timestamp, secondary original_timestamp
        if sort_asc:
            query = query.order_by(
                Event.normalized_timestamp.asc().nulls_last(),
                Event.id.asc()
            )
        else:
            query = query.order_by(
                Event.normalized_timestamp.desc().nulls_last(),
                Event.id.desc()
            )

        total_count = query.count()
        total_pages = max(1, (total_count + page_size - 1) // page_size) if total_count > 0 else 1

        offset = max(0, (page - 1) * page_size)
        events = query.offset(offset).limit(page_size).all()

        return events, total_count, total_pages

    def get_processing_summary(self, investigation_id: str) -> Dict[str, Any]:
        """Aggregate forensic parsing, timestamp, and severity metrics for an investigation."""
        events = self.db.query(Event).filter(Event.investigation_id == investigation_id).all()

        status_counts = {"OK": 0, "PARTIAL": 0, "FAILED": 0}
        ts_counts: Dict[str, int] = {}
        sev_counts: Dict[str, int] = {}
        cat_counts: Dict[str, int] = {}

        for ev in events:
            # Parsing status
            status_counts[ev.parsing_status] = status_counts.get(ev.parsing_status, 0) + 1

            # Timestamp status
            ts_counts[ev.timestamp_status] = ts_counts.get(ev.timestamp_status, 0) + 1

            # Severity
            sev_counts[ev.severity] = sev_counts.get(ev.severity, 0) + 1

            # Category
            cat_counts[ev.event_category] = cat_counts.get(ev.event_category, 0) + 1

        from app.models.models import EvidenceFile
        evidence_count = self.db.query(EvidenceFile).filter(EvidenceFile.investigation_id == investigation_id).count()

        return {
            "investigation_id": investigation_id,
            "total_evidence_files": evidence_count,
            "total_events": len(events),
            "status_counts": status_counts,
            "timestamp_status_counts": ts_counts,
            "severity_counts": sev_counts,
            "category_counts": cat_counts,
            "total_files": evidence_count,
            "total_records": len(events),
            "parsed_ok": status_counts.get("OK", 0),
            "parsed_partial": status_counts.get("PARTIAL", 0),
            "parsed_failed": status_counts.get("FAILED", 0),
            "missing_timestamps": ts_counts.get("MISSING", 0),
        }

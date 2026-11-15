"""Forensic timeline aggregation and query builder."""

import json
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc, asc

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
        filters = [Event.investigation_id == investigation_id]

        # Filters
        if search:
            search_pattern = f"%{search.strip()}%"
            filters.append(
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
            filters.append(Event.source_ip == source_ip.strip())

        if username:
            filters.append(Event.username == username.strip())

        if category:
            filters.append(Event.event_category == category.strip())

        if severity:
            filters.append(Event.severity == severity.strip().upper())

        if source_system:
            filters.append(Event.source_system == source_system.strip())

        if start_date:
            filters.append(Event.normalized_timestamp >= start_date)

        if end_date:
            filters.append(Event.normalized_timestamp <= end_date)

        # COUNT(*) can use covering indexes; COUNT(id) forces row lookups on SQLite.
        total_count = (
            self.db.query(func.count())
            .select_from(Event)
            .filter(*filters)
            .scalar()
            or 0
        )
        total_pages = max(1, (total_count + page_size - 1) // page_size) if total_count > 0 else 1

        query = self.db.query(Event).filter(*filters)

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

        offset = max(0, (page - 1) * page_size)
        events = query.offset(offset).limit(page_size).all()

        return events, total_count, total_pages

    def get_processing_summary(self, investigation_id: str) -> Dict[str, Any]:
        """Aggregate forensic parsing metrics with SQL GROUP BY, never loading full events."""
        from app.models.models import EvidenceFile

        base_filter = Event.investigation_id == investigation_id

        def grouped(column):
            rows = (
                self.db.query(column, func.count())
                .select_from(Event)
                .filter(base_filter)
                .group_by(column)
                .all()
            )
            return {key or "UNKNOWN": count for key, count in rows}

        total_events = (
            self.db.query(func.count())
            .select_from(Event)
            .filter(base_filter)
            .scalar()
            or 0
        )
        evidence_count = (
            self.db.query(func.count())
            .select_from(EvidenceFile)
            .filter(EvidenceFile.investigation_id == investigation_id)
            .scalar()
            or 0
        )

        status_counts = {"OK": 0, "PARTIAL": 0, "FAILED": 0}
        status_counts.update(grouped(Event.parsing_status))
        ts_counts = grouped(Event.timestamp_status)
        sev_counts = grouped(Event.severity)
        cat_counts = grouped(Event.event_category)

        return {
            "investigation_id": investigation_id,
            "total_evidence_files": evidence_count,
            "total_events": total_events,
            "status_counts": status_counts,
            "timestamp_status_counts": ts_counts,
            "severity_counts": sev_counts,
            "category_counts": cat_counts,
            "total_files": evidence_count,
            "total_records": total_events,
            "parsed_ok": status_counts.get("OK", 0),
            "parsed_partial": status_counts.get("PARTIAL", 0),
            "parsed_failed": status_counts.get("FAILED", 0),
            "missing_timestamps": ts_counts.get("MISSING", 0),
        }

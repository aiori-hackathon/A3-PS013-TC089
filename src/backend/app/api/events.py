"""Forensic event timeline, filtering, and processing summary API routes."""

import json
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Event, Investigation
from app.schemas.schemas import (
    EventResponse,
    PaginatedEventsResponse,
    ProcessingSummaryResponse,
)
from app.services.timeline.timeline_builder import TimelineBuilder

router = APIRouter(tags=["Events & Timeline"])


def _event_to_response(e: Event) -> EventResponse:
    """Helper to convert Event ORM model to EventResponse schema."""
    extra = None
    if e.extra_fields:
        try:
            extra = json.loads(e.extra_fields)
        except Exception:
            extra = {"raw_extra": e.extra_fields}

    return EventResponse(
        id=e.id,
        investigation_id=e.investigation_id,
        evidence_id=e.evidence_id,
        source_system=e.source_system,
        original_timestamp=e.original_timestamp,
        normalized_timestamp=e.normalized_timestamp,
        timestamp_status=e.timestamp_status,
        event_type=e.event_type,
        event_category=e.event_category,
        username=e.username,
        source_ip=e.source_ip,
        dest_ip=e.dest_ip,
        severity=e.severity,
        description=e.description,
        raw_record=e.raw_record,
        parsing_status=e.parsing_status,
        extra_fields=extra,
    )


@router.get("/investigations/{investigation_id}/events", response_model=PaginatedEventsResponse)
def get_investigation_events(
    investigation_id: str,
    search: Optional[str] = Query(None, description="Keyword search across description, raw text, and IPs"),
    ip: Optional[str] = Query(None, description="Filter by source IP"),
    username: Optional[str] = Query(None, description="Filter by targeted username"),
    category: Optional[str] = Query(None, description="Filter by normalized event category"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    source: Optional[str] = Query(None, description="Filter by source system"),
    start_date: Optional[datetime] = Query(None, description="UTC start datetime filter"),
    end_date: Optional[datetime] = Query(None, description="UTC end datetime filter"),
    sort_asc: bool = Query(True, description="Sort chronologically ascending"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Page size"),
    db: Session = Depends(get_db)
):
    """Retrieve filtered, paginated forensic event logs for an investigation."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found."
        )

    builder = TimelineBuilder(db)
    events, total_count, total_pages = builder.query_timeline(
        investigation_id=investigation_id,
        search=search,
        source_ip=ip,
        username=username,
        category=category,
        severity=severity,
        source_system=source,
        start_date=start_date,
        end_date=end_date,
        sort_asc=sort_asc,
        page=page,
        page_size=page_size,
    )

    return PaginatedEventsResponse(
        total=total_count,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        events=[_event_to_response(e) for e in events],
    )


@router.get("/investigations/{investigation_id}/timeline", response_model=PaginatedEventsResponse)
def get_investigation_timeline(
    investigation_id: str,
    search: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    sort_asc: bool = Query(True),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db)
):
    """Retrieve chronological unified forensic timeline optimized for timeline visualization."""
    return get_investigation_events(
        investigation_id=investigation_id,
        search=search,
        ip=ip,
        username=username,
        category=category,
        severity=severity,
        source=source,
        start_date=start_date,
        end_date=end_date,
        sort_asc=sort_asc,
        page=page,
        page_size=page_size,
        db=db,
    )


@router.get("/events/{event_id}", response_model=EventResponse)
def get_event_detail(event_id: str, db: Session = Depends(get_db)):
    """Retrieve full forensic details of a single event."""
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' was not found."
        )
    return _event_to_response(event)


@router.get("/investigations/{investigation_id}/processing-summary", response_model=ProcessingSummaryResponse)
def get_processing_summary(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve comprehensive parsing statistics and timestamp validation status breakdown."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found."
        )

    builder = TimelineBuilder(db)
    summary = builder.get_processing_summary(investigation_id)
    return ProcessingSummaryResponse(**summary)

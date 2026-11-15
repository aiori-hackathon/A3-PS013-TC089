"""Triage measurement, telemetry, and forensic benchmarking API routes."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.cache import invalidate_cache
from app.models.models import Investigation
from app.schemas.schemas import (
    HumanTriageEstimateResponse,
    TriageMeasurementCreate,
    TriageMeasurementResponse,
    TriageComparisonResponse,
)
from app.services.triage.human_estimator import HumanTriageEstimator
from app.services.triage.triage_service import TriageService

router = APIRouter(tags=["Triage Benchmarking"])


@router.post(
    "/investigations/{investigation_id}/triage",
    response_model=TriageMeasurementResponse,
    status_code=status.HTTP_201_CREATED
)
def record_triage_measurement(
    investigation_id: str,
    payload: TriageMeasurementCreate,
    db: Session = Depends(get_db)
):
    """Record a triage timing and accuracy benchmark measurement (MANUAL vs VIGILANCE)."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' was not found."
        )

    service = TriageService(db)
    record = service.record_measurement(investigation_id, payload)
    invalidate_cache()
    return record


@router.get("/investigations/{investigation_id}/triage", response_model=List[TriageMeasurementResponse])
def list_triage_measurements(investigation_id: str, db: Session = Depends(get_db)):
    """List all triage timing and benchmark records for an investigation."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' was not found."
        )

    service = TriageService(db)
    return service.get_measurements(investigation_id)


@router.get("/investigations/{investigation_id}/triage/comparison", response_model=TriageComparisonResponse)
def get_triage_comparison(investigation_id: str, db: Session = Depends(get_db)):
    """Calculate comparative forensic triage efficiency (time saved, speedup factor, accuracy)."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' was not found."
        )

    service = TriageService(db)
    comparison = service.calculate_comparison(investigation_id)
    return TriageComparisonResponse(**comparison)


@router.get("/investigations/{investigation_id}/triage/estimate", response_model=HumanTriageEstimateResponse)
def get_human_triage_estimate(investigation_id: str, db: Session = Depends(get_db)):
    """Estimate the manual human effort required to triage this investigation's logs.

    The estimate is derived from log volume, number of sources, timestamp
    normalisation difficulty, malformed records and detected findings.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' was not found."
        )

    estimator = HumanTriageEstimator(db)
    return HumanTriageEstimateResponse(**estimator.estimate(investigation_id))

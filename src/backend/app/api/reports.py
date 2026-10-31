"""Forensic report generation and download API routes."""

import json
from datetime import datetime
from pathlib import Path
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.models import Investigation, InvestigationReport, AuditLog
from app.schemas.schemas import ReportGenerateRequest, ReportResponse
from app.services.reporting.json_reporter import generate_json_report
from app.services.reporting.csv_reporter import generate_csv_report
from app.services.reporting.pdf_reporter import generate_pdf_report

router = APIRouter(tags=["Reports"])


def _report_to_response(rep: InvestigationReport) -> ReportResponse:
    """Helper to convert InvestigationReport ORM model to response schema."""
    return ReportResponse(
        id=rep.id,
        investigation_id=rep.investigation_id,
        format=rep.format,
        file_path=rep.file_path,
        generated_at=rep.generated_at,
        file_size=rep.file_size,
        download_url=f"/api/reports/{rep.id}/download",
    )


@router.post("/investigations/{investigation_id}/report", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
def create_report(
    investigation_id: str,
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db)
):
    """Generate a formal forensic investigation report in PDF, CSV, or JSON format."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' was not found."
        )

    fmt = payload.format.lower().strip()
    try:
        if fmt == "pdf":
            report_record = generate_pdf_report(investigation_id, db)
        elif fmt == "csv":
            report_record = generate_csv_report(investigation_id, db)
        elif fmt == "json":
            report_record = generate_json_report(investigation_id, db)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported report format '{payload.format}'. Allowed: pdf, csv, json."
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation error: {str(e)}"
        )

    # Log audit
    audit = AuditLog(
        investigation_id=investigation_id,
        action="REPORT_GENERATED",
        actor="INVESTIGATOR",
        timestamp=datetime.utcnow(),
        details=json.dumps({
            "report_id": report_record.id,
            "format": report_record.format,
            "file_size": report_record.file_size,
        }),
    )
    db.add(audit)
    db.commit()

    return _report_to_response(report_record)


@router.get("/investigations/{investigation_id}/reports", response_model=List[ReportResponse])
def list_investigation_reports(investigation_id: str, db: Session = Depends(get_db)):
    """List all previously generated reports for an investigation."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' was not found."
        )

    reports = (
        db.query(InvestigationReport)
        .filter(InvestigationReport.investigation_id == investigation_id)
        .order_by(InvestigationReport.generated_at.desc())
        .all()
    )
    return [_report_to_response(r) for r in reports]


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    """Download generated forensic report file."""
    report = db.query(InvestigationReport).filter(InvestigationReport.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' was not found."
        )

    file_path = Path(report.file_path)
    if not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report file does not exist on disk."
        )

    media_types = {
        "pdf": "application/pdf",
        "csv": "text/csv",
        "json": "application/json",
    }
    media_type = media_types.get(report.format.lower(), "application/octet-stream")

    return FileResponse(
        path=str(file_path),
        filename=file_path.name,
        media_type=media_type,
    )

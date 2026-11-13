"""Evidence management, cryptographic verification, and acquisition API routes."""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.models import (
    Investigation,
    EvidenceFile,
    IntegrityVerification,
    AuditLog,
    generate_uuid,
)
from app.schemas.schemas import (
    EvidenceFileResponse,
    EvidenceVerifyResponse,
    EvidenceUploadSummary,
    IntegrityVerificationResponse,
)
from app.services.ingestion.ingestor import IngestionService
from app.services.hashing.hasher import calculate_sha256

router = APIRouter(tags=["Evidence"])


@router.post("/evidence/upload", response_model=List[EvidenceUploadSummary], status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    investigation_id: str = Form(...),
    source_system: Optional[str] = Form(None),
    source_category: Optional[str] = Form(None),
    timezone_hint: Optional[str] = Form(None),
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db)
):
    """Multipart forensic evidence upload endpoint.

    Hashes content prior to storage, parses records, applies timezone normalizations,
    and returns acquisition summaries.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' does not exist."
        )

    ingestor = IngestionService(db)
    summaries: List[EvidenceUploadSummary] = []

    for upload_file in files:
        file_bytes = await upload_file.read()
        try:
            evidence, job = ingestor.ingest_file(
                investigation_id=investigation_id,
                file_bytes=file_bytes,
                original_filename=upload_file.filename or "unknown_evidence.log",
                source_system=source_system,
                source_category=source_category,
                timezone_hint=timezone_hint,
                actor="INVESTIGATOR",
            )
            summaries.append(
                EvidenceUploadSummary(
                    evidence_id=evidence.id,
                    filename=evidence.original_filename,
                    file_size=evidence.file_size,
                    sha256=evidence.sha256_hash,
                    detected_format=evidence.file_format or "unknown",
                    records_processed=job.total_records,
                    parsed_ok=job.parsed_ok,
                    parsed_partial=job.parsed_partial,
                    parsed_failed=job.parsed_failed,
                    missing_timestamps=job.missing_timestamps,
                )
            )
        except ValueError as ve:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed processing evidence file '{upload_file.filename}': {str(e)}"
            )

    return summaries


@router.get("/evidence", response_model=List[EvidenceFileResponse])
def list_all_evidence(db: Session = Depends(get_db)):
    """List all evidence files across every investigation."""
    return (
        db.query(EvidenceFile)
        .order_by(EvidenceFile.upload_timestamp.desc())
        .all()
    )


@router.get("/evidence/{evidence_id}", response_model=EvidenceFileResponse)
def get_evidence_metadata(evidence_id: str, db: Session = Depends(get_db)):
    """Retrieve forensic metadata for a specific evidence file."""
    evidence = db.query(EvidenceFile).filter(EvidenceFile.id == evidence_id).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file '{evidence_id}' was not found."
        )
    return evidence


@router.get("/evidence/{evidence_id}/download")
def download_evidence_file(evidence_id: str, db: Session = Depends(get_db)):
    """Download pristine original evidence file."""
    evidence = db.query(EvidenceFile).filter(EvidenceFile.id == evidence_id).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file '{evidence_id}' was not found."
        )

    file_path = (
        Path(settings.EVIDENCE_STORAGE_PATH)
        / evidence.investigation_id
        / evidence.stored_filename
    )

    if not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Stored evidence file not found on disk."
        )

    # Log audit
    audit = AuditLog(
        investigation_id=evidence.investigation_id,
        evidence_id=evidence.id,
        action="EVIDENCE_DOWNLOAD",
        actor="INVESTIGATOR",
        timestamp=datetime.utcnow(),
        details=json.dumps({"stored_filename": evidence.stored_filename}),
    )
    db.add(audit)
    db.commit()

    return FileResponse(
        path=str(file_path),
        filename=evidence.original_filename,
        media_type="application/octet-stream"
    )


@router.post("/evidence/{evidence_id}/verify", response_model=EvidenceVerifyResponse)
def verify_evidence_integrity(evidence_id: str, db: Session = Depends(get_db)):
    """Recalculate SHA-256 hash of stored evidence file and verify against baseline custody record."""
    evidence = db.query(EvidenceFile).filter(EvidenceFile.id == evidence_id).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file '{evidence_id}' was not found."
        )

    file_path = (
        Path(settings.EVIDENCE_STORAGE_PATH)
        / evidence.investigation_id
        / evidence.stored_filename
    )

    if not file_path.is_file():
        verification = IntegrityVerification(
            id=generate_uuid(),
            evidence_id=evidence.id,
            verified_at=datetime.utcnow(),
            original_hash=evidence.sha256_hash,
            recalculated_hash="",
            result="ERROR",
            notes="Stored evidence file missing from storage path.",
        )
        db.add(verification)
        db.commit()
        return EvidenceVerifyResponse(
            id=verification.id,
            verification_id=verification.id,
            evidence_id=evidence.id,
            verified_at=verification.verified_at,
            original_hash=verification.original_hash,
            recalculated_hash="",
            result="ERROR",
            notes=verification.notes,
        )

    recalculated_hash = calculate_sha256(str(file_path))
    is_match = (recalculated_hash.lower() == evidence.sha256_hash.lower())
    result_str = "MATCH" if is_match else "MISMATCH"
    notes = "Cryptographic integrity intact; bit-for-bit match verified." if is_match else "CRITICAL: Hash mismatch detected! Evidence integrity violated."

    verification = IntegrityVerification(
        id=generate_uuid(),
        evidence_id=evidence.id,
        verified_at=datetime.utcnow(),
        original_hash=evidence.sha256_hash,
        recalculated_hash=recalculated_hash,
        result=result_str,
        notes=notes,
    )
    db.add(verification)

    # Log audit
    audit = AuditLog(
        investigation_id=evidence.investigation_id,
        evidence_id=evidence.id,
        action="INTEGRITY_VERIFICATION",
        actor="INVESTIGATOR",
        timestamp=datetime.utcnow(),
        details=json.dumps({
            "result": result_str,
            "original_hash": evidence.sha256_hash,
            "recalculated_hash": recalculated_hash,
        }),
    )
    db.add(audit)
    db.commit()

    return EvidenceVerifyResponse(
        id=verification.id,
        verification_id=verification.id,
        evidence_id=evidence.id,
        verified_at=verification.verified_at,
        original_hash=verification.original_hash,
        recalculated_hash=recalculated_hash,
        result=result_str,
        notes=notes,
    )


@router.get("/evidence/{evidence_id}/verifications", response_model=List[IntegrityVerificationResponse])
def list_evidence_verifications(evidence_id: str, db: Session = Depends(get_db)):
    """List the complete integrity verification history for an evidence artifact."""
    evidence = db.query(EvidenceFile).filter(EvidenceFile.id == evidence_id).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file '{evidence_id}' was not found."
        )

    return (
        db.query(IntegrityVerification)
        .filter(IntegrityVerification.evidence_id == evidence_id)
        .order_by(IntegrityVerification.verified_at.desc())
        .all()
    )


@router.get("/investigations/{investigation_id}/evidence", response_model=List[EvidenceFileResponse])
def list_investigation_evidence(investigation_id: str, db: Session = Depends(get_db)):
    """List all evidence files acquired under a given investigation."""
    evidence_list = (
        db.query(EvidenceFile)
        .filter(EvidenceFile.investigation_id == investigation_id)
        .order_by(EvidenceFile.upload_timestamp.desc())
        .all()
    )
    return evidence_list

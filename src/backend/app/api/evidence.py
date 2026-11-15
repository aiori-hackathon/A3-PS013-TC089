"""Evidence management, cryptographic verification, and acquisition API routes."""

import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional
import aiofiles
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.services.cache import invalidate_cache
from app.models.models import (
    Investigation,
    EvidenceFile,
    IntegrityVerification,
    ProcessingJob,
    AuditLog,
    generate_uuid,
)
from app.schemas.schemas import (
    EvidenceFileResponse,
    EvidenceVerifyResponse,
    EvidenceUploadSummary,
    IntegrityVerificationResponse,
    ProcessingJobStatus,
)
from app.services.ingestion.ingestor import (
    FORMAT_SAMPLE_BYTES,
    IngestionService,
    detect_file_format_bytes,
    process_evidence_in_background,
)
from app.services.hashing.hasher import calculate_sha256

router = APIRouter(tags=["Evidence"])


@router.post("/evidence/upload", response_model=List[EvidenceUploadSummary], status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    background_tasks: BackgroundTasks,
    investigation_id: str = Form(...),
    source_system: Optional[str] = Form(None),
    source_category: Optional[str] = Form(None),
    timezone_hint: Optional[str] = Form(None),
    reference_year: Optional[int] = Form(None),
    clock_skew_seconds: Optional[int] = Form(0),
    files: List[UploadFile] = File(...),
    db: Session = Depends(get_db)
):
    """Stream multipart evidence to disk, seal it, and queue bounded-memory parsing.

    The response is returned as soon as the artifact is hashed and stored. Parsing
    runs in the background so large logs do not hold the HTTP request open.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' does not exist."
        )

    ingestor = IngestionService(db)
    summaries: List[EvidenceUploadSummary] = []
    investigation_storage = Path(settings.EVIDENCE_STORAGE_PATH) / investigation_id
    investigation_storage.mkdir(parents=True, exist_ok=True)

    for upload_file in files:
        original_filename = upload_file.filename or "unknown_evidence.log"
        file_ext = Path(original_filename).suffix.lower()
        if file_ext and file_ext not in settings.ALLOWED_EXTENSIONS:
            await upload_file.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File extension '{file_ext}' not permitted. Allowed: {settings.ALLOWED_EXTENSIONS}",
            )

        stored_filename = f"{uuid.uuid4()}{file_ext or '.log'}"
        stored_path = investigation_storage / stored_filename
        sha256 = hashlib.sha256()
        sample = bytearray()
        file_size = 0

        try:
            async with aiofiles.open(stored_path, "wb") as out:
                while True:
                    chunk = await upload_file.read(1024 * 1024)
                    if not chunk:
                        break
                    file_size += len(chunk)
                    if file_size > settings.MAX_FILE_SIZE_BYTES:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_MB}MB.",
                        )
                    sha256.update(chunk)
                    if len(sample) < FORMAT_SAMPLE_BYTES:
                        sample.extend(chunk[: FORMAT_SAMPLE_BYTES - len(sample)])
                    await out.write(chunk)
        except HTTPException:
            stored_path.unlink(missing_ok=True)
            await upload_file.close()
            raise
        except Exception as exc:
            stored_path.unlink(missing_ok=True)
            await upload_file.close()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed storing evidence file '{original_filename}': {str(exc)}",
            )
        finally:
            await upload_file.close()

        detected_format = detect_file_format_bytes(bytes(sample), filename=original_filename)
        try:
            evidence, job = ingestor.register_stored_file(
                investigation_id=investigation_id,
                stored_filename=stored_filename,
                original_filename=original_filename,
                file_size=file_size,
                sha256_hash=sha256.hexdigest(),
                detected_format=detected_format,
                source_system=source_system,
                source_category=source_category,
                timezone_hint=timezone_hint,
                reference_year=reference_year,
                clock_skew_seconds=clock_skew_seconds,
                actor="INVESTIGATOR",
            )
        except Exception as exc:
            stored_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed registering evidence file '{original_filename}': {str(exc)}",
            )

        background_tasks.add_task(
            process_evidence_in_background,
            evidence.id,
            job.id,
            source_system,
            timezone_hint,
            reference_year,
            clock_skew_seconds,
        )

        invalidate_cache()
        summaries.append(
            EvidenceUploadSummary(
                evidence_id=evidence.id,
                job_id=job.id,
                filename=evidence.original_filename,
                file_size=evidence.file_size,
                sha256=evidence.sha256_hash,
                detected_format=evidence.file_format or "unknown",
                records_processed=0,
                parsed_ok=0,
                parsed_partial=0,
                parsed_failed=0,
                missing_timestamps=0,
                reference_year=reference_year,
                clock_skew_seconds=clock_skew_seconds or 0,
                status="PROCESSING",
            )
        )

    return summaries


@router.get("/processing-jobs/{job_id}", response_model=ProcessingJobStatus)
def get_processing_job(job_id: str, db: Session = Depends(get_db)):
    """Poll progress and final counts for a background ingestion job."""
    job = db.query(ProcessingJob).filter(ProcessingJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Processing job '{job_id}' was not found."
        )

    evidence = db.query(EvidenceFile).filter(EvidenceFile.id == job.evidence_id).first()
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file for processing job '{job_id}' was not found."
        )

    errors = []
    if job.errors_json:
        try:
            parsed_errors = json.loads(job.errors_json)
            errors = parsed_errors if isinstance(parsed_errors, list) else [str(parsed_errors)]
        except Exception:
            errors = [str(job.errors_json)]

    return ProcessingJobStatus(
        job_id=job.id,
        evidence_id=job.evidence_id,
        investigation_id=job.investigation_id,
        filename=evidence.original_filename,
        file_size=evidence.file_size,
        sha256=evidence.sha256_hash,
        detected_format=evidence.file_format or "unknown",
        status=job.status,
        total_records=job.total_records,
        parsed_ok=job.parsed_ok,
        parsed_partial=job.parsed_partial,
        parsed_failed=job.parsed_failed,
        missing_timestamps=job.missing_timestamps,
        started_at=job.started_at,
        completed_at=job.completed_at,
        errors=errors,
    )


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
        invalidate_cache()
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
    invalidate_cache()

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

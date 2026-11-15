"""Forensic ingestion service with bounded-memory streaming and batched persistence."""

import json
import logging
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional, Tuple

from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.services.cache import invalidate_cache
from app.models.models import (
    AuditLog,
    Event,
    EvidenceFile,
    ProcessingJob,
    generate_uuid,
)
from app.services.hashing.hasher import calculate_sha256_bytes
from app.services.parsing.csv_parser import CSVParser
from app.services.parsing.json_parser import JSONParser
from app.services.parsing.syslog_parser import SyslogParser, RFC3164_REGEX, RFC5424_REGEX
from app.services.normalization.timestamp_normalizer import apply_clock_skew, normalize_timestamp

logger = logging.getLogger(__name__)

INGESTION_BATCH_SIZE = max(100, int(os.getenv("INGESTION_BATCH_SIZE", "50000")))
FORMAT_SAMPLE_BYTES = 64 * 1024


def detect_file_format(content: str, filename: str = "") -> str:
    """Detect file format primarily via content inspection with extension fallback.

    Returns: 'json', 'csv', 'syslog', or 'unknown'
    """
    if not content or not content.strip():
        ext = Path(filename).suffix.lower()
        if ext == ".json":
            return "json"
        elif ext == ".csv":
            return "csv"
        elif ext in (".log", ".txt"):
            return "syslog"
        return "unknown"

    stripped = content.strip()

    # 1. Test for JSON (object or array)
    if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
        try:
            json.loads(stripped)
            return "json"
        except Exception:
            pass

    # Test for NDJSON (multiple lines starting with '{' and ending with '}')
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    if lines and all(l.startswith("{") and l.endswith("}") for l in lines[:5]):
        try:
            json.loads(lines[0])
            return "json"
        except Exception:
            pass

    # 2. Test for Syslog format (RFC 3164 / RFC 5424 or standard syslog timestamp)
    sample_lines = lines[:10]
    syslog_matches = 0
    for l in sample_lines:
        if (
            RFC3164_REGEX.match(l)
            or RFC5424_REGEX.match(l)
            or re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", l)
        ):
            syslog_matches += 1

    if syslog_matches >= max(1, len(sample_lines) // 2):
        return "syslog"

    # 3. Test for CSV format (delimiter presence and column count consistency)
    first_line = lines[0] if lines else ""
    if any(delimiter in first_line for delimiter in [",", "\t", ";", "|"]):
        header_tokens = re.split(r"[,;\t|]", first_line)
        if len(header_tokens) >= 2:
            # Check for common header names or comma structure
            common_csv_terms = ["time", "date", "ip", "user", "host", "event", "status", "message", "level", "id", "action"]
            matched_terms = [t for t in header_tokens if any(c in t.lower() for c in common_csv_terms)]
            if matched_terms or len(lines) > 1:
                return "csv"

    # Fallback based on extension
    ext = Path(filename).suffix.lower()
    if ext == ".json":
        return "json"
    elif ext == ".csv":
        return "csv"
    elif ext in (".log", ".txt"):
        return "syslog"

    return "unknown"


def detect_file_format_bytes(sample: bytes, filename: str = "") -> str:
    """Detect format from a bounded byte sample without loading the full artifact."""
    try:
        content = sample.decode("utf-8")
    except UnicodeDecodeError:
        content = sample.decode("latin-1", errors="replace")
    return detect_file_format(content, filename=filename)


class IngestionService:
    """Coordinates evidence registration, streaming parsing, and batched event persistence."""

    def __init__(self, db: Session):
        self.db = db

    def _validate_file(self, original_filename: str, file_size: int) -> str:
        if file_size > settings.MAX_FILE_SIZE_BYTES:
            raise ValueError(f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_MB}MB.")

        file_ext = Path(original_filename).suffix.lower()
        if file_ext and file_ext not in settings.ALLOWED_EXTENSIONS:
            raise ValueError(f"File extension '{file_ext}' not permitted. Allowed: {settings.ALLOWED_EXTENSIONS}")
        return file_ext

    def _select_parser(self, detected_format: str):
        if detected_format == "csv":
            return CSVParser()
        if detected_format == "json":
            return JSONParser()
        return SyslogParser()

    def register_stored_file(
        self,
        investigation_id: str,
        stored_filename: str,
        original_filename: str,
        file_size: int,
        sha256_hash: str,
        detected_format: str,
        source_system: Optional[str] = None,
        source_category: Optional[str] = None,
        timezone_hint: Optional[str] = None,
        reference_year: Optional[int] = None,
        clock_skew_seconds: Optional[int] = None,
        actor: str = "INVESTIGATOR",
    ) -> Tuple[EvidenceFile, ProcessingJob]:
        """Create custody metadata and a processing job for an already-sealed file."""
        evidence_id = generate_uuid()
        evidence = EvidenceFile(
            id=evidence_id,
            investigation_id=investigation_id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            file_size=file_size,
            sha256_hash=sha256_hash,
            upload_timestamp=datetime.utcnow(),
            source_system=source_system,
            source_category=source_category,
            file_format=detected_format,
            processing_status="PROCESSING",
            timezone_hint=timezone_hint,
        )
        self.db.add(evidence)

        audit = AuditLog(
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            action="EVIDENCE_ACQUISITION",
            actor=actor,
            timestamp=datetime.utcnow(),
            details=json.dumps({
                "original_filename": original_filename,
                "file_size": file_size,
                "sha256": sha256_hash,
                "detected_format": detected_format,
                "timezone_hint": timezone_hint,
                "reference_year": reference_year,
                "clock_skew_seconds": clock_skew_seconds or 0,
            })
        )
        self.db.add(audit)

        job = ProcessingJob(
            id=generate_uuid(),
            evidence_id=evidence_id,
            investigation_id=investigation_id,
            started_at=datetime.utcnow(),
            status="IN_PROGRESS",
            total_records=0,
            parsed_ok=0,
            parsed_partial=0,
            parsed_failed=0,
            missing_timestamps=0,
            errors_json=json.dumps([]),
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(evidence)
        self.db.refresh(job)
        return evidence, job

    def process_evidence(
        self,
        evidence_id: str,
        job_id: str,
        source_system: Optional[str] = None,
        timezone_hint: Optional[str] = None,
        reference_year: Optional[int] = None,
        clock_skew_seconds: Optional[int] = None,
    ) -> Optional[Tuple[EvidenceFile, ProcessingJob]]:
        """Stream a stored evidence artifact, normalizing and persisting events in batches."""
        evidence = self.db.query(EvidenceFile).filter(EvidenceFile.id == evidence_id).first()
        job = self.db.query(ProcessingJob).filter(ProcessingJob.id == job_id).first()
        if not evidence or not job:
            return None

        # Keep the job counters live without forcing a reload after every batch commit.
        self.db.expire_on_commit = False

        file_path = (
            Path(settings.EVIDENCE_STORAGE_PATH)
            / evidence.investigation_id
            / evidence.stored_filename
        )
        if not file_path.is_file():
            return self._mark_failed(evidence, job, ["Stored evidence file missing from disk."])

        parser = self._select_parser(evidence.file_format or "unknown")
        effective_source = source_system or evidence.source_system

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace", newline="") as stream:
                records = parser.parse_stream(stream, default_source=effective_source)
                self._consume_records(
                    records=records,
                    evidence=evidence,
                    job=job,
                    source_system=effective_source,
                    timezone_hint=timezone_hint or evidence.timezone_hint,
                    reference_year=reference_year,
                    clock_skew_seconds=clock_skew_seconds,
                    original_filename=evidence.original_filename,
                )
        except Exception as exc:
            logger.exception("Evidence processing failed for %s", evidence_id)
            try:
                self.db.rollback()
            except Exception:
                pass
            return self._mark_failed(evidence, job, [f"Parser exception: {str(exc)}"])

        return evidence, job

    def _consume_records(
        self,
        records: Iterator[Any],
        evidence: EvidenceFile,
        job: ProcessingJob,
        source_system: Optional[str],
        timezone_hint: Optional[str],
        reference_year: Optional[int],
        clock_skew_seconds: Optional[int],
        original_filename: str,
    ) -> None:
        parsed_ok_cnt = 0
        parsed_partial_cnt = 0
        parsed_failed_cnt = 0
        missing_ts_cnt = 0
        total_records = 0
        errors = []
        batch = []

        def flush_batch() -> None:
            if batch:
                self.db.bulk_save_objects(batch)
                batch.clear()
            job.total_records = total_records
            job.parsed_ok = parsed_ok_cnt
            job.parsed_partial = parsed_partial_cnt
            job.parsed_failed = parsed_failed_cnt
            job.missing_timestamps = missing_ts_cnt
            job.errors_json = json.dumps(errors)
            self.db.commit()

        for rec in records:
            total_records += 1
            if rec.parsing_status == "OK":
                parsed_ok_cnt += 1
            elif rec.parsing_status == "PARTIAL":
                parsed_partial_cnt += 1
            else:
                parsed_failed_cnt += 1

            ts_norm = normalize_timestamp(
                rec.original_timestamp,
                source_timezone=timezone_hint,
                reference_year=reference_year,
            )
            ts_norm = apply_clock_skew(ts_norm, clock_skew_seconds)

            if ts_norm["status"] == "MISSING":
                missing_ts_cnt += 1

            extra_fields = dict(rec.extra_fields or {})
            if reference_year:
                extra_fields["reference_year"] = reference_year
            if clock_skew_seconds:
                extra_fields["clock_skew_seconds"] = clock_skew_seconds
                extra_fields["clock_skew_applied"] = ts_norm["status"] == "CLOCK_SKEW_ADJUSTED"
            extra_json = json.dumps(extra_fields, default=str) if extra_fields else None

            batch.append(Event(
                investigation_id=evidence.investigation_id,
                evidence_id=evidence.id,
                source_system=rec.source_system or source_system,
                original_timestamp=str(rec.original_timestamp) if rec.original_timestamp else None,
                normalized_timestamp=ts_norm["normalized_utc"],
                timestamp_status=ts_norm["status"],
                event_type=rec.event_type,
                event_category=rec.event_category or "UNCATEGORIZED",
                username=rec.username,
                source_ip=rec.source_ip,
                dest_ip=rec.dest_ip,
                severity=rec.severity or "INFO",
                description=rec.description,
                raw_record=rec.raw_record or original_filename,
                parsing_status=rec.parsing_status,
                extra_fields=extra_json,
            ))

            if len(batch) >= INGESTION_BATCH_SIZE:
                flush_batch()

        flush_batch()
        invalidate_cache()

        job.completed_at = datetime.utcnow()
        if errors and parsed_ok_cnt == 0:
            job.status = "FAILED"
        elif errors:
            job.status = "PARTIAL"
        elif total_records > 0 and parsed_ok_cnt == 0 and parsed_partial_cnt == 0:
            job.status = "FAILED"
        else:
            job.status = "COMPLETED"
        job.errors_json = json.dumps(errors)
        evidence.processing_status = "COMPLETED" if job.status in ("COMPLETED", "PARTIAL") else "FAILED"
        self.db.commit()

    def _mark_failed(
        self,
        evidence: EvidenceFile,
        job: ProcessingJob,
        errors: list,
    ) -> Tuple[EvidenceFile, ProcessingJob]:
        job.completed_at = datetime.utcnow()
        job.status = "FAILED"
        job.errors_json = json.dumps(errors)
        evidence.processing_status = "FAILED"
        self.db.commit()
        invalidate_cache()
        return evidence, job

    def ingest_file(
        self,
        investigation_id: str,
        file_bytes: bytes,
        original_filename: str,
        source_system: Optional[str] = None,
        source_category: Optional[str] = None,
        timezone_hint: Optional[str] = None,
        reference_year: Optional[int] = None,
        clock_skew_seconds: Optional[int] = None,
        actor: str = "INVESTIGATOR",
    ) -> Tuple[EvidenceFile, ProcessingJob]:
        """Synchronous compatibility wrapper used by demo loading and tests."""
        file_ext = self._validate_file(original_filename, len(file_bytes))
        sha256_hash = calculate_sha256_bytes(file_bytes)

        investigation_storage = Path(settings.EVIDENCE_STORAGE_PATH) / investigation_id
        investigation_storage.mkdir(parents=True, exist_ok=True)

        stored_filename = f"{uuid.uuid4()}{file_ext or '.log'}"
        stored_path = investigation_storage / stored_filename
        with open(stored_path, "wb") as f:
            f.write(file_bytes)

        detected_format = detect_file_format_bytes(file_bytes[:FORMAT_SAMPLE_BYTES], filename=original_filename)
        evidence, job = self.register_stored_file(
            investigation_id=investigation_id,
            stored_filename=stored_filename,
            original_filename=original_filename,
            file_size=len(file_bytes),
            sha256_hash=sha256_hash,
            detected_format=detected_format,
            source_system=source_system,
            source_category=source_category,
            timezone_hint=timezone_hint,
            reference_year=reference_year,
            clock_skew_seconds=clock_skew_seconds,
            actor=actor,
        )
        self.process_evidence(
            evidence_id=evidence.id,
            job_id=job.id,
            source_system=source_system,
            timezone_hint=timezone_hint,
            reference_year=reference_year,
            clock_skew_seconds=clock_skew_seconds,
        )
        self.db.refresh(evidence)
        self.db.refresh(job)
        return evidence, job


def process_evidence_in_background(
    evidence_id: str,
    job_id: str,
    source_system: Optional[str] = None,
    timezone_hint: Optional[str] = None,
    reference_year: Optional[int] = None,
    clock_skew_seconds: Optional[int] = None,
) -> None:
    """Run ingestion in a dedicated session after the upload response is returned."""
    db = SessionLocal()
    try:
        IngestionService(db).process_evidence(
            evidence_id=evidence_id,
            job_id=job_id,
            source_system=source_system,
            timezone_hint=timezone_hint,
            reference_year=reference_year,
            clock_skew_seconds=clock_skew_seconds,
        )
    except Exception:
        logger.exception("Background evidence processing failed for %s", evidence_id)
        db.rollback()
    finally:
        db.close()

"""Forensic ingestion service handling cryptographic hashing, format detection, and event normalization."""

import os
import uuid
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session

from app.config import settings
from app.models.models import (
    EvidenceFile,
    Event,
    ProcessingJob,
    AuditLog,
    generate_uuid,
)
from app.services.hashing.hasher import calculate_sha256_bytes
from app.services.parsing.csv_parser import CSVParser
from app.services.parsing.json_parser import JSONParser
from app.services.parsing.syslog_parser import SyslogParser, RFC3164_REGEX, RFC5424_REGEX
from app.services.normalization.timestamp_normalizer import normalize_timestamp


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


class IngestionService:
    """Coordinates evidence file reception, hashing, database recording, and forensic parsing."""

    def __init__(self, db: Session):
        self.db = db

    def ingest_file(
        self,
        investigation_id: str,
        file_bytes: bytes,
        original_filename: str,
        source_system: Optional[str] = None,
        source_category: Optional[str] = None,
        timezone_hint: Optional[str] = None,
        actor: str = "INVESTIGATOR"
    ) -> Tuple[EvidenceFile, ProcessingJob]:
        """Ingest evidence file adhering to chain-of-custody standards."""
        # 1. Validation
        if len(file_bytes) > settings.MAX_FILE_SIZE_BYTES:
            raise ValueError(f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_MB}MB.")

        file_ext = Path(original_filename).suffix.lower()
        if file_ext and file_ext not in settings.ALLOWED_EXTENSIONS:
            raise ValueError(f"File extension '{file_ext}' not permitted. Allowed: {settings.ALLOWED_EXTENSIONS}")

        # 2. Cryptographic Hashing BEFORE any processing or storage
        sha256_hash = calculate_sha256_bytes(file_bytes)

        # 3. Secure disk storage under evidence_storage/<investigation_id>/
        investigation_storage = Path(settings.EVIDENCE_STORAGE_PATH) / investigation_id
        investigation_storage.mkdir(parents=True, exist_ok=True)

        stored_filename = f"{uuid.uuid4()}{file_ext or '.log'}"
        stored_path = investigation_storage / stored_filename

        with open(stored_path, "wb") as f:
            f.write(file_bytes)

        # Decode content for parsing
        try:
            content_str = file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            content_str = file_bytes.decode("latin-1", errors="replace")

        detected_format = detect_file_format(content_str, filename=original_filename)

        # 4. Create EvidenceFile record
        evidence_id = generate_uuid()
        evidence = EvidenceFile(
            id=evidence_id,
            investigation_id=investigation_id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            file_size=len(file_bytes),
            sha256_hash=sha256_hash,
            upload_timestamp=datetime.utcnow(),
            source_system=source_system,
            source_category=source_category,
            file_format=detected_format,
            processing_status="PROCESSING",
            timezone_hint=timezone_hint,
        )
        self.db.add(evidence)
        self.db.flush()

        # 5. Create Audit Log Entry
        audit = AuditLog(
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            action="EVIDENCE_ACQUISITION",
            actor=actor,
            timestamp=datetime.utcnow(),
            details=json.dumps({
                "original_filename": original_filename,
                "file_size": len(file_bytes),
                "sha256": sha256_hash,
                "detected_format": detected_format,
                "timezone_hint": timezone_hint,
            })
        )
        self.db.add(audit)

        # 6. Initialize ProcessingJob record
        job_id = generate_uuid()
        job = ProcessingJob(
            id=job_id,
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

        # 7. Select Parser
        if detected_format == "csv":
            parser = CSVParser()
        elif detected_format == "json":
            parser = JSONParser()
        else:
            parser = SyslogParser()

        # 8. Parse and Normalize Events
        errors = []
        parsed_records = []
        try:
            parsed_records = parser.parse(content_str, default_source=source_system)
        except Exception as e:
            errors.append(f"Parser exception: {str(e)}")

        parsed_ok_cnt = 0
        parsed_partial_cnt = 0
        parsed_failed_cnt = 0
        missing_ts_cnt = 0

        event_entities = []
        for rec in parsed_records:
            if rec.parsing_status == "OK":
                parsed_ok_cnt += 1
            elif rec.parsing_status == "PARTIAL":
                parsed_partial_cnt += 1
            else:
                parsed_failed_cnt += 1

            # Normalize timestamp
            ts_norm = normalize_timestamp(
                rec.original_timestamp,
                source_timezone=timezone_hint
            )

            if ts_norm["status"] == "MISSING":
                missing_ts_cnt += 1

            extra_json = json.dumps(rec.extra_fields, default=str) if rec.extra_fields else None

            event = Event(
                investigation_id=investigation_id,
                evidence_id=evidence_id,
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
            )
            event_entities.append(event)

        # Bulk save events
        if event_entities:
            self.db.bulk_save_objects(event_entities)

        # 9. Update ProcessingJob and EvidenceFile completion status
        job.completed_at = datetime.utcnow()
        job.total_records = len(parsed_records)
        job.parsed_ok = parsed_ok_cnt
        job.parsed_partial = parsed_partial_cnt
        job.parsed_failed = parsed_failed_cnt
        job.missing_timestamps = missing_ts_cnt
        job.errors_json = json.dumps(errors)
        job.status = "COMPLETED" if not errors else ("PARTIAL" if parsed_ok_cnt > 0 else "FAILED")

        evidence.processing_status = "COMPLETED" if job.status in ("COMPLETED", "PARTIAL") else "FAILED"
        self.db.commit()
        self.db.refresh(evidence)
        self.db.refresh(job)

        return evidence, job

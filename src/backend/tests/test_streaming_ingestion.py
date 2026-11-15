"""Tests for bounded-memory streaming ingestion and background-job bookkeeping."""

import hashlib
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.database import Base
from app.models.models import Event, Investigation, generate_uuid
from app.services.ingestion import ingestor as ingestor_module
from app.services.ingestion.ingestor import IngestionService


def _setup_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_streaming_ingestion_persists_batches_and_clock_skew(tmp_path, monkeypatch):
    db = _setup_db()
    inv_id = generate_uuid()
    db.add(Investigation(id=inv_id, name="Streaming Test", status="ACTIVE"))
    db.commit()

    storage = tmp_path / "evidence" / inv_id
    storage.mkdir(parents=True)
    stored = storage / "auth.log"
    lines = [
        f"Oct 30 10:15:{i % 60:02d} host sshd[1]: Failed password for invalid user u{i} from 192.0.2.{i % 250}"
        for i in range(250)
    ]
    payload = ("\n".join(lines) + "\n").encode()
    stored.write_bytes(payload)
    sha = hashlib.sha256(payload).hexdigest()

    monkeypatch.setattr(settings, "EVIDENCE_STORAGE_PATH", str(tmp_path / "evidence"))
    monkeypatch.setattr(ingestor_module, "INGESTION_BATCH_SIZE", 50)

    service = IngestionService(db)
    evidence, job = service.register_stored_file(
        investigation_id=inv_id,
        stored_filename=stored.name,
        original_filename="auth.log",
        file_size=len(payload),
        sha256_hash=sha,
        detected_format="syslog",
        source_system="host",
        reference_year=2024,
        clock_skew_seconds=-300,
    )
    service.process_evidence(
        evidence_id=evidence.id,
        job_id=job.id,
        source_system="host",
        reference_year=2024,
        clock_skew_seconds=-300,
    )

    db.refresh(job)
    db.refresh(evidence)
    assert job.status == "COMPLETED"
    assert job.total_records == 250
    assert job.parsed_ok == 250
    assert evidence.processing_status == "COMPLETED"

    events = db.query(Event).filter(Event.evidence_id == evidence.id).all()
    assert len(events) == 250
    assert all(e.timestamp_status == "CLOCK_SKEW_ADJUSTED" for e in events)
    assert events[0].normalized_timestamp == datetime(2024, 10, 30, 10, 10, 0)
    assert events[0].original_timestamp == "Oct 30 10:15:00"


def test_generic_cef_leef_logfmt_ingestion_end_to_end(tmp_path, monkeypatch):
    """Verify detected CEF/LEEF/logfmt lines use the generic parser during ingestion."""
    import json

    from app.services.ingestion.ingestor import detect_file_format

    db = _setup_db()
    inv_id = generate_uuid()
    db.add(Investigation(id=inv_id, name="Generic Format Test", status="ACTIVE"))
    db.commit()

    lines = [
        "<14>Sep 18 14:58:29 logstream syslog: CEF:0|Citrix|NetScaler|NS10.0|APPFW|"
        "APPFW_STARTURL|6|src=10.217.253.78 method=GET "
        "request=http://vpx247.example.net/login msg=Disallow Illegal URL.",
        "<113>1 2019-01-18T11:07:53.520+07:00 hostname4 "
        "LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=10.0.1.8^dst=10.0.0.5^sev=5",
        'time="2023-07-16T01:10:42Z" level=error msg="Error message" client_id=1',
    ]
    payload = ("\n".join(lines) + "\n").encode()
    detected_format = detect_file_format(payload.decode(), "mixed.log")
    assert detected_format == "generic"

    storage = tmp_path / "evidence" / inv_id
    storage.mkdir(parents=True)
    stored = storage / "mixed.log"
    stored.write_bytes(payload)
    sha = hashlib.sha256(payload).hexdigest()

    monkeypatch.setattr(settings, "EVIDENCE_STORAGE_PATH", str(tmp_path / "evidence"))

    service = IngestionService(db)
    evidence, job = service.register_stored_file(
        investigation_id=inv_id,
        stored_filename=stored.name,
        original_filename="mixed.log",
        file_size=len(payload),
        sha256_hash=sha,
        detected_format=detected_format,
        source_system="collector",
        timezone_hint="UTC",
        reference_year=2024,
    )
    service.process_evidence(
        evidence_id=evidence.id,
        job_id=job.id,
        source_system="collector",
        timezone_hint="UTC",
        reference_year=2024,
    )

    db.refresh(job)
    assert job.status == "COMPLETED"
    assert job.total_records == 3
    assert job.parsed_ok == 3

    events = db.query(Event).filter(Event.evidence_id == evidence.id).all()
    formats = {json.loads(event.extra_fields)["log_format"] for event in events}
    assert formats == {"cef", "leef", "keyvalue"}
    assert {event.source_ip for event in events if event.source_ip} == {"10.217.253.78", "10.0.1.8"}

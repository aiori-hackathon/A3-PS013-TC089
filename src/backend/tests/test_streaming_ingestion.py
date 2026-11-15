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

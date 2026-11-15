"""SQLAlchemy ORM models for VIGILANCE digital forensics platform."""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    Float,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from app.database import Base


def generate_uuid() -> str:
    """Generate string UUID4."""
    return str(uuid.uuid4())


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=True, default="General Investigation")
    status = Column(String(50), nullable=False, default="ACTIVE", index=True)  # ACTIVE, CLOSED, ARCHIVED
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    archived_at = Column(DateTime, nullable=True)

    # Relationships with cascade delete
    evidence_files = relationship("EvidenceFile", back_populates="investigation", cascade="all, delete-orphan")
    events = relationship("Event", back_populates="investigation", cascade="all, delete-orphan")
    processing_jobs = relationship("ProcessingJob", back_populates="investigation", cascade="all, delete-orphan")
    detection_alerts = relationship("DetectionAlert", back_populates="investigation", cascade="all, delete-orphan")
    investigation_reports = relationship("InvestigationReport", back_populates="investigation", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="investigation", cascade="all, delete-orphan")
    triage_measurements = relationship("TriageMeasurement", back_populates="investigation", cascade="all, delete-orphan")


class EvidenceFile(Base):
    __tablename__ = "evidence_files"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    collection_timestamp = Column(DateTime, nullable=True)
    upload_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    source_system = Column(String(100), nullable=True)
    source_category = Column(String(100), nullable=True)
    file_format = Column(String(50), nullable=True)  # csv, json, syslog, unknown
    processing_status = Column(String(50), default="PENDING", nullable=False)  # PENDING, PROCESSING, COMPLETED, FAILED
    timezone_hint = Column(String(50), nullable=True)

    # Relationships
    investigation = relationship("Investigation", back_populates="evidence_files")
    events = relationship("Event", back_populates="evidence_file", cascade="all, delete-orphan")
    verifications = relationship("IntegrityVerification", back_populates="evidence_file", cascade="all, delete-orphan")
    processing_jobs = relationship("ProcessingJob", back_populates="evidence_file", cascade="all, delete-orphan")


class Event(Base):
    __tablename__ = "events"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence_files.id", ondelete="CASCADE"), nullable=False, index=True)
    source_system = Column(String(100), nullable=True, index=True)
    original_timestamp = Column(String(100), nullable=True)
    normalized_timestamp = Column(DateTime, nullable=True, index=True)
    timestamp_status = Column(String(50), nullable=False, default="UNCERTAIN", index=True)
    event_type = Column(String(100), nullable=True, index=True)
    event_category = Column(String(100), nullable=False, default="UNCATEGORIZED", index=True)
    username = Column(String(150), nullable=True, index=True)
    source_ip = Column(String(50), nullable=True, index=True)
    dest_ip = Column(String(50), nullable=True, index=True)
    severity = Column(String(50), nullable=False, default="INFO", index=True)
    description = Column(Text, nullable=True)
    raw_record = Column(Text, nullable=False)
    parsing_status = Column(String(50), nullable=False, default="OK")  # OK, PARTIAL, FAILED
    extra_fields = Column(Text, nullable=True)  # JSON text

    # Relationships
    investigation = relationship("Investigation", back_populates="events")
    evidence_file = relationship("EvidenceFile", back_populates="events")

    __table_args__ = (
        Index("idx_events_investigation_normalized_ts", "investigation_id", "normalized_timestamp"),
        Index("idx_events_investigation_source_ip", "investigation_id", "source_ip"),
        Index("idx_events_investigation_username", "investigation_id", "username"),
        Index("idx_events_investigation_parsing_status", "investigation_id", "parsing_status"),
        Index("idx_events_investigation_timestamp_status", "investigation_id", "timestamp_status"),
        Index("idx_events_investigation_severity", "investigation_id", "severity"),
        Index("idx_events_investigation_event_category", "investigation_id", "event_category"),
    )


class IntegrityVerification(Base):
    __tablename__ = "integrity_verifications"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence_files.id", ondelete="CASCADE"), nullable=False, index=True)
    verified_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    original_hash = Column(String(64), nullable=False)
    recalculated_hash = Column(String(64), nullable=False)
    result = Column(String(20), nullable=False)  # MATCH, MISMATCH, ERROR
    notes = Column(Text, nullable=True)

    evidence_file = relationship("EvidenceFile", back_populates="verifications")


class ProcessingJob(Base):
    __tablename__ = "processing_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence_files.id", ondelete="CASCADE"), nullable=False, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(50), nullable=False, default="IN_PROGRESS")  # IN_PROGRESS, COMPLETED, FAILED
    total_records = Column(Integer, default=0, nullable=False)
    parsed_ok = Column(Integer, default=0, nullable=False)
    parsed_partial = Column(Integer, default=0, nullable=False)
    parsed_failed = Column(Integer, default=0, nullable=False)
    missing_timestamps = Column(Integer, default=0, nullable=False)
    errors_json = Column(Text, nullable=True)  # JSON list of error details

    evidence_file = relationship("EvidenceFile", back_populates="processing_jobs")
    investigation = relationship("Investigation", back_populates="processing_jobs")


class DetectionAlert(Base):
    __tablename__ = "detection_alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_name = Column(String(200), nullable=False, index=True)
    severity = Column(String(50), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    explanation = Column(Text, nullable=False)
    event_ids = Column(Text, nullable=True)  # JSON array of event UUIDs
    ip_addresses = Column(Text, nullable=True)  # JSON array of IPs
    usernames = Column(Text, nullable=True)  # JSON array of usernames
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    alert_type = Column(String(100), nullable=False)

    investigation = relationship("Investigation", back_populates="detection_alerts")


class InvestigationReport(Base):
    __tablename__ = "investigation_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    format = Column(String(20), nullable=False)  # PDF, CSV, JSON
    file_path = Column(String(500), nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    file_size = Column(Integer, nullable=False)

    investigation = relationship("Investigation", back_populates="investigation_reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True, index=True)
    evidence_id = Column(String(36), ForeignKey("evidence_files.id", ondelete="CASCADE"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    actor = Column(String(100), nullable=False, default="SYSTEM")
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    details = Column(Text, nullable=True)  # JSON text

    investigation = relationship("Investigation", back_populates="audit_logs")


class TriageMeasurement(Base):
    __tablename__ = "triage_measurements"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    method = Column(String(50), nullable=False)  # MANUAL, VIGILANCE
    scenario = Column(String(100), nullable=False)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    duration_seconds = Column(Float, nullable=False)
    events_identified = Column(Integer, default=0, nullable=False)
    records_processed = Column(Integer, default=0, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    investigation = relationship("Investigation", back_populates="triage_measurements")

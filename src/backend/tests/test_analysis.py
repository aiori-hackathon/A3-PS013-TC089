"""Unit tests for forensic rule engine and correlation alerts."""

import json
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.models import Investigation, EvidenceFile, Event, generate_uuid
from app.services.analysis.rule_engine import RuleEngine, run_all_rules


def _setup_test_db():
    """Create fresh in-memory SQLite database for test execution."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_rule_1_brute_force_triggers_on_threshold():
    """Verify Rule 1 triggers HIGH/CRITICAL alert on 5 failed logins from same IP."""
    db = _setup_test_db()
    inv_id = generate_uuid()
    ev_id = generate_uuid()

    inv = Investigation(id=inv_id, name="Test Brute Force Case", status="ACTIVE")
    evidence = EvidenceFile(
        id=ev_id, investigation_id=inv_id, original_filename="test.log",
        stored_filename="stored.log", file_size=100, sha256_hash="dummy"
    )
    db.add(inv)
    db.add(evidence)
    db.commit()

    # Add 5 failed logins from 192.168.100.5
    for i in range(5):
        event = Event(
            id=generate_uuid(),
            investigation_id=inv_id,
            evidence_id=ev_id,
            source_system="auth01",
            normalized_timestamp=datetime(2026, 10, 30, 10, 0, i),
            timestamp_status="UTC_CONFIRMED",
            event_type="LOGIN",
            event_category="LOGIN_FAILURE",
            username="root",
            source_ip="192.168.100.5",
            severity="MEDIUM",
            description="Failed password for root",
            raw_record="auth.log line",
            parsing_status="OK",
        )
        db.add(event)
    db.commit()

    engine = RuleEngine(db, inv_id)
    alerts = engine.rule_1_multiple_failed_logins()

    assert len(alerts) == 1
    assert alerts[0].rule_name == "Multiple Failed Logins from Same IP"
    assert alerts[0].severity in ("HIGH", "CRITICAL")
    assert "192.168.100.5" in alerts[0].ip_addresses


def test_rule_1_does_not_trigger_below_threshold():
    """Verify Rule 1 does NOT trigger on only 2 failed logins from same IP."""
    db = _setup_test_db()
    inv_id = generate_uuid()
    ev_id = generate_uuid()

    inv = Investigation(id=inv_id, name="Test Safe Case", status="ACTIVE")
    evidence = EvidenceFile(
        id=ev_id, investigation_id=inv_id, original_filename="test.log",
        stored_filename="stored.log", file_size=100, sha256_hash="dummy"
    )
    db.add(inv)
    db.add(evidence)

    for i in range(2):
        event = Event(
            id=generate_uuid(),
            investigation_id=inv_id,
            evidence_id=ev_id,
            normalized_timestamp=datetime(2026, 10, 30, 10, 0, i),
            event_category="LOGIN_FAILURE",
            username="alice",
            source_ip="10.0.0.1",
            raw_record="line",
            parsing_status="OK",
        )
        db.add(event)
    db.commit()

    engine = RuleEngine(db, inv_id)
    alerts = engine.rule_1_multiple_failed_logins()
    assert len(alerts) == 0


def test_rule_2_compromised_account_detection():
    """Verify Rule 2 triggers when successful login follows repeated failures from same IP."""
    db = _setup_test_db()
    inv_id = generate_uuid()
    ev_id = generate_uuid()

    inv = Investigation(id=inv_id, name="Test Compromise Case", status="ACTIVE")
    evidence = EvidenceFile(id=ev_id, investigation_id=inv_id, original_filename="t.log", stored_filename="s.log", file_size=10, sha256_hash="d")
    db.add_all([inv, evidence])

    # 3 failures followed by 1 success
    for i in range(3):
        db.add(Event(
            id=generate_uuid(), investigation_id=inv_id, evidence_id=ev_id,
            normalized_timestamp=datetime(2026, 10, 30, 10, 0, i),
            event_category="LOGIN_FAILURE", username="bob", source_ip="198.51.100.22",
            raw_record="fail", parsing_status="OK"
        ))

    db.add(Event(
        id=generate_uuid(), investigation_id=inv_id, evidence_id=ev_id,
        normalized_timestamp=datetime(2026, 10, 30, 10, 0, 10),
        event_category="LOGIN_SUCCESS", username="bob", source_ip="198.51.100.22",
        raw_record="success", parsing_status="OK"
    ))
    db.commit()

    engine = RuleEngine(db, inv_id)
    alerts = engine.rule_2_successful_login_after_failures()

    assert len(alerts) == 1
    assert alerts[0].rule_name == "Successful Login After Repeated Failures"
    assert alerts[0].severity == "CRITICAL"


def test_rule_4_suspicious_path_access():
    """Verify Rule 4 flags attempts to access sensitive paths like /.env and /etc/passwd."""
    db = _setup_test_db()
    inv_id = generate_uuid()
    ev_id = generate_uuid()

    inv = Investigation(id=inv_id, name="Web Probe Case")
    evidence = EvidenceFile(id=ev_id, investigation_id=inv_id, original_filename="web.log", stored_filename="w.log", file_size=10, sha256_hash="d")
    db.add_all([inv, evidence])

    db.add(Event(
        id=generate_uuid(), investigation_id=inv_id, evidence_id=ev_id,
        normalized_timestamp=datetime(2026, 10, 30, 12, 0, 0),
        event_category="HTTP_REQUEST", source_ip="203.0.113.88",
        description="GET /.env HTTP/1.1 404", raw_record="GET /.env",
        parsing_status="OK"
    ))
    db.commit()

    engine = RuleEngine(db, inv_id)
    alerts = engine.rule_4_suspicious_path_access()

    assert len(alerts) == 1
    assert "Suspicious Path" in alerts[0].rule_name
    assert "203.0.113.88" in alerts[0].ip_addresses

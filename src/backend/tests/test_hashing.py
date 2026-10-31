"""Unit tests for cryptographic hashing service."""

import hashlib
import tempfile
import os
from app.services.hashing.hasher import calculate_sha256, calculate_sha256_bytes


def test_sha256_known_content():
    """Verify SHA-256 calculation matches known cryptographic baseline."""
    content = b"VIGILANCE_FORENSIC_EVIDENCE_PAYLOAD_TEST_12345"
    expected = hashlib.sha256(content).hexdigest()

    result = calculate_sha256_bytes(content)
    assert result == expected
    assert len(result) == 64


def test_sha256_file_matches_bytes():
    """Verify file streaming hash produces identical result to direct byte hashing."""
    test_data = b"Chain-of-custody test record line 1\nLine 2 with special chars: @#$%^&*()\n"
    expected_hash = calculate_sha256_bytes(test_data)

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(test_data)
        tmp_path = tmp.name

    try:
        file_hash = calculate_sha256(tmp_path)
        assert file_hash == expected_hash
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_sha256_empty_bytes():
    """Verify hash of empty bytes matches standard SHA-256 empty hash."""
    empty_hash = hashlib.sha256(b"").hexdigest()
    assert calculate_sha256_bytes(b"") == empty_hash
    assert empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_detects_modified_file(tmp_path):
    """Verify that modifying evidence content changes its SHA-256 hash."""
    evidence_file = tmp_path / "evidence.txt"

    evidence_file.write_bytes(b"Original forensic evidence")
    original_hash = calculate_sha256(str(evidence_file))

    # Simulate modification of the test file
    evidence_file.write_bytes(b"Modified forensic evidence")
    modified_hash = calculate_sha256(str(evidence_file))

    assert original_hash != modified_hash

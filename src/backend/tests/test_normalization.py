"""Unit tests for forensic timestamp normalization."""

from datetime import datetime
from app.services.normalization.timestamp_normalizer import normalize_timestamp


def test_iso_8601_explicit_utc():
    """Verify ISO 8601 with Z or UTC indicator maps to UTC_CONFIRMED."""
    raw = "2026-10-30T10:15:23Z"
    res = normalize_timestamp(raw)

    assert res["status"] == "UTC_CONFIRMED"
    assert res["normalized_utc"] is not None
    assert res["normalized_utc"].year == 2026
    assert res["normalized_utc"].month == 10
    assert res["normalized_utc"].day == 30
    assert res["normalized_utc"].hour == 10
    assert res["normalized_utc"].minute == 15
    assert res["normalized_utc"].second == 23


def test_iso_8601_with_offset():
    """Verify timestamp with non-zero offset converts accurately to UTC."""
    raw = "2026-10-30T15:45:00+05:30"
    res = normalize_timestamp(raw)

    assert res["status"] == "OFFSET_CONVERTED"
    assert res["normalized_utc"] is not None
    # 15:45 - 5:30 = 10:15 UTC
    assert res["normalized_utc"].hour == 10
    assert res["normalized_utc"].minute == 15


def test_naive_timestamp_without_timezone_is_uncertain():
    """Verify strict forensics: naive timestamp without timezone is UNCERTAIN (never silently assumed UTC)."""
    raw = "2026-10-30 14:30:00"
    res = normalize_timestamp(raw)

    assert res["status"] == "UNCERTAIN"
    assert res["normalized_utc"] is None
    assert "uncertain" in res["assumptions"].lower()


def test_naive_timestamp_with_source_timezone():
    """Verify providing investigator source_timezone resolves naive timestamp to UTC with SOURCE_TZ_USED."""
    raw = "2026-10-30 15:45:00"
    # Asia/Kolkata is UTC+5:30
    res = normalize_timestamp(raw, source_timezone="Asia/Kolkata")

    assert res["status"] == "SOURCE_TZ_USED"
    assert res["normalized_utc"] is not None
    assert res["normalized_utc"].hour == 10
    assert res["normalized_utc"].minute == 15


def test_unix_epoch_timestamp():
    """Verify integer and float epoch timestamps are parsed as UNIX_TIMESTAMP."""
    raw = 1700000000  # 2023-11-14 22:13:20 UTC
    res = normalize_timestamp(raw)

    assert res["status"] == "UNIX_TIMESTAMP"
    assert res["normalized_utc"] is not None
    assert res["normalized_utc"].year == 2023


def test_syslog_timestamp_no_year():
    """Verify syslog timestamp lacking year is assigned SYSLOG_NO_YEAR with reference year context."""
    raw = "Oct 30 10:15:23"
    res = normalize_timestamp(raw, reference_year=2026)

    assert res["status"] == "SYSLOG_NO_YEAR"
    assert res["normalized_utc"] is not None
    assert res["normalized_utc"].year == 2026
    assert res["normalized_utc"].month == 10
    assert res["normalized_utc"].day == 30
    assert res["normalized_utc"].hour == 10
    assert res["normalized_utc"].minute == 15
    assert res["normalized_utc"].second == 23


def test_missing_and_invalid_timestamps():
    """Verify missing and corrupt timestamps produce proper forensic flags."""
    res_none = normalize_timestamp(None)
    assert res_none["status"] == "MISSING"

    res_empty = normalize_timestamp("   ")
    assert res_empty["status"] == "MISSING"

    res_bad = normalize_timestamp("not_a_valid_date_string_xyz")
    assert res_bad["status"] == "INVALID"
    assert res_bad["normalized_utc"] is None

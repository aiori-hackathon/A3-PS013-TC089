"""Forensic timestamp normalizer adhering to strict chain-of-custody standards.

Never silently assumes UTC when no timezone information is present.
Tracks exact conversion status and audit assumptions for forensic veracity.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from dateutil import parser as dt_parser
from dateutil import tz
import pytz

CONVERSION_STATUS = {
    "UTC_CONFIRMED": "Timestamp had explicit UTC or +00:00",
    "OFFSET_CONVERTED": "Timestamp had explicit offset, converted to UTC",
    "TIMEZONE_CONVERTED": "Timestamp had named timezone, converted to UTC",
    "SOURCE_TZ_USED": "No timezone info; used investigator-provided source timezone",
    "UNCERTAIN": "No timezone info and no source timezone provided; timestamp uncertain",
    "SYSLOG_NO_YEAR": "Syslog format lacks year; estimated from context",
    "CLOCK_SKEW_ADJUSTED": "Timestamp adjusted by investigator-provided clock skew offset",
    "UNIX_TIMESTAMP": "Unix epoch timestamp converted to UTC",
    "INVALID": "Could not parse timestamp",
    "MISSING": "No timestamp found in record",
}

# Regex for syslog timestamp: "Oct 30 10:15:23" or "Oct  5 09:12:00"
SYSLOG_TS_REGEX = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<micro>\d+))?$"
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _resolve_timezone(tz_identifier: str):
    """Resolve a timezone string from pytz or dateutil.tz."""
    tz_clean = tz_identifier.strip()
    try:
        return pytz.timezone(tz_clean)
    except Exception:
        pass

    try:
        parsed_tz = tz.gettz(tz_clean)
        if parsed_tz is not None:
            return parsed_tz
    except Exception:
        pass

    # Check numeric offset like +05:30 or -0400
    offset_match = re.match(r"^([+-])(\d{2}):?(\d{2})$", tz_clean)
    if offset_match:
        sign, hours, mins = offset_match.groups()
        total_seconds = (int(hours) * 3600 + int(mins) * 60) * (-1 if sign == "-" else 1)
        return tz.tzoffset(tz_clean, total_seconds)

    return None


def normalize_timestamp(
    raw_ts: Optional[Any],
    source_timezone: Optional[str] = None,
    reference_year: Optional[int] = None
) -> Dict[str, Any]:
    """Normalize a raw timestamp string/number to UTC with explicit status and assumptions.

    Returns:
        dict: {
            "original": raw_ts,
            "normalized_utc": datetime | None,
            "status": str (from CONVERSION_STATUS keys),
            "assumptions": str
        }
    """
    if raw_ts is None:
        return {
            "original": None,
            "normalized_utc": None,
            "status": "MISSING",
            "assumptions": "No timestamp was present in the record.",
        }

    raw_str = str(raw_ts).strip()
    if not raw_str or raw_str.lower() in ("none", "null", "nan", ""):
        return {
            "original": raw_str,
            "normalized_utc": None,
            "status": "MISSING",
            "assumptions": "Timestamp field was empty or null.",
        }

    # 1. Check for Unix Epoch (integer or float)
    epoch_candidate = None
    if isinstance(raw_ts, (int, float)):
        epoch_candidate = float(raw_ts)
    else:
        # Match purely numeric string with optional fractional seconds
        if re.match(r"^\d{9,13}(?:\.\d+)?$", raw_str):
            try:
                epoch_candidate = float(raw_str)
            except ValueError:
                epoch_candidate = None

    if epoch_candidate is not None:
        # If timestamp is in milliseconds (> 1e11), convert to seconds
        if epoch_candidate > 1e11:
            epoch_candidate = epoch_candidate / 1000.0
        try:
            dt_utc = datetime.fromtimestamp(epoch_candidate, tz=timezone.utc).replace(tzinfo=None)
            return {
                "original": raw_str,
                "normalized_utc": dt_utc,
                "status": "UNIX_TIMESTAMP",
                "assumptions": f"Parsed as Unix epoch timestamp ({epoch_candidate:.3f}s), converted directly to UTC.",
            }
        except Exception as e:
            return {
                "original": raw_str,
                "normalized_utc": None,
                "status": "INVALID",
                "assumptions": f"Failed converting epoch value {epoch_candidate}: {str(e)}",
            }

    # 2. Check for Syslog format (e.g. "Oct 30 10:15:23")
    syslog_match = SYSLOG_TS_REGEX.match(raw_str)
    if syslog_match:
        mon_str = syslog_match.group("month")
        day_str = syslog_match.group("day")
        time_str = syslog_match.group("time")
        month = MONTH_MAP.get(mon_str.capitalize())
        if month:
            ref_year = reference_year or datetime.utcnow().year
            try:
                time_parts = [int(p) for p in time_str.split(":")]
                micro = int(syslog_match.group("micro") or 0)
                parsed_dt = datetime(ref_year, month, int(day_str), time_parts[0], time_parts[1], time_parts[2], micro)

                if source_timezone:
                    tz_obj = _resolve_timezone(source_timezone)
                    if tz_obj:
                        if hasattr(tz_obj, "localize"):
                            loc_dt = tz_obj.localize(parsed_dt)
                        else:
                            loc_dt = parsed_dt.replace(tzinfo=tz_obj)
                        dt_utc = loc_dt.astimezone(timezone.utc).replace(tzinfo=None)
                        return {
                            "original": raw_str,
                            "normalized_utc": dt_utc,
                            "status": "SYSLOG_NO_YEAR",
                            "assumptions": f"Syslog lacked year; estimated year {ref_year} and converted via source timezone {source_timezone}.",
                        }

                # If no source timezone provided, syslog cannot be deterministically UTC
                return {
                    "original": raw_str,
                    "normalized_utc": parsed_dt,
                    "status": "SYSLOG_NO_YEAR",
                    "assumptions": f"Syslog lacked year; estimated year {ref_year}. No timezone present; assumed local reference.",
                }
            except Exception as e:
                return {
                    "original": raw_str,
                    "normalized_utc": None,
                    "status": "INVALID",
                    "assumptions": f"Malformed syslog date components: {str(e)}",
                }

    # 3. Standard parsing (ISO 8601, RFC 3339, common formats)
    try:
        parsed_dt = dt_parser.parse(raw_str)
    except Exception as e:
        return {
            "original": raw_str,
            "normalized_utc": None,
            "status": "INVALID",
            "assumptions": f"Timestamp could not be parsed: {str(e)}",
        }

    # Analyze timezone awareness
    if parsed_dt.tzinfo is not None:
        tz_offset = parsed_dt.utcoffset()
        dt_utc = parsed_dt.astimezone(timezone.utc).replace(tzinfo=None)

        # Check if explicit UTC (offset is 0 and indicator present)
        is_explicit_utc = (
            tz_offset is not None
            and tz_offset.total_seconds() == 0
            and ("Z" in raw_str or "UTC" in raw_str.upper() or "+00:00" in raw_str or "+0000" in raw_str)
        )

        if is_explicit_utc:
            return {
                "original": raw_str,
                "normalized_utc": dt_utc,
                "status": "UTC_CONFIRMED",
                "assumptions": "Explicit UTC indicator found and verified.",
            }

        # Check if named timezone or numerical offset
        if re.search(r"[+-]\d{2}:?\d{2}", raw_str):
            return {
                "original": raw_str,
                "normalized_utc": dt_utc,
                "status": "OFFSET_CONVERTED",
                "assumptions": f"Converted from explicit UTC offset ({tz_offset}) to UTC.",
            }

        return {
            "original": raw_str,
            "normalized_utc": dt_utc,
            "status": "TIMEZONE_CONVERTED",
            "assumptions": f"Converted from timezone {parsed_dt.tzname() or parsed_dt.tzinfo} to UTC.",
        }

    # Naive timestamp (No timezone info attached)
    if source_timezone:
        tz_obj = _resolve_timezone(source_timezone)
        if tz_obj:
            try:
                if hasattr(tz_obj, "localize"):
                    loc_dt = tz_obj.localize(parsed_dt)
                else:
                    loc_dt = parsed_dt.replace(tzinfo=tz_obj)
                dt_utc = loc_dt.astimezone(timezone.utc).replace(tzinfo=None)
                return {
                    "original": raw_str,
                    "normalized_utc": dt_utc,
                    "status": "SOURCE_TZ_USED",
                    "assumptions": f"No timezone info in raw timestamp; converted using investigator-provided source timezone '{source_timezone}'.",
                }
            except Exception as e:
                return {
                    "original": raw_str,
                    "normalized_utc": None,
                    "status": "INVALID",
                    "assumptions": f"Failed applying source timezone '{source_timezone}': {str(e)}",
                }

    # Strict Forensics: Never silently assume UTC!
    return {
        "original": raw_str,
        "normalized_utc": None,
        "status": "UNCERTAIN",
        "assumptions": "No timezone info present in record and no source timezone provided. Timestamp marked UNCERTAIN; UTC conversion omitted to prevent forensic contamination.",
    }


def apply_clock_skew(ts_norm: Dict[str, Any], clock_skew_seconds: Optional[int]) -> Dict[str, Any]:
    """Apply an explicit investigator-provided clock skew correction to a normalized timestamp."""
    if not clock_skew_seconds or ts_norm.get("normalized_utc") is None:
        return ts_norm

    adjusted = ts_norm["normalized_utc"] + timedelta(seconds=int(clock_skew_seconds))
    return {
        **ts_norm,
        "normalized_utc": adjusted,
        "status": "CLOCK_SKEW_ADJUSTED",
        "assumptions": (
            f"{ts_norm.get('assumptions', '')} Applied explicit clock skew correction of "
            f"{int(clock_skew_seconds):+d} seconds."
        ).strip(),
    }

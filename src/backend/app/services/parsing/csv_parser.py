"""Forensic CSV log parser with flexible field detection."""

import csv
import io
import json
from typing import Optional, List, Dict, Any
from app.services.parsing.base_parser import BaseParser, ParsedRecord
from app.services.normalization.event_normalizer import categorize_event, normalize_severity


TIMESTAMP_COLUMNS = [
    "timestamp", "@timestamp", "datetime", "date_time", "time", "date",
    "ts", "event_time", "log_time", "event_timestamp"
]

SEVERITY_COLUMNS = [
    "severity", "level", "priority", "loglevel", "log_level", "status_code"
]

SOURCE_IP_COLUMNS = [
    "src_ip", "source_ip", "client_ip", "remote_addr", "ip", "srcip",
    "clientip", "c_ip", "src_host", "source_address"
]

DEST_IP_COLUMNS = [
    "dest_ip", "destination_ip", "dst_ip", "dstip", "server_ip", "target_ip",
    "s_ip", "dest_host", "destination_address"
]

USERNAME_COLUMNS = [
    "username", "user", "account", "login", "user_id", "src_user",
    "dst_user", "principal", "actor"
]

EVENT_TYPE_COLUMNS = [
    "event_type", "event", "type", "action", "activity", "category",
    "operation", "method", "command"
]

DESCRIPTION_COLUMNS = [
    "description", "message", "msg", "details", "text", "info", "raw",
    "request", "uri", "path", "reason"
]


class CSVParser(BaseParser):
    """Parses arbitrary CSV log files, extracting forensic fields."""

    def _find_field_match(self, row: Dict[str, Any], candidates: List[str]) -> Optional[str]:
        """Find matching key in row insensitive to case and underscores/spaces."""
        normalized_row = {
            str(k).strip().lower().replace(" ", "_").replace("-", "_"): v
            for k, v in row.items() if k is not None
        }

        for candidate in candidates:
            cand_norm = candidate.lower().replace(" ", "_").replace("-", "_")
            if cand_norm in normalized_row and normalized_row[cand_norm] is not None:
                val = str(normalized_row[cand_norm]).strip()
                if val and val.lower() != "nan" and val.lower() != "none":
                    return val
        return None

    def parse(self, content: str, default_source: Optional[str] = "CSV_IMPORT") -> List[ParsedRecord]:
        """Parse CSV string into a list of standardized ParsedRecord items."""
        records: List[ParsedRecord] = []
        if not content or not content.strip():
            return records

        # Handle sniffing dialect safely
        f = io.StringIO(content.strip())
        try:
            sample = content[:4096]
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
            except Exception:
                dialect = csv.excel
            f.seek(0)
            reader = csv.DictReader(f, dialect=dialect)
        except Exception:
            # Fallback to standard comma reader
            f.seek(0)
            reader = csv.DictReader(f)

        for line_no, row in enumerate(reader, start=1):
            if not row or not any(row.values()):
                continue

            raw_line = json.dumps(row, default=str)

            ts = self._find_field_match(row, TIMESTAMP_COLUMNS)
            src_ip = self._find_field_match(row, SOURCE_IP_COLUMNS)
            dst_ip = self._find_field_match(row, DEST_IP_COLUMNS)
            user = self._find_field_match(row, USERNAME_COLUMNS)
            event_type = self._find_field_match(row, EVENT_TYPE_COLUMNS)
            desc = self._find_field_match(row, DESCRIPTION_COLUMNS)
            raw_sev = self._find_field_match(row, SEVERITY_COLUMNS)
            src_sys = self._find_field_match(row, ["host", "hostname", "source", "source_system"]) or default_source

            # If description not found, create readable summary from remaining fields
            if not desc:
                desc_parts = [f"{k}={v}" for k, v in row.items() if v and str(v).strip()]
                desc = ", ".join(desc_parts[:4]) if desc_parts else "CSV Log Entry"

            category = categorize_event(description=desc, event_type=event_type, raw_record=raw_line)
            severity = normalize_severity(raw_sev, event_category=category)

            # Store unmatched attributes in extra_fields
            extra = {}
            for k, v in row.items():
                if k is not None and v is not None:
                    k_str = str(k).strip()
                    extra[k_str] = v

            record = ParsedRecord(
                original_timestamp=ts,
                source_system=src_sys,
                event_type=event_type or category,
                event_category=category,
                username=user,
                source_ip=src_ip,
                dest_ip=dst_ip,
                severity=severity,
                description=desc,
                raw_record=raw_line,
                extra_fields=extra,
            )
            record.evaluate_status()
            records.append(record)

        return records

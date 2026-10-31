"""Forensic JSON log parser supporting arrays, single objects, and NDJSON."""

import json
from typing import Optional, List, Dict, Any
from app.services.parsing.base_parser import BaseParser, ParsedRecord
from app.services.parsing.csv_parser import (
    TIMESTAMP_COLUMNS,
    SEVERITY_COLUMNS,
    SOURCE_IP_COLUMNS,
    DEST_IP_COLUMNS,
    USERNAME_COLUMNS,
    EVENT_TYPE_COLUMNS,
    DESCRIPTION_COLUMNS,
)
from app.services.normalization.event_normalizer import categorize_event, normalize_severity


class JSONParser(BaseParser):
    """Parses JSON documents, nested event objects, and JSON Lines."""

    def _flatten_one_level(self, d: Dict[str, Any], parent_key: str = "", sep: str = "_") -> Dict[str, Any]:
        """Flatten dictionary by exactly one level to surface nested fields."""
        items: List[tuple] = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
            if isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    sub_key = f"{new_key}{sep}{sub_k}"
                    items.append((sub_key, sub_v))
                items.append((new_key, json.dumps(v, default=str)))
            else:
                items.append((new_key, v))
        return dict(items)

    def _find_field_match(self, row: Dict[str, Any], candidates: List[str]) -> Optional[str]:
        """Find matching value from flattened map."""
        normalized_row = {
            str(k).strip().lower().replace(" ", "_").replace("-", "_"): v
            for k, v in row.items() if k is not None
        }

        for candidate in candidates:
            cand_norm = candidate.lower().replace(" ", "_").replace("-", "_")
            if cand_norm in normalized_row and normalized_row[cand_norm] is not None:
                val = str(normalized_row[cand_norm]).strip()
                if val and val.lower() != "none" and val.lower() != "null":
                    return val
        return None

    def _parse_single_dict(self, item: Dict[str, Any], raw_record: str, default_source: Optional[str]) -> ParsedRecord:
        """Parse one dictionary record."""
        flattened = self._flatten_one_level(item)

        ts = self._find_field_match(flattened, TIMESTAMP_COLUMNS)
        src_ip = self._find_field_match(flattened, SOURCE_IP_COLUMNS)
        dst_ip = self._find_field_match(flattened, DEST_IP_COLUMNS)
        user = self._find_field_match(flattened, USERNAME_COLUMNS)
        event_type = self._find_field_match(flattened, EVENT_TYPE_COLUMNS)
        desc = self._find_field_match(flattened, DESCRIPTION_COLUMNS)
        raw_sev = self._find_field_match(flattened, SEVERITY_COLUMNS)
        src_sys = (
            self._find_field_match(flattened, ["host", "hostname", "source", "source_system"])
            or default_source
        )

        if not desc:
            desc_parts = [f"{k}={v}" for k, v in item.items() if not isinstance(v, (dict, list)) and v]
            desc = ", ".join(desc_parts[:4]) if desc_parts else "JSON Log Event"

        category = categorize_event(description=desc, event_type=event_type, raw_record=raw_record)
        severity = normalize_severity(raw_sev, event_category=category)

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
            raw_record=raw_record,
            extra_fields=item,
        )
        record.evaluate_status()
        return record

    def parse(self, content: str, default_source: Optional[str] = "JSON_IMPORT") -> List[ParsedRecord]:
        """Parse JSON array, single JSON object, or JSON Lines (NDJSON)."""
        records: List[ParsedRecord] = []
        if not content or not content.strip():
            return records

        clean_content = content.strip()

        # Attempt 1: Standard JSON parse (Array or Object)
        try:
            parsed_data = json.loads(clean_content)
            if isinstance(parsed_data, list):
                for item in parsed_data:
                    if isinstance(item, dict):
                        raw_str = json.dumps(item, default=str)
                        records.append(self._parse_single_dict(item, raw_str, default_source))
                    else:
                        raw_str = str(item)
                        rec = ParsedRecord(raw_record=raw_str, description=raw_str, parsing_status="PARTIAL")
                        records.append(rec)
                return records
            elif isinstance(parsed_data, dict):
                raw_str = json.dumps(parsed_data, default=str)
                records.append(self._parse_single_dict(parsed_data, raw_str, default_source))
                return records
        except json.JSONDecodeError:
            pass

        # Attempt 2: JSON Lines (NDJSON)
        lines = [line.strip() for line in clean_content.splitlines() if line.strip()]
        ndjson_parsed = 0
        for line in lines:
            try:
                line_data = json.loads(line)
                if isinstance(line_data, dict):
                    records.append(self._parse_single_dict(line_data, line, default_source))
                    ndjson_parsed += 1
            except Exception:
                continue

        if ndjson_parsed > 0:
            return records

        # If completely unparseable JSON, return a single FAILED record
        failed_rec = ParsedRecord(
            raw_record=clean_content[:2000],
            description="Malformed JSON document could not be decoded.",
            parsing_status="FAILED",
            extra_fields={"error": "JSONDecodeError"}
        )
        records.append(failed_rec)
        return records

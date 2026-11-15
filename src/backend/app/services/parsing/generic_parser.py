"""Generic parser for CEF, LEEF, logfmt/key-value, and unknown text logs."""

import re
import shlex
from typing import Any, Dict, Iterable, Iterator, List, Optional, TextIO, Tuple

from app.services.normalization.event_normalizer import (
    EVENT_CATEGORIES,
    categorize_event,
    normalize_severity,
)
from app.services.parsing.base_parser import BaseParser, ParsedRecord
from app.services.parsing.syslog_parser import SyslogParser

CEF_PREFIX_REGEX = re.compile(r"\bCEF:\s*\d+(?:\.\d+)?\|")
LEEF_PREFIX_REGEX = re.compile(r"\bLEEF:\s*\d+(?:\.\d+)?\|")

SYSLOG_PREFIX_REGEX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s*(?P<rest>.*)$"
)
ISO_PREFIX_REGEX = re.compile(
    r"^(?:\d+\s+)?(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<hostname>\S+)\s*(?P<rest>.*)$"
)

KV_TOKEN_REGEX = re.compile(
    r"(?P<key>[A-Za-z_@][\w.@\-]*)="
    r"(?P<value>\"(?:[^\"\\]|\\.)*\"|.*?)"
    r"(?=\s+[A-Za-z_@][\w.@\-]*=|$)",
    re.DOTALL,
)
KV_PAIR_REGEX = re.compile(r"(?:^|\s)[A-Za-z_@][\w.@\-]*=")
LOGFMT_START_REGEX = re.compile(r"^\s*(?:<\d+>\s*)?[A-Za-z_@][\w.@\-]*=")
HEX_DELIMITER_REGEX = re.compile(r"^(?:0x|x)([0-9a-fA-F]{1,4})$")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]*:[0-9a-fA-F:]+\b")
FALLBACK_IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

DEFAULT_FIELD_ALIASES: Dict[str, Iterable[str]] = {
    "timestamp": (
        "timestamp", "@timestamp", "ts", "time", "date", "datetime", "event_time",
        "eventtime", "devtime", "rt", "art", "mrt", "receipt_time",
        "device_receipt_time", "start", "end", "starttime", "endtime",
        "start_time", "end_time", "update_time", "created_at", "log_time",
        "logtime", "dev_time",
    ),
    "source_ip": (
        "src", "source_ip", "src_ip", "sourceip", "srcip", "source_address",
        "sourceaddress", "sip", "srcaddr", "client_ip", "clientip",
        "remote_addr", "remoteaddr", "ip", "source_host", "src_host",
        "r_clienthost", "r_client_ip", "message_source_address",
        "offender_ip",
    ),
    "dest_ip": (
        "dst", "dest_ip", "dst_ip", "dstip", "destination_ip", "destinationip",
        "destination_address", "destaddress", "dip", "dstaddr", "dest",
        "dest_host", "dst_host", "destination_host", "victim_ip",
    ),
    "username": (
        "user", "username", "user_name", "usrname", "suser", "duser",
        "account", "login", "src_user", "actor", "actorupn", "principal",
        "u_username", "src_username", "target_user",
    ),
    "event_type": (
        "event_type", "event", "type", "action", "activity", "eventid",
        "event_id", "signature", "signatureid", "event_code", "name",
        "operation", "method", "tag", "code", "logid",
    ),
    "description": (
        "msg", "message", "description", "text", "details", "reason",
        "summary", "eventname", "name", "signature", "desc", "error", "err",
    ),
    "severity": (
        "severity", "sev", "level", "loglevel", "priority", "risk", "score",
        "severityvalue", "deviceseverity", "severity_label",
    ),
    "source_system": (
        "host", "hostname", "device", "dvc", "dvchost", "devname", "source",
        "source_system", "sourcesystem", "devicehostname", "ahost",
        "src_host", "host_name", "service", "app", "component",
    ),
    "category": (
        "category", "cat", "catdt", "categorybehavior", "event_category",
        "eventcategory", "class", "event_class",
    ),
}


def _normalize_key(key: str) -> str:
    return key.strip().lower().lstrip("@").replace("-", "_").replace(".", "_")


def _split_unescaped(text: str, separator: str, maxsplit: int = -1) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    escaped = False
    splits = 0
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == separator and (maxsplit < 0 or splits < maxsplit):
            parts.append("".join(current))
            current = []
            splits += 1
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _unescape_value(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ("'", '"'):
        cleaned = cleaned[1:-1]
    return (
        cleaned.replace("\\|", "|")
        .replace("\\=", "=")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\\\", "\\")
    )


def _count_key_value_pairs(line: str) -> int:
    return len(KV_PAIR_REGEX.findall(line))


def is_generic_line(line: str) -> bool:
    """Return True for CEF/LEEF lines and logfmt lines that begin with a key."""
    return bool(
        CEF_PREFIX_REGEX.search(line)
        or LEEF_PREFIX_REGEX.search(line)
        or (LOGFMT_START_REGEX.match(line) and _count_key_value_pairs(line) >= 2)
    )


class GenericParser(BaseParser):
    """Best-effort parser for structured text logs not covered by a native parser."""

    def __init__(self, field_aliases: Optional[Dict[str, Iterable[str]]] = None):
        self._syslog = SyslogParser()
        self.field_aliases = {
            field: tuple(aliases)
            for field, aliases in (field_aliases or DEFAULT_FIELD_ALIASES).items()
        }
        self._alias_to_field: Dict[str, str] = {}
        for field, aliases in self.field_aliases.items():
            for alias in (field, *aliases):
                self._alias_to_field[_normalize_key(alias)] = field

    def _lookup(self, fields: Dict[str, str], normalized: Dict[str, str], field: str) -> Optional[str]:
        for alias in self.field_aliases.get(field, ()):
            value = normalized.get(_normalize_key(alias))
            if value not in (None, ""):
                return value
        return None

    def _severity_from_value(self, value: Optional[str], category: str) -> str:
        if not value:
            return normalize_severity(None, event_category=category)

        text = str(value).strip()
        try:
            score = float(text)
        except ValueError:
            score = None

        if score is not None:
            if score <= 0:
                return "INFO"
            if score <= 3:
                return "LOW"
            if score <= 6:
                return "MEDIUM"
            if score <= 8:
                return "HIGH"
            return "CRITICAL"

        return normalize_severity(text, event_category=category)

    def _resolve_category(
        self,
        explicit_category: Optional[str],
        description: str,
        event_type: str,
        raw_record: str,
    ) -> str:
        if explicit_category:
            normalized = explicit_category.strip().upper().replace(" ", "_").replace("-", "_")
            if normalized in EVENT_CATEGORIES:
                return normalized
            mapped = categorize_event(
                description=explicit_category,
                event_type=event_type,
                raw_record=raw_record,
            )
            if mapped != "UNCATEGORIZED":
                return mapped

        return categorize_event(
            description=description,
            event_type=event_type,
            raw_record=raw_record,
        )

    def _parse_key_value_extension(self, text: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        if not text:
            return fields
        for match in KV_TOKEN_REGEX.finditer(text):
            key = match.group("key").strip()
            value = _unescape_value(match.group("value"))
            if key:
                fields[key] = value
        return fields

    def _resolve_delimiter(self, delimiter: Optional[str]) -> Optional[str]:
        if delimiter is None:
            return None
        candidate = delimiter.strip()
        if candidate == "":
            return None
        if candidate.lower() in ("\\t", "tab"):
            return "\t"
        hex_match = HEX_DELIMITER_REGEX.match(candidate)
        if hex_match:
            try:
                codepoint = int(hex_match.group(1), 16)
                if 0 < codepoint <= 0x10FFFF:
                    return chr(codepoint)
            except ValueError:
                return None
        if len(candidate) == 1:
            return candidate
        return None

    def _parse_delimited_extension(self, text: str, delimiter: Optional[str]) -> Dict[str, str]:
        separator = self._resolve_delimiter(delimiter)
        if separator is None:
            return self._parse_key_value_extension(text)

        fields: Dict[str, str] = {}
        for segment in text.split(separator):
            if "=" not in segment:
                continue
            key, value = segment.split("=", 1)
            key = key.strip()
            if key:
                fields[key] = _unescape_value(value)
        return fields

    def _parse_logfmt(self, text: str) -> Dict[str, str]:
        fields: Dict[str, str] = {}
        try:
            tokens = shlex.split(text, posix=True)
        except ValueError:
            tokens = text.split()

        for token in tokens:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            key = key.strip()
            if key:
                fields[key] = value
        return fields

    def _strip_syslog_prefix(self, line: str) -> Tuple[Optional[str], Optional[str], str]:
        without_priority = re.sub(r"^<\d+>", "", line).strip()
        match = SYSLOG_PREFIX_REGEX.match(without_priority) or ISO_PREFIX_REGEX.match(without_priority)
        if match:
            return (
                match.group("timestamp"),
                match.group("hostname"),
                match.group("rest").strip(),
            )
        return None, None, without_priority

    def _build_record(
        self,
        raw_record: str,
        default_source: Optional[str],
        fields: Dict[str, str],
        header_fields: Dict[str, Any],
        prefix_timestamp: Optional[str],
        prefix_hostname: Optional[str],
        fallback_event_type: str,
        fallback_description: Optional[str],
        fallback_source_system: Optional[str],
        severity_override: Optional[str] = None,
        log_format: str = "generic",
    ) -> ParsedRecord:
        normalized = {_normalize_key(key): value for key, value in fields.items()}

        timestamp = self._lookup(fields, normalized, "timestamp") or prefix_timestamp
        date_value = normalized.get(_normalize_key("date"))
        time_value = normalized.get(_normalize_key("time"))
        if date_value and time_value and timestamp in (date_value, time_value):
            timestamp = f"{date_value} {time_value}"
        source_ip = self._lookup(fields, normalized, "source_ip")
        if not source_ip and log_format == "keyvalue":
            ip_match = FALLBACK_IP_REGEX.search(raw_record)
            source_ip = ip_match.group(0) if ip_match else None
        dest_ip = self._lookup(fields, normalized, "dest_ip")
        username = self._lookup(fields, normalized, "username")
        event_type = self._lookup(fields, normalized, "event_type") or fallback_event_type
        description = (
            self._lookup(fields, normalized, "description")
            or fallback_description
            or raw_record
        )
        explicit_category = self._lookup(fields, normalized, "category")
        category = self._resolve_category(explicit_category, description, event_type, "")
        severity_value = severity_override or self._lookup(fields, normalized, "severity")
        severity = self._severity_from_value(severity_value, category)
        source_system = (
            self._lookup(fields, normalized, "source_system")
            or fallback_source_system
            or prefix_hostname
            or default_source
            or "Generic Log"
        )

        extra_fields: Dict[str, Any] = {
            "log_format": log_format,
            **header_fields,
            **fields,
        }

        record = ParsedRecord(
            original_timestamp=timestamp,
            source_system=source_system,
            event_type=event_type,
            event_category=category,
            username=username,
            source_ip=source_ip,
            dest_ip=dest_ip,
            severity=severity,
            description=description,
            raw_record=raw_record,
            extra_fields=extra_fields,
        )
        record.evaluate_status()
        return record

    def _parse_cef(self, line: str, default_source: Optional[str]) -> Optional[ParsedRecord]:
        index = line.find("CEF:")
        if index < 0:
            return None

        prefix = line[:index].strip()
        parts = _split_unescaped(line[index:].strip(), "|", maxsplit=7)
        if len(parts) < 7:
            return None

        version_match = re.match(r"CEF:\s*(\d+(?:\.\d+)?)", parts[0])
        vendor = _unescape_value(parts[1])
        product = _unescape_value(parts[2])
        device_version = _unescape_value(parts[3])
        signature_id = _unescape_value(parts[4])
        name = _unescape_value(parts[5])
        header_severity = _unescape_value(parts[6])
        extension = self._parse_key_value_extension(parts[7] if len(parts) > 7 else "")
        prefix_timestamp, prefix_hostname, _ = self._strip_syslog_prefix(prefix)

        header_fields = {
            "cef_version": version_match.group(1) if version_match else None,
            "cef_vendor": vendor,
            "cef_product": product,
            "cef_device_version": device_version,
            "cef_signature_id": signature_id,
            "cef_name": name,
            "cef_severity": header_severity,
        }

        return self._build_record(
            raw_record=line,
            default_source=default_source,
            fields=extension,
            header_fields=header_fields,
            prefix_timestamp=prefix_timestamp,
            prefix_hostname=prefix_hostname,
            fallback_event_type=signature_id or "cef_event",
            fallback_description=name or signature_id,
            fallback_source_system=f"{vendor} {product}".strip() or None,
            severity_override=header_severity,
            log_format="cef",
        )

    def _parse_leef(self, line: str, default_source: Optional[str]) -> Optional[ParsedRecord]:
        index = line.find("LEEF:")
        if index < 0:
            return None

        prefix = line[:index].strip()
        parts = _split_unescaped(line[index:].strip(), "|", maxsplit=6)
        if len(parts) < 5:
            return None

        version_match = re.match(r"LEEF:\s*(\d+(?:\.\d+)?)", parts[0])
        vendor = _unescape_value(parts[1])
        product = _unescape_value(parts[2])
        device_version = _unescape_value(parts[3])
        event_id = _unescape_value(parts[4])

        delimiter = None
        extension_text = ""
        if len(parts) == 7:
            candidate = parts[5].strip()
            resolved = self._resolve_delimiter(candidate)
            if candidate == "" or resolved is not None:
                delimiter = candidate
                extension_text = parts[6]
            else:
                extension_text = "|".join(parts[5:])
        elif len(parts) == 6:
            extension_text = parts[5]

        extension = self._parse_delimited_extension(extension_text, delimiter)
        prefix_timestamp, prefix_hostname, _ = self._strip_syslog_prefix(prefix)

        header_fields = {
            "leef_version": version_match.group(1) if version_match else None,
            "leef_vendor": vendor,
            "leef_product": product,
            "leef_device_version": device_version,
            "leef_event_id": event_id,
            "leef_delimiter": delimiter,
        }

        return self._build_record(
            raw_record=line,
            default_source=default_source,
            fields=extension,
            header_fields=header_fields,
            prefix_timestamp=prefix_timestamp,
            prefix_hostname=prefix_hostname,
            fallback_event_type=event_id or "leef_event",
            fallback_description=event_id,
            fallback_source_system=f"{vendor} {product}".strip() or None,
            log_format="leef",
        )

    def _parse_key_value_line(self, line: str, default_source: Optional[str]) -> Optional[ParsedRecord]:
        prefix_timestamp, prefix_hostname, body = self._strip_syslog_prefix(line)
        fields = self._parse_logfmt(body)
        if not fields:
            return None

        return self._build_record(
            raw_record=line,
            default_source=default_source,
            fields=fields,
            header_fields={},
            prefix_timestamp=prefix_timestamp,
            prefix_hostname=prefix_hostname,
            fallback_event_type="generic_event",
            fallback_description=None,
            fallback_source_system=None,
            log_format="keyvalue",
        )

    def parse_line(self, line: str, default_source: Optional[str] = None) -> ParsedRecord:
        """Parse CEF, LEEF, logfmt/key-value, or fall back to syslog parsing."""
        clean_line = line.strip()
        if not clean_line:
            return ParsedRecord(raw_record=line, parsing_status="FAILED")

        if CEF_PREFIX_REGEX.search(clean_line):
            record = self._parse_cef(clean_line, default_source)
            if record is not None:
                return record

        if LEEF_PREFIX_REGEX.search(clean_line):
            record = self._parse_leef(clean_line, default_source)
            if record is not None:
                return record

        if is_generic_line(clean_line) or LOGFMT_START_REGEX.match(clean_line):
            record = self._parse_key_value_line(clean_line, default_source)
            if record is not None:
                return record

        return self._syslog.parse_line(clean_line, default_source)

    def parse_stream(self, stream: TextIO, default_source: Optional[str] = "Generic Log") -> Iterator[ParsedRecord]:
        """Parse generic log lines lazily without loading the artifact into memory."""
        for line in stream:
            line_str = line.strip()
            if not line_str:
                continue
            yield self.parse_line(line_str, default_source=default_source)

    def parse(self, content: str, default_source: Optional[str] = "Generic Log") -> List[ParsedRecord]:
        """Parse full generic log text into ParsedRecord list."""
        if not content or not content.strip():
            return []
        return list(self.parse_stream(content.splitlines(True), default_source=default_source))

"""Forensic parser for Apache HTTP Server error and access logs."""

import re
from typing import Optional, List, Dict, Any, Iterator, TextIO

from app.services.parsing.base_parser import BaseParser, ParsedRecord
from app.services.normalization.event_normalizer import normalize_severity

APACHE_ERROR_REGEX = re.compile(
    r"^\[[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?\s+\d{4}\]\s+\[[^\]]+\]"
)

APACHE_ACCESS_REGEX = re.compile(
    r"^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+\"(?:[A-Z]+|-)\s+\S+"
)

APACHE_ERROR_LINE_REGEX = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+"
    r"\[(?P<level>[^\]]+)\]"
    r"(?:\s+\[pid [^\]]+\])?"
    r"(?:\s+\[client (?P<client>[^\]]+)\])?"
    r"\s*(?P<message>.*)$"
)

APACHE_ACCESS_LINE_REGEX = re.compile(
    r"^(?P<ip>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"\"(?P<request>[^\"]*)\"\s+"
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\S+)"
    r"(?:\s+\"(?P<referer>[^\"]*)\"\s+\"(?P<agent>[^\"]*)\")?"
)

MISSING_RESOURCE_PATTERNS = (
    "file does not exist",
    "script not found",
    "unable to stat",
    "no such file or directory",
    "file name too long",
)

ACCESS_DENIED_PATTERNS = (
    "client denied by server configuration",
    "access denied",
    "authorization required",
    "authentication required",
    "directory index forbidden",
)

CLIENT_REQUEST_PATTERNS = (
    "attempt to invoke directory as script",
    "request failed:",
    "invalid method in request",
    "invalid uri in request",
)

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]*:[0-9a-fA-F:]+\b")


class ApacheParser(BaseParser):
    """Parses Apache error logs and common/combined access logs."""

    def _classify_error_message(self, message: str, severity_name: str):
        """Classify an Apache error-log message without conflating 4xx with app failures."""
        lower_message = message.lower()

        if any(pattern in lower_message for pattern in MISSING_RESOURCE_PATTERNS):
            return "apache_missing_resource", "HTTP_REQUEST", "LOW"
        if any(pattern in lower_message for pattern in ACCESS_DENIED_PATTERNS):
            return "apache_access_denied", "HTTP_REQUEST", "MEDIUM"
        if any(pattern in lower_message for pattern in CLIENT_REQUEST_PATTERNS):
            return "apache_client_error", "HTTP_REQUEST", "LOW"
        if severity_name in ("emerg", "alert", "crit", "error"):
            return (
                "apache_error",
                "APPLICATION_ERROR",
                normalize_severity(severity_name, event_category="APPLICATION_ERROR"),
            )
        if severity_name == "warn":
            return "apache_warning", "APPLICATION_ERROR", "MEDIUM"
        return f"apache_{severity_name or 'notice'}", "SYSTEM_EVENT", normalize_severity(severity_name)

    def _parse_error_line(self, line: str, default_source: Optional[str]) -> ParsedRecord:
        match = APACHE_ERROR_LINE_REGEX.match(line)
        if not match:
            event_type, category, severity = self._classify_error_message(line, "")
            record = ParsedRecord(
                raw_record=line,
                description=line,
                source_system=default_source or "Apache HTTP Server",
                event_type=event_type,
                event_category=category,
                severity=severity,
                parsing_status="PARTIAL",
            )
            return record

        timestamp = match.group("timestamp").strip()
        level = match.group("level").strip().lower()
        severity_name = level.split(":")[-1]
        client = (match.group("client") or "").strip()
        message = match.group("message").strip()

        ip_match = IP_REGEX.search(client)
        source_ip = ip_match.group(0) if ip_match else None
        event_type, category, severity = self._classify_error_message(message, severity_name)

        extra: Dict[str, Any] = {
            "apache_level": severity_name,
            "client": client or None,
            "module": level.split(":")[0] if ":" in level else None,
        }

        record = ParsedRecord(
            original_timestamp=timestamp,
            source_system=default_source or "Apache HTTP Server",
            event_type=event_type,
            event_category=category,
            username=None,
            source_ip=source_ip,
            dest_ip=None,
            severity=severity,
            description=message,
            raw_record=line,
            extra_fields=extra,
        )
        record.evaluate_status()
        return record

    def _parse_access_line(self, line: str, default_source: Optional[str]) -> ParsedRecord:
        match = APACHE_ACCESS_LINE_REGEX.match(line)
        if not match:
            record = ParsedRecord(
                raw_record=line,
                description=line,
                source_system=default_source or "Apache HTTP Server",
                event_type="apache_unparsed",
                event_category="UNCATEGORIZED",
                severity="INFO",
                parsing_status="PARTIAL",
            )
            return record

        request = match.group("request").strip()
        request_parts = request.split()
        method = request_parts[0] if request_parts else None
        path = request_parts[1] if len(request_parts) > 1 else None
        protocol = request_parts[2] if len(request_parts) > 2 else None

        status_text = match.group("status")
        try:
            status = int(status_text)
        except ValueError:
            status = None

        if status is not None and status >= 500:
            severity = "HIGH"
        elif status in (401, 403):
            severity = "MEDIUM"
        elif status is not None and status >= 400:
            severity = "LOW"
        else:
            severity = "INFO"

        user = match.group("user")
        if user == "-":
            user = None

        description = request if not status_text else f"{request} {status_text}".strip()
        extra: Dict[str, Any] = {
            "method": method,
            "path": path,
            "protocol": protocol,
            "status": status,
            "bytes": match.group("size"),
            "referer": match.group("referer"),
            "user_agent": match.group("agent"),
        }

        record = ParsedRecord(
            original_timestamp=match.group("timestamp").strip(),
            source_system=default_source or "Apache HTTP Server",
            event_type="http_request",
            event_category="HTTP_REQUEST",
            username=user,
            source_ip=match.group("ip"),
            dest_ip=None,
            severity=severity,
            description=description,
            raw_record=line,
            extra_fields=extra,
        )
        record.evaluate_status()
        return record

    def parse_line(self, line: str, default_source: Optional[str] = None) -> ParsedRecord:
        """Parse a single Apache error or access log line."""
        clean_line = line.strip()
        if not clean_line:
            return ParsedRecord(raw_record=line, parsing_status="FAILED")

        if APACHE_ACCESS_LINE_REGEX.match(clean_line):
            return self._parse_access_line(clean_line, default_source)
        return self._parse_error_line(clean_line, default_source)

    def parse_stream(self, stream: TextIO, default_source: Optional[str] = "Apache HTTP Server") -> Iterator[ParsedRecord]:
        """Parse Apache log lines lazily without loading the artifact into memory."""
        for line in stream:
            line_str = line.strip()
            if not line_str:
                continue
            yield self.parse_line(line_str, default_source=default_source)

    def parse(self, content: str, default_source: Optional[str] = "Apache HTTP Server") -> List[ParsedRecord]:
        """Parse full Apache log text into ParsedRecord list."""
        if not content or not content.strip():
            return []
        return list(self.parse_stream(content.splitlines(True), default_source=default_source))

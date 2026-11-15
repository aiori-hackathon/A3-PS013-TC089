"""Forensic Syslog / Linux auth.log parser."""

import re
from typing import Optional, List, Dict, Any, Iterator, TextIO
from app.services.parsing.base_parser import BaseParser, ParsedRecord
from app.services.normalization.event_normalizer import categorize_event, normalize_severity

# Regex for standard BSD syslog (RFC 3164) e.g. "Oct 30 10:15:23 hostname sshd[1234]: message"
RFC3164_REGEX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Regex for ISO-8601 syslog (RFC 5424) e.g. "2026-10-30T10:15:23.000Z hostname sshd[1234]: message"
RFC5424_REGEX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Sub-patterns for auth.log messages
SSHD_FAILED_PWD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+)(?: port (?P<port>\d+))?",
    re.IGNORECASE
)

SSHD_ACCEPTED_PWD = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+)(?: port (?P<port>\d+))?",
    re.IGNORECASE
)

SSHD_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+)",
    re.IGNORECASE
)

SUDO_EXEC = re.compile(
    r"(?:sudo:\s*)?(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>[^;]*)\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<cmd>.*)",
    re.IGNORECASE
)

PAM_SESSION = re.compile(
    r"session (?P<action>opened|closed) for user (?P<user>\S+)",
    re.IGNORECASE
)

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class SyslogParser(BaseParser):
    """Parses Linux syslog and auth.log streams, extracting forensic artifacts."""

    def parse_line(self, line: str, default_source: Optional[str] = None) -> ParsedRecord:
        """Parse a single syslog line."""
        clean_line = line.strip()
        if not clean_line:
            return ParsedRecord(raw_record=line, parsing_status="FAILED")

        timestamp = None
        hostname = None
        process = None
        pid = None
        message = clean_line

        # Match RFC 3164 or RFC 5424 header
        match = RFC3164_REGEX.match(clean_line) or RFC5424_REGEX.match(clean_line)
        if match:
            timestamp = match.group("timestamp")
            hostname = match.group("hostname")
            process = match.group("process")
            pid = match.group("pid")
            message = match.group("message")
        else:
            # Fallback: check if line starts with syslog date anyway
            date_match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.*)$", clean_line)
            if date_match:
                timestamp = date_match.group(1)
                message = date_match.group(2)

        username = None
        source_ip = None
        event_type = process or "syslog"
        category = "UNCATEGORIZED"
        extra: Dict[str, Any] = {
            "hostname": hostname,
            "process": process,
            "pid": pid,
        }

        # Check specific message patterns
        # 1. Failed Password
        failed_match = SSHD_FAILED_PWD.search(message)
        if failed_match:
            username = failed_match.group("user")
            source_ip = failed_match.group("ip")
            event_type = "sshd_failed_password"
            category = "LOGIN_FAILURE"
            if failed_match.group("port"):
                extra["port"] = failed_match.group("port")

        # 2. Accepted Password
        elif SSHD_ACCEPTED_PWD.search(message):
            acc_match = SSHD_ACCEPTED_PWD.search(message)
            username = acc_match.group("user")
            source_ip = acc_match.group("ip")
            event_type = "sshd_login_success"
            category = "LOGIN_SUCCESS"
            if acc_match.group("port"):
                extra["port"] = acc_match.group("port")

        # 3. Invalid User
        elif SSHD_INVALID_USER.search(message):
            inv_match = SSHD_INVALID_USER.search(message)
            username = inv_match.group("user")
            source_ip = inv_match.group("ip")
            event_type = "sshd_invalid_user"
            category = "LOGIN_FAILURE"

        # 4. Sudo Execution
        elif SUDO_EXEC.search(message):
            sudo_match = SUDO_EXEC.search(message)
            username = sudo_match.group("user")
            event_type = "sudo_execution"
            category = "PRIVILEGE_CHANGE"
            extra["tty"] = sudo_match.group("tty")
            extra["pwd"] = sudo_match.group("pwd")
            extra["target_user"] = sudo_match.group("target_user")
            extra["command"] = sudo_match.group("cmd")

        # 5. PAM Session
        elif PAM_SESSION.search(message):
            pam_match = PAM_SESSION.search(message)
            username = pam_match.group("user")
            act = pam_match.group("action")
            event_type = f"session_{act}"
            category = "LOGIN_SUCCESS" if act == "opened" else "SSH_CONNECTION"

        # General categorization fallback
        if category == "UNCATEGORIZED":
            category = categorize_event(description=message, event_type=event_type, raw_record=clean_line)

        # Extract IP if not found yet
        if not source_ip:
            ip_found = IP_REGEX.search(message)
            if ip_found:
                source_ip = ip_found.group(0)

        severity = normalize_severity(None, event_category=category)

        record = ParsedRecord(
            original_timestamp=timestamp,
            source_system=hostname or default_source or "Linux System",
            event_type=event_type,
            event_category=category,
            username=username,
            source_ip=source_ip,
            dest_ip=None,
            severity=severity,
            description=message,
            raw_record=clean_line,
            extra_fields=extra,
        )
        record.evaluate_status()
        return record

    def parse_stream(self, stream: TextIO, default_source: Optional[str] = "Linux System") -> Iterator[ParsedRecord]:
        """Parse syslog lines lazily without loading the full artifact into memory."""
        for line in stream:
            line_str = line.strip()
            if not line_str:
                continue
            yield self.parse_line(line_str, default_source=default_source)

    def parse(self, content: str, default_source: Optional[str] = "Linux System") -> List[ParsedRecord]:
        """Parse full syslog text into ParsedRecord list."""
        if not content or not content.strip():
            return []
        return list(self.parse_stream(content.splitlines(True), default_source=default_source))

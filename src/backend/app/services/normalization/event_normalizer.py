"""Event categorization and severity normalization service."""

from typing import Optional

EVENT_CATEGORIES = {
    "LOGIN_SUCCESS": [
        "accepted password",
        "successful login",
        "authentication success",
        "logged in",
        "session opened",
        "login success",
    ],
    "LOGIN_FAILURE": [
        "failed password",
        "authentication failure",
        "login failed",
        "invalid password",
        "login denied",
        "authentication failed",
        "invalid user",
    ],
    "SSH_CONNECTION": [
        "sshd",
        "ssh2",
        "ssh connection",
        "disconnected from",
        "connection closed by",
    ],
    "NETWORK_CONNECTION": [
        "connection",
        "connect",
        "tcp",
        "udp",
        "port",
        "syn_flood",
        "firewall",
        "packet",
    ],
    "FILE_ACCESS": [
        "open",
        "read",
        "write",
        "access",
        "stat",
        "chmod",
        "chown",
        "touch",
        "unlink",
    ],
    "PRIVILEGE_CHANGE": [
        "sudo",
        "su ",
        "privilege",
        "root",
        "elevated",
        "admin",
        "setuid",
        "escalation",
    ],
    "HTTP_REQUEST": [
        "get ",
        "post ",
        "put ",
        "delete ",
        "patch ",
        "http/",
        "status",
        "uri",
        "url",
    ],
    "APPLICATION_ERROR": [
        "error",
        "exception",
        "traceback",
        "500",
        "critical",
        "fatal",
        "panic",
        "segmentation fault",
    ],
    "ACCOUNT_CHANGE": [
        "useradd",
        "userdel",
        "passwd",
        "groupadd",
        "account created",
        "account deleted",
        "usermod",
    ],
}

SEVERITY_LEVELS = ["DEBUG", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def categorize_event(
    description: Optional[str] = None,
    event_type: Optional[str] = None,
    raw_record: Optional[str] = None
) -> str:
    """Categorize forensic event based on message content, explicit type, or raw record."""
    combined_text = " ".join(
        filter(None, [str(description or "").lower(), str(event_type or "").lower(), str(raw_record or "").lower()])
    )

    if not combined_text.strip():
        return "UNCATEGORIZED"

    # Prioritize specific high-fidelity categories first
    # 1. Login Failure vs Success
    for term in EVENT_CATEGORIES["LOGIN_FAILURE"]:
        if term in combined_text:
            return "LOGIN_FAILURE"

    for term in EVENT_CATEGORIES["LOGIN_SUCCESS"]:
        if term in combined_text:
            return "LOGIN_SUCCESS"

    # 2. Privilege Change
    for term in EVENT_CATEGORIES["PRIVILEGE_CHANGE"]:
        if term in combined_text:
            return "PRIVILEGE_CHANGE"

    # 3. Account Change
    for term in EVENT_CATEGORIES["ACCOUNT_CHANGE"]:
        if term in combined_text:
            return "ACCOUNT_CHANGE"

    # 4. Application Error
    for term in EVENT_CATEGORIES["APPLICATION_ERROR"]:
        if term in combined_text:
            return "APPLICATION_ERROR"

    # 5. HTTP Request
    for term in EVENT_CATEGORIES["HTTP_REQUEST"]:
        if term in combined_text:
            return "HTTP_REQUEST"

    # 6. SSH / Network
    for term in EVENT_CATEGORIES["SSH_CONNECTION"]:
        if term in combined_text:
            return "SSH_CONNECTION"

    for term in EVENT_CATEGORIES["NETWORK_CONNECTION"]:
        if term in combined_text:
            return "NETWORK_CONNECTION"

    # 7. File Access
    for term in EVENT_CATEGORIES["FILE_ACCESS"]:
        if term in combined_text:
            return "FILE_ACCESS"

    return "UNCATEGORIZED"


def normalize_severity(
    raw_severity: Optional[str],
    event_category: Optional[str] = None
) -> str:
    """Normalize log severity to standard levels: DEBUG, INFO, LOW, MEDIUM, HIGH, CRITICAL."""
    if not raw_severity:
        # Default based on category
        if event_category == "LOGIN_FAILURE":
            return "MEDIUM"
        elif event_category in ("PRIVILEGE_CHANGE", "ACCOUNT_CHANGE"):
            return "HIGH"
        elif event_category == "APPLICATION_ERROR":
            return "HIGH"
        return "INFO"

    sev_clean = str(raw_severity).strip().upper()

    # Direct match
    if sev_clean in SEVERITY_LEVELS:
        return sev_clean

    # Common aliases
    if sev_clean in ("WARN", "WARNING"):
        return "MEDIUM"
    elif sev_clean in ("ERR", "ERROR", "ALERT"):
        return "HIGH"
    elif sev_clean in ("EMERGENCY", "FATAL", "CRIT"):
        return "CRITICAL"
    elif sev_clean in ("NOTICE", "INFORMATIONAL", "LOG"):
        return "INFO"
    elif sev_clean in ("TRACE", "VERBOSE"):
        return "DEBUG"

    # Check numeric syslog severities (0=Emergency, 1=Alert, 2=Crit, 3=Err, 4=Warn, 5=Notice, 6=Info, 7=Debug)
    if sev_clean.isdigit():
        code = int(sev_clean)
        if code in (0, 1, 2):
            return "CRITICAL"
        elif code == 3:
            return "HIGH"
        elif code == 4:
            return "MEDIUM"
        elif code in (5, 6):
            return "INFO"
        elif code >= 7:
            return "DEBUG"

    return "INFO"

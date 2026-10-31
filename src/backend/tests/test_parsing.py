"""Unit tests for CSV, JSON, and Syslog forensic parsers."""

import json
from app.services.parsing.csv_parser import CSVParser
from app.services.parsing.json_parser import JSONParser
from app.services.parsing.syslog_parser import SyslogParser


def test_csv_parser_valid_data():
    """Verify standard CSV with timestamp, ip, user, and message is parsed properly."""
    csv_content = """timestamp,source_ip,username,event_type,message,severity
2026-10-30T10:15:00Z,192.168.1.100,admin,LOGIN,Failed password for admin,HIGH
2026-10-30T10:15:05Z,192.168.1.100,admin,LOGIN,Accepted password for admin,INFO
"""
    parser = CSVParser()
    records = parser.parse(csv_content)

    assert len(records) == 2
    assert records[0].source_ip == "192.168.1.100"
    assert records[0].username == "admin"
    assert records[0].event_category == "LOGIN_FAILURE"
    assert records[0].severity == "HIGH"
    assert records[0].parsing_status == "OK"

    assert records[1].event_category == "LOGIN_SUCCESS"
    assert records[1].severity == "INFO"
    assert records[1].parsing_status == "OK"


def test_csv_parser_missing_columns():
    """Verify CSV parser does not crash on missing headers or sparse records."""
    csv_content = """random_col,another_col
value_one,value_two
only_one_value
"""
    parser = CSVParser()
    records = parser.parse(csv_content)

    assert len(records) >= 1
    # Status should be PARTIAL because timestamp is missing
    assert records[0].parsing_status in ("PARTIAL", "FAILED")
    assert records[0].original_timestamp is None


def test_json_parser_array():
    """Verify JSON array of event objects is parsed correctly."""
    json_data = [
        {
            "timestamp": "2026-10-30T11:00:00Z",
            "src_ip": "10.0.0.50",
            "user": "alice",
            "action": "sshd_connect",
            "message": "Connection established via SSH",
        },
        {
            "timestamp": "2026-10-30T11:00:10Z",
            "src_ip": "10.0.0.50",
            "user": "alice",
            "action": "sudo_command",
            "message": "sudo: alice : USER=root ; COMMAND=/bin/bash",
        }
    ]
    parser = JSONParser()
    records = parser.parse(json.dumps(json_data))

    assert len(records) == 2
    assert records[0].source_ip == "10.0.0.50"
    assert records[0].username == "alice"
    assert records[0].parsing_status == "OK"
    assert records[1].event_category == "PRIVILEGE_CHANGE"


def test_json_parser_nested_fields():
    """Verify JSON parser flattens nested structures by one level."""
    nested_json = {
        "event_header": {
            "timestamp": "2026-10-30T12:00:00Z",
            "host": "database-prod-01",
        },
        "network": {
            "source_ip": "172.16.5.99",
            "dest_ip": "172.16.5.1",
        },
        "details": {
            "username": "svc_backup",
            "message": "Authentication failure: invalid token",
        }
    }
    parser = JSONParser()
    records = parser.parse(json.dumps(nested_json))

    assert len(records) == 1
    rec = records[0]
    assert rec.source_ip == "172.16.5.99"
    assert rec.dest_ip == "172.16.5.1"
    assert rec.username == "svc_backup"
    assert rec.event_category == "LOGIN_FAILURE"
    assert rec.parsing_status == "OK"


def test_syslog_line_parsing():
    """Verify Linux auth.log regex patterns extract timestamp, process, IP, and credentials."""
    parser = SyslogParser()

    # 1. Failed SSH password
    line1 = "Oct 30 10:15:23 hostname sshd[1234]: Failed password for invalid user hacker from 192.168.1.1 port 22 ssh2"
    rec1 = parser.parse_line(line1)
    assert rec1.original_timestamp == "Oct 30 10:15:23"
    assert rec1.username == "hacker"
    assert rec1.source_ip == "192.168.1.1"
    assert rec1.event_category == "LOGIN_FAILURE"

    # 2. Accepted SSH password
    line2 = "Oct 30 10:15:30 hostname sshd[1234]: Accepted password for deploy from 192.168.1.1 port 22 ssh2"
    rec2 = parser.parse_line(line2)
    assert rec2.username == "deploy"
    assert rec2.source_ip == "192.168.1.1"
    assert rec2.event_category == "LOGIN_SUCCESS"

    # 3. Sudo execution
    line3 = "Oct 30 10:16:00 hostname sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    rec3 = parser.parse_line(line3)
    assert rec3.username == "deploy"
    assert rec3.event_category == "PRIVILEGE_CHANGE"
    assert rec3.extra_fields.get("command") == "/bin/cat /etc/shadow"

    # 4. Invalid user attempt
    line4 = "Oct 30 10:16:05 hostname sshd[1234]: Invalid user administrator from 10.10.10.200"
    rec4 = parser.parse_line(line4)
    assert rec4.username == "administrator"
    assert rec4.source_ip == "10.10.10.200"
    assert rec4.event_category == "LOGIN_FAILURE"

"""Unit tests for CSV, JSON, Syslog, and Apache forensic parsers."""

import io
import json
from app.services.ingestion.ingestor import detect_file_format
from app.services.normalization.event_normalizer import categorize_event
from app.services.parsing.apache_parser import ApacheParser
from app.services.parsing.csv_parser import CSVParser
from app.services.parsing.generic_parser import GenericParser, is_generic_line
from app.services.parsing.json_parser import JSONParser
from app.services.parsing.registry import ParserRegistry, parser_registry
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


def test_syslog_parser_streams_without_loading_full_content():
    """Verify syslog streaming yields records incrementally from a text stream."""
    content = """Oct 30 10:15:23 hostname sshd[1234]: Failed password for hacker from 192.168.1.1 port 22 ssh2
Oct 30 10:15:30 hostname sshd[1234]: Accepted password for deploy from 192.168.1.1 port 22 ssh2
"""
    parser = SyslogParser()
    records = list(parser.parse_stream(io.StringIO(content)))
    assert len(records) == 2
    assert records[0].event_category == "LOGIN_FAILURE"
    assert records[1].event_category == "LOGIN_SUCCESS"


def test_csv_parser_streams_from_seekable_text_stream():
    """Verify CSV streaming preserves field extraction and row counts."""
    content = """timestamp,source_ip,username,message
2026-10-30T10:15:00Z,192.168.1.100,admin,Failed password for admin
2026-10-30T10:15:05Z,192.168.1.100,admin,Accepted password for admin
"""
    parser = CSVParser()
    records = list(parser.parse_stream(io.StringIO(content)))
    assert len(records) == 2
    assert records[0].source_ip == "192.168.1.100"
    assert records[1].event_category == "LOGIN_SUCCESS"


def test_json_parser_streams_ndjson():
    """Verify NDJSON is decoded one line at a time."""
    lines = [
        json.dumps({"timestamp": "2026-10-30T10:00:00Z", "src_ip": "10.0.0.1", "message": "one"}),
        json.dumps({"timestamp": "2026-10-30T10:00:01Z", "src_ip": "10.0.0.2", "message": "two"}),
    ]
    parser = JSONParser()
    records = list(parser.parse_stream(io.StringIO("\n".join(lines) + "\n")))
    assert len(records) == 2
    assert records[0].source_ip == "10.0.0.1"
    assert records[1].source_ip == "10.0.0.2"


def test_apache_error_log_parsing():
    """Verify Apache error timestamps, client IPs, and 404s are classified correctly."""
    parser = ApacheParser()

    missing = parser.parse_line(
        "[Tue Nov 22 05:43:21 2005] [error] [client 128.210.16.37] "
        "File does not exist: /var/www/html/admin"
    )
    assert missing.original_timestamp == "Tue Nov 22 05:43:21 2005"
    assert missing.source_ip == "128.210.16.37"
    assert missing.event_category == "HTTP_REQUEST"
    assert missing.event_type == "apache_missing_resource"
    assert missing.severity == "LOW"

    startup = parser.parse_line(
        "[Thu Jun 09 06:07:19 2005] [notice] Apache/2.0.49 (Fedora) configured -- resuming normal operations"
    )
    assert startup.event_category == "SYSTEM_EVENT"
    assert startup.severity == "INFO"

    denied = parser.parse_line(
        "[Tue Nov 22 05:44:00 2005] [error] [client 203.0.113.5] "
        "client denied by server configuration: /var/www/html/private"
    )
    assert denied.event_category == "HTTP_REQUEST"
    assert denied.severity == "MEDIUM"


def test_apache_access_log_parsing():
    """Verify combined access logs extract request, status, user, and source IP."""
    parser = ApacheParser()
    record = parser.parse_line(
        '203.0.113.88 - alice [10/Oct/2000:13:55:36 -0700] '
        '"GET /admin HTTP/1.0" 404 2326 "-" "Mozilla/5.0"'
    )

    assert record.original_timestamp == "10/Oct/2000:13:55:36 -0700"
    assert record.source_ip == "203.0.113.88"
    assert record.username == "alice"
    assert record.event_category == "HTTP_REQUEST"
    assert record.severity == "LOW"
    assert record.extra_fields["path"] == "/admin"
    assert record.extra_fields["status"] == 404


def test_apache_admin_path_does_not_imply_privilege_change():
    """Verify a benign /admin path is not mislabeled as privilege escalation."""
    category = categorize_event(
        description="File does not exist: /var/www/html/admin",
        raw_record="[error] [client 203.0.113.5] File does not exist: /var/www/html/admin",
    )
    assert category != "PRIVILEGE_CHANGE"


def test_apache_log_format_detection():
    """Verify Apache error and access logs are detected as apache, not generic syslog."""
    error_log = (
        "[Thu Jun 09 06:07:04 2005] [notice] LDAP: Built with OpenLDAP LDAP SDK\n"
        "[Thu Jun 09 06:07:05 2005] [error] env.createBean2(): Factory error\n"
    )
    access_log = (
        '203.0.113.88 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 2326\n'
        '203.0.113.89 - - [10/Oct/2000:13:55:37 -0700] "GET /admin HTTP/1.0" 404 0\n'
    )

    assert detect_file_format(error_log, "Apache.log") == "apache"
    assert detect_file_format(access_log, "access.log") == "apache"


def test_generic_parser_cef_real_world_sample():
    """Verify a public Citrix CEF event with a syslog prefix is normalized correctly."""
    line = (
        "<14>Sep 18 14:58:29 logstream syslog: CEF:0|Citrix|NetScaler|NS10.0|APPFW|"
        "APPFW_STARTURL|6|src=10.217.253.78 spt=54711 method=GET "
        "request=http://vpx247.example.net/FFC/login_post.html?abc\\=def "
        "msg=Disallow Illegal URL. cn1=465 cn2=535 cs1=profile1 cs2=PPE0 "
        "cs3=IliG4Dxp1SjOhKVRDVBXmqvAaIcA000 cs4=ALERT cs5=2012 act=not blocked"
    )

    assert is_generic_line(line)
    assert detect_file_format(line, "cef.log") == "generic"

    record = GenericParser().parse_line(line)
    assert record.original_timestamp == "Sep 18 14:58:29"
    assert record.source_ip == "10.217.253.78"
    assert record.event_type == "GET"
    assert record.event_category == "HTTP_REQUEST"
    assert record.severity == "MEDIUM"
    assert record.source_system == "Citrix NetScaler"
    assert record.description == "Disallow Illegal URL."
    assert record.extra_fields["log_format"] == "cef"
    assert record.extra_fields["cef_vendor"] == "Citrix"
    assert record.extra_fields["cef_product"] == "NetScaler"
    assert record.extra_fields["request"].endswith("abc=def")
    assert record.parsing_status == "OK"


def test_generic_parser_leef_real_world_samples():
    """Verify public LEEF 1.x/2.0 events using caret, pipe, and broken-bar delimiters."""
    extrahop = (
        "<134>Feb 01 05:00:00 logstream syslog: LEEF:2.0|ExtraHop|Reveal(x)|7.8|"
        "extrahop-detection|xa6|appliance_id=dd0685a93cdc3bc5bb9a88251e7a7804"
        "¦categories=sec,sec.caution¦det_id=0123456789"
        "¦risk_score=60¦start_time=Jan 24 2022 20:23:39 +0000"
        "¦title=Non-standard HTTP Port¦offender_ip=10.1.2.3¦victim_ip=192.168.1.50"
        "¦desc=Host CRIBL sent an HTTP request to an external device on a non-standard HTTP port."
    )
    caret = (
        "<113>1 2019-01-18T11:07:53.520+07:00 hostname4 "
        "LEEF:2.0|Lancope|StealthWatch|1.0|41|^|"
        "src=10.0.1.8^dst=10.0.0.5^sev=5^srcPort=81^dstPort=21"
    )
    pipe = (
        "LEEF:2.0|Palo Alto Networks|PAN-OS Syslog Integration|11.1.6|allow|x7C|"
        "cat=TRAFFIC|devTime=Jun 03 2025 19:01:07 GMT|src=203.0.113.10|dst=1.1.1.1|"
        "usrName=admin|proto=udp|dstPort=53"
    )

    parser = GenericParser()

    extrahop_record = parser.parse_line(extrahop)
    assert extrahop_record.original_timestamp == "Jan 24 2022 20:23:39 +0000"
    assert extrahop_record.source_ip == "10.1.2.3"
    assert extrahop_record.dest_ip == "192.168.1.50"
    assert extrahop_record.event_category == "NETWORK_CONNECTION"
    assert extrahop_record.source_system == "ExtraHop Reveal(x)"
    assert extrahop_record.extra_fields["leef_delimiter"] == "xa6"
    assert extrahop_record.parsing_status == "OK"

    caret_record = parser.parse_line(caret)
    assert caret_record.original_timestamp == "2019-01-18T11:07:53.520+07:00"
    assert caret_record.source_ip == "10.0.1.8"
    assert caret_record.dest_ip == "10.0.0.5"
    assert caret_record.severity == "MEDIUM"
    assert caret_record.extra_fields["leef_delimiter"] == "^"
    assert caret_record.parsing_status == "OK"

    pipe_record = parser.parse_line(pipe)
    assert pipe_record.original_timestamp == "Jun 03 2025 19:01:07 GMT"
    assert pipe_record.source_ip == "203.0.113.10"
    assert pipe_record.dest_ip == "1.1.1.1"
    assert pipe_record.username == "admin"
    assert pipe_record.extra_fields["leef_delimiter"] == "x7C"
    assert pipe_record.parsing_status == "OK"


def test_generic_parser_logfmt_real_world_samples():
    """Verify public logfmt lines parse timestamps, levels, and messages."""
    lines = [
        'time="2023-07-16T01:10:41Z" level=warning msg="Warning message" client_id=1',
        'time="2023-07-16T01:10:42Z" level=error msg="Error message" client_id=1',
    ]

    assert detect_file_format("\n".join(lines), "app.log") == "generic"
    parser = GenericParser()
    warning = parser.parse_line(lines[0])
    error = parser.parse_line(lines[1])

    assert warning.original_timestamp == "2023-07-16T01:10:41Z"
    assert warning.description == "Warning message"
    assert warning.severity == "MEDIUM"
    assert warning.source_ip is None
    assert warning.extra_fields["log_format"] == "keyvalue"
    assert warning.parsing_status == "OK"

    assert error.event_category == "APPLICATION_ERROR"
    assert error.severity == "HIGH"


def test_generic_parser_fortinet_key_value_real_world_sample():
    """Verify a public FortiGate key-value event combines date/time and IPv6 fields."""
    line = (
        '<189>date=2025-07-25 time=07:43:43 devname="FortiGate-40F-SVA" '
        'devid="FGT40FTK2409BDPZ" eventtime=1753454623318460180 tz="-0700" '
        'logid="0001000014" type="traffic" subtype="local" level="notice" '
        'vd="root" srcip=fe80::2a70:4eff:fe71:34f1 srcport=5353 '
        'dstip=ff02::fb dstport=5353 proto=17 action="deny" appcat="unscanned"'
    )

    assert detect_file_format(line, "fortigate.log") == "generic"
    record = GenericParser().parse_line(line)

    assert record.original_timestamp == "2025-07-25 07:43:43"
    assert record.source_ip == "fe80::2a70:4eff:fe71:34f1"
    assert record.dest_ip == "ff02::fb"
    assert record.source_system == "FortiGate-40F-SVA"
    assert record.event_type == "traffic"
    assert record.event_category == "NETWORK_CONNECTION"
    assert record.severity == "INFO"
    assert record.parsing_status == "OK"


def test_parser_registry_defaults_and_plugin_registration():
    """Verify built-in aliases and custom parser registration through the registry."""
    registry = ParserRegistry()
    generic = GenericParser()
    registry.register("generic", generic)

    custom = SyslogParser()
    registry.register("custom", custom, aliases=("custom-log",))

    assert registry.get("custom") is custom
    assert registry.get("custom-log") is custom
    assert registry.get("missing") is generic
    assert isinstance(parser_registry.get("cef"), GenericParser)
    assert isinstance(parser_registry.get("leef"), GenericParser)
    assert isinstance(parser_registry.get("apache"), ApacheParser)

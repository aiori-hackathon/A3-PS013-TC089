"""Forensic detection rule engine implementing correlation and threat detection rules."""

import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.models import Event, DetectionAlert, generate_uuid


SUSPICIOUS_PATHS = [
    "/admin",
    "/config",
    "/etc/passwd",
    "passwd",
    "shadow",
    "/wp-admin",
    "/.env",
    ".env",
    "/.git",
    "phpmyadmin",
    "/shell",
    "/backup",
    "cmd.exe",
    "/bin/sh",
    "/bin/bash",
]

MAX_ALERT_EVENT_IDS = 200
MAX_ALERTS_PER_RULE = 100


class RuleEngine:
    """Evaluates cyber forensic correlation rules across unified investigation events."""

    def __init__(self, db: Session, investigation_id: str):
        self.db = db
        self.investigation_id = investigation_id

    def _stream(self, stmt, batch_size: int = 5000):
        return self.db.execute(stmt).yield_per(batch_size)

    def rule_1_multiple_failed_logins(self) -> List[DetectionAlert]:
        """Rule 1: Multiple failed logins from same IP (threshold >= 3)."""
        alerts: List[DetectionAlert] = []
        failures_by_ip: Dict[str, dict] = defaultdict(
            lambda: {"count": 0, "users": set(), "event_ids": []}
        )

        stmt = (
            select(Event.source_ip, Event.username, Event.id)
            .where(
                Event.investigation_id == self.investigation_id,
                Event.event_category == "LOGIN_FAILURE",
                Event.source_ip.isnot(None),
            )
        )
        for row in self._stream(stmt):
            entry = failures_by_ip[row.source_ip]
            entry["count"] += 1
            if row.username:
                entry["users"].add(row.username)
            if len(entry["event_ids"]) < MAX_ALERT_EVENT_IDS:
                entry["event_ids"].append(row.id)

        for ip, entry in failures_by_ip.items():
            if entry["count"] >= 3 and len(alerts) < MAX_ALERTS_PER_RULE:
                users = sorted(entry["users"])
                alert = DetectionAlert(
                    id=generate_uuid(),
                    investigation_id=self.investigation_id,
                    rule_name="Multiple Failed Logins from Same IP",
                    severity="HIGH" if entry["count"] < 10 else "CRITICAL",
                    explanation=(
                        f"Detected {entry['count']} authentication failures originating from IP address {ip}. "
                        f"Targeted accounts: {', '.join(users) if users else 'unknown'}."
                    ),
                    event_ids=json.dumps(entry["event_ids"]),
                    ip_addresses=json.dumps([ip]),
                    usernames=json.dumps(users),
                    created_at=datetime.utcnow(),
                    alert_type="AUTHENTICATION_ATTACK",
                )
                alerts.append(alert)

        return alerts

    def rule_2_successful_login_after_failures(self) -> List[DetectionAlert]:
        """Rule 2: Successful login after repeated failures from same IP."""
        alerts: List[DetectionAlert] = []
        state_by_ip: Dict[str, dict] = defaultdict(
            lambda: {"fail_count": 0, "fail_users": set(), "fail_ids": []}
        )

        stmt = (
            select(
                Event.source_ip,
                Event.event_category,
                Event.username,
                Event.id,
            )
            .where(
                Event.investigation_id == self.investigation_id,
                Event.source_ip.isnot(None),
                Event.event_category.in_(("LOGIN_FAILURE", "LOGIN_SUCCESS")),
            )
            .order_by(Event.normalized_timestamp.asc().nulls_last(), Event.id.asc())
        )
        for row in self._stream(stmt):
            state = state_by_ip[row.source_ip]
            if row.event_category == "LOGIN_FAILURE":
                state["fail_count"] += 1
                if row.username:
                    state["fail_users"].add(row.username)
                if len(state["fail_ids"]) < MAX_ALERT_EVENT_IDS:
                    state["fail_ids"].append(row.id)
            elif state["fail_count"] >= 2 and len(alerts) < MAX_ALERTS_PER_RULE:
                users = set(state["fail_users"])
                if row.username:
                    users.add(row.username)
                event_ids = list(state["fail_ids"])
                if len(event_ids) < MAX_ALERT_EVENT_IDS:
                    event_ids.append(row.id)
                alert = DetectionAlert(
                    id=generate_uuid(),
                    investigation_id=self.investigation_id,
                    rule_name="Successful Login After Repeated Failures",
                    severity="CRITICAL",
                    explanation=(
                        f"High-confidence credential compromise detected. IP {row.source_ip} successfully logged in as "
                        f"'{row.username or 'unknown'}' immediately following {state['fail_count']} failed "
                        "authentication attempts."
                    ),
                    event_ids=json.dumps(event_ids),
                    ip_addresses=json.dumps([row.source_ip]),
                    usernames=json.dumps(sorted(users)),
                    created_at=datetime.utcnow(),
                    alert_type="ACCOUNT_COMPROMISE",
                )
                alerts.append(alert)
                state["fail_count"] = 0
                state["fail_users"] = set()
                state["fail_ids"] = []

        return alerts

    def rule_3_multiple_accounts_targeted(self) -> List[DetectionAlert]:
        """Rule 3: Multiple distinct accounts targeted by one source IP (threshold >= 3)."""
        alerts: List[DetectionAlert] = []
        users_by_ip: Dict[str, Dict[str, dict]] = defaultdict(dict)

        stmt = (
            select(Event.source_ip, Event.username, Event.id)
            .where(
                Event.investigation_id == self.investigation_id,
                Event.source_ip.isnot(None),
                Event.username.isnot(None),
            )
        )
        for row in self._stream(stmt):
            user_map = users_by_ip[row.source_ip]
            entry = user_map.setdefault(row.username, {"count": 0, "event_ids": []})
            entry["count"] += 1
            if len(entry["event_ids"]) < 50:
                entry["event_ids"].append(row.id)

        for ip, user_map in users_by_ip.items():
            if len(user_map) >= 3 and len(alerts) < MAX_ALERTS_PER_RULE:
                all_event_ids = [eid for entry in user_map.values() for eid in entry["event_ids"]]
                target_users = sorted(user_map.keys())
                alert = DetectionAlert(
                    id=generate_uuid(),
                    investigation_id=self.investigation_id,
                    rule_name="Multiple Accounts Targeted by Single IP",
                    severity="HIGH",
                    explanation=(
                        f"Potential user enumeration or password spraying: IP {ip} targeted {len(target_users)} "
                        f"different accounts: {', '.join(target_users)}."
                    ),
                    event_ids=json.dumps(all_event_ids[:50]),
                    ip_addresses=json.dumps([ip]),
                    usernames=json.dumps(target_users),
                    created_at=datetime.utcnow(),
                    alert_type="RECONNAISSANCE_OR_SPRAYING",
                )
                alerts.append(alert)

        return alerts

    def rule_4_suspicious_path_access(self) -> List[DetectionAlert]:
        """Rule 4: Suspicious path access (admin, config, passwd, shadow, etc.)."""
        alerts: List[DetectionAlert] = []
        suspicious_by_ip: Dict[str, dict] = defaultdict(
            lambda: {"count": 0, "users": set(), "paths": set(), "event_ids": []}
        )

        stmt = select(
            Event.id,
            Event.source_ip,
            Event.username,
            Event.description,
            Event.raw_record,
        ).where(Event.investigation_id == self.investigation_id)

        for row in self._stream(stmt, batch_size=2000):
            text = f"{row.description or ''} {row.raw_record or ''}".lower()
            detected = [p for p in SUSPICIOUS_PATHS if p in text]
            if not detected:
                continue
            ip = row.source_ip or "UNKNOWN_ORIGIN"
            entry = suspicious_by_ip[ip]
            entry["count"] += 1
            if row.username:
                entry["users"].add(row.username)
            entry["paths"].update(detected)
            if len(entry["event_ids"]) < MAX_ALERT_EVENT_IDS:
                entry["event_ids"].append(row.id)

        for ip, entry in suspicious_by_ip.items():
            if len(alerts) >= MAX_ALERTS_PER_RULE:
                break
            alert = DetectionAlert(
                id=generate_uuid(),
                investigation_id=self.investigation_id,
                rule_name="Suspicious Path and Configuration Access",
                severity="HIGH",
                explanation=(
                    f"Suspicious probing or exploitation requests detected from {ip} targeting sensitive resources: "
                    f"{', '.join(sorted(entry['paths']))}. Total requests: {entry['count']}."
                ),
                event_ids=json.dumps(entry["event_ids"]),
                ip_addresses=json.dumps([ip] if ip != "UNKNOWN_ORIGIN" else []),
                usernames=json.dumps(sorted(entry["users"])),
                created_at=datetime.utcnow(),
                alert_type="RECONNAISSANCE_OR_EXPLOITATION",
            )
            alerts.append(alert)

        return alerts

    def rule_5_privilege_escalation(self) -> List[DetectionAlert]:
        """Rule 5: Privilege escalation (sudo / su after login or elevated commands)."""
        alerts: List[DetectionAlert] = []

        stmt = select(
            Event.id,
            Event.username,
            Event.source_system,
            Event.description,
            Event.raw_record,
            Event.source_ip,
        ).where(
            Event.investigation_id == self.investigation_id,
            Event.event_category == "PRIVILEGE_CHANGE",
        )

        for row in self._stream(stmt):
            if len(alerts) >= MAX_ALERTS_PER_RULE:
                break
            users = [row.username] if row.username else []
            alert = DetectionAlert(
                id=generate_uuid(),
                investigation_id=self.investigation_id,
                rule_name="Privilege Escalation Detected",
                severity="HIGH",
                explanation=(
                    f"Elevated execution detected by '{row.username or 'unknown'}' on "
                    f"{row.source_system or 'system'}: {row.description or row.raw_record}"
                ),
                event_ids=json.dumps([row.id]),
                ip_addresses=json.dumps([row.source_ip] if row.source_ip else []),
                usernames=json.dumps(users),
                created_at=datetime.utcnow(),
                alert_type="PRIVILEGE_ESCALATION",
            )
            alerts.append(alert)

        return alerts

    def rule_6_application_errors_following_activity(self) -> List[DetectionAlert]:
        """Rule 6: Application errors following suspicious activity or probes."""
        alerts: List[DetectionAlert] = []
        app_error_ids: List[str] = []
        app_error_count = 0
        app_ips: Set[str] = set()
        app_users: Set[str] = set()

        stmt = select(Event.id, Event.source_ip, Event.username).where(
            Event.investigation_id == self.investigation_id,
            Event.event_category == "APPLICATION_ERROR",
        )
        for row in self._stream(stmt):
            app_error_count += 1
            if len(app_error_ids) < MAX_ALERT_EVENT_IDS:
                app_error_ids.append(row.id)
            if row.source_ip:
                app_ips.add(row.source_ip)
            if row.username:
                app_users.add(row.username)

        suspicious_ids: List[str] = []
        suspicious_count = 0
        suspicious_ips: Set[str] = set()
        suspicious_users: Set[str] = set()

        stmt = select(Event.id, Event.source_ip, Event.username).where(
            Event.investigation_id == self.investigation_id,
            Event.event_category.in_(("LOGIN_FAILURE", "PRIVILEGE_CHANGE")),
        )
        for row in self._stream(stmt):
            suspicious_count += 1
            if len(suspicious_ids) < 10:
                suspicious_ids.append(row.id)
            if row.source_ip:
                suspicious_ips.add(row.source_ip)
            if row.username:
                suspicious_users.add(row.username)

        if app_error_count and (suspicious_count or app_error_count >= 3):
            alert = DetectionAlert(
                id=generate_uuid(),
                investigation_id=self.investigation_id,
                rule_name="Application Errors Correlated with Suspicious Activity",
                severity="MEDIUM",
                explanation=(
                    f"Observed {app_error_count} application error / 500 events concurrent with security anomalies. "
                    "Indicates potential system degradation, payload crash, or injection error."
                ),
                event_ids=json.dumps(app_error_ids + suspicious_ids),
                ip_addresses=json.dumps(sorted(app_ips | suspicious_ips)),
                usernames=json.dumps(sorted(app_users | suspicious_users)),
                created_at=datetime.utcnow(),
                alert_type="SYSTEM_INSTABILITY_OR_ATTACK_IMPACT",
            )
            alerts.append(alert)

        return alerts

    def rule_7_after_hours_activity(self) -> List[DetectionAlert]:
        """Rule 7: After-hours activity (outside 07:00-19:00 UTC)."""
        alerts: List[DetectionAlert] = []
        off_hour_count = 0
        off_hour_ids: List[str] = []
        users: Set[str] = set()
        ips: Set[str] = set()

        stmt = select(
            Event.id,
            Event.username,
            Event.source_ip,
            Event.normalized_timestamp,
        ).where(
            Event.investigation_id == self.investigation_id,
            Event.event_category.in_(("LOGIN_SUCCESS", "PRIVILEGE_CHANGE", "ACCOUNT_CHANGE")),
            Event.normalized_timestamp.isnot(None),
        )
        for row in self._stream(stmt):
            hour = row.normalized_timestamp.hour
            if hour < 7 or hour >= 19:
                off_hour_count += 1
                if len(off_hour_ids) < MAX_ALERT_EVENT_IDS:
                    off_hour_ids.append(row.id)
                if row.username:
                    users.add(row.username)
                if row.source_ip:
                    ips.add(row.source_ip)

        if off_hour_count:
            alert = DetectionAlert(
                id=generate_uuid(),
                investigation_id=self.investigation_id,
                rule_name="Anomalous After-Hours Security Activity",
                severity="MEDIUM",
                explanation=(
                    f"Identified {off_hour_count} sensitive security actions (logins, privilege escalations) "
                    "conducted during off-hours (between 19:00 and 07:00 UTC). "
                    f"Involved users: {', '.join(sorted(users)) if users else 'system'}."
                ),
                event_ids=json.dumps(off_hour_ids),
                ip_addresses=json.dumps(sorted(ips)),
                usernames=json.dumps(sorted(users)),
                created_at=datetime.utcnow(),
                alert_type="ANOMALOUS_OFF_HOURS_ACTIVITY",
            )
            alerts.append(alert)

        return alerts

    def run_all(self) -> List[DetectionAlert]:
        """Execute all 7 detection rules, store alerts in database, and return generated alerts."""
        # Remove existing alerts for fresh run
        self.db.query(DetectionAlert).filter(
            DetectionAlert.investigation_id == self.investigation_id
        ).delete()
        self.db.commit()

        all_alerts: List[DetectionAlert] = []
        all_alerts.extend(self.rule_1_multiple_failed_logins())
        all_alerts.extend(self.rule_2_successful_login_after_failures())
        all_alerts.extend(self.rule_3_multiple_accounts_targeted())
        all_alerts.extend(self.rule_4_suspicious_path_access())
        all_alerts.extend(self.rule_5_privilege_escalation())
        all_alerts.extend(self.rule_6_application_errors_following_activity())
        all_alerts.extend(self.rule_7_after_hours_activity())

        for alert in all_alerts:
            self.db.add(alert)

        self.db.commit()
        for alert in all_alerts:
            self.db.refresh(alert)

        return all_alerts


def run_all_rules(investigation_id: str, db: Session) -> List[DetectionAlert]:
    """Top-level helper function to run all analysis rules for an investigation."""
    engine = RuleEngine(db, investigation_id)
    return engine.run_all()

"""Forensic detection rule engine implementing correlation and threat detection rules."""

import json
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Set
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


class RuleEngine:
    """Evaluates cyber forensic correlation rules across unified investigation events."""

    def __init__(self, db: Session, investigation_id: str):
        self.db = db
        self.investigation_id = investigation_id
        self.events: List[Event] = (
            self.db.query(Event)
            .filter(Event.investigation_id == investigation_id)
            .order_by(Event.normalized_timestamp.asc().nulls_last(), Event.id.asc())
            .all()
        )

    def rule_1_multiple_failed_logins(self) -> List[DetectionAlert]:
        """Rule 1: Multiple failed logins from same IP (threshold >= 3)."""
        alerts: List[DetectionAlert] = []
        failures_by_ip: Dict[str, List[Event]] = defaultdict(list)

        for ev in self.events:
            if ev.event_category == "LOGIN_FAILURE" and ev.source_ip:
                failures_by_ip[ev.source_ip].append(ev)

        for ip, fail_events in failures_by_ip.items():
            if len(fail_events) >= 3:
                users = list({e.username for e in fail_events if e.username})
                alert = DetectionAlert(
                    id=generate_uuid(),
                    investigation_id=self.investigation_id,
                    rule_name="Multiple Failed Logins from Same IP",
                    severity="HIGH" if len(fail_events) < 10 else "CRITICAL",
                    explanation=(
                        f"Detected {len(fail_events)} authentication failures originating from IP address {ip}. "
                        f"Targeted accounts: {', '.join(users) if users else 'unknown'}."
                    ),
                    event_ids=json.dumps([e.id for e in fail_events]),
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
        events_by_ip: Dict[str, List[Event]] = defaultdict(list)

        for ev in self.events:
            if ev.source_ip and ev.event_category in ("LOGIN_FAILURE", "LOGIN_SUCCESS"):
                events_by_ip[ev.source_ip].append(ev)

        for ip, ip_events in events_by_ip.items():
            fail_streak: List[Event] = []
            for ev in ip_events:
                if ev.event_category == "LOGIN_FAILURE":
                    fail_streak.append(ev)
                elif ev.event_category == "LOGIN_SUCCESS":
                    if len(fail_streak) >= 2:
                        matched_event_ids = [e.id for e in fail_streak] + [ev.id]
                        users = list({e.username for e in fail_streak if e.username} | ({ev.username} if ev.username else set()))
                        alert = DetectionAlert(
                            id=generate_uuid(),
                            investigation_id=self.investigation_id,
                            rule_name="Successful Login After Repeated Failures",
                            severity="CRITICAL",
                            explanation=(
                                f"High-confidence credential compromise detected. IP {ip} successfully logged in as '{ev.username or 'unknown'}' "
                                f"immediately following {len(fail_streak)} failed authentication attempts."
                            ),
                            event_ids=json.dumps(matched_event_ids),
                            ip_addresses=json.dumps([ip]),
                            usernames=json.dumps(users),
                            created_at=datetime.utcnow(),
                            alert_type="ACCOUNT_COMPROMISE",
                        )
                        alerts.append(alert)
                        fail_streak = []  # Reset streak after detection

        return alerts

    def rule_3_multiple_accounts_targeted(self) -> List[DetectionAlert]:
        """Rule 3: Multiple distinct accounts targeted by one source IP (threshold >= 3)."""
        alerts: List[DetectionAlert] = []
        users_by_ip: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))

        for ev in self.events:
            if ev.source_ip and ev.username:
                users_by_ip[ev.source_ip][ev.username].append(ev.id)

        for ip, user_map in users_by_ip.items():
            if len(user_map) >= 3:
                all_event_ids = [eid for eids in user_map.values() for eid in eids]
                target_users = list(user_map.keys())
                alert = DetectionAlert(
                    id=generate_uuid(),
                    investigation_id=self.investigation_id,
                    rule_name="Multiple Accounts Targeted by Single IP",
                    severity="HIGH",
                    explanation=(
                        f"Potential user enumeration or password spraying: IP {ip} targeted {len(target_users)} "
                        f"different accounts: {', '.join(sorted(target_users))}."
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
        suspicious_by_ip: Dict[str, List[Event]] = defaultdict(list)
        matched_paths_by_ip: Dict[str, Set[str]] = defaultdict(set)

        for ev in self.events:
            text = f"{ev.description or ''} {ev.raw_record or ''}".lower()
            detected = [p for p in SUSPICIOUS_PATHS if p in text]
            if detected:
                ip = ev.source_ip or "UNKNOWN_ORIGIN"
                suspicious_by_ip[ip].append(ev)
                matched_paths_by_ip[ip].update(detected)

        for ip, susp_events in suspicious_by_ip.items():
            paths = list(matched_paths_by_ip[ip])
            users = list({e.username for e in susp_events if e.username})
            alert = DetectionAlert(
                id=generate_uuid(),
                investigation_id=self.investigation_id,
                rule_name="Suspicious Path and Configuration Access",
                severity="HIGH",
                explanation=(
                    f"Suspicious probing or exploitation requests detected from {ip} targeting sensitive resources: "
                    f"{', '.join(paths)}. Total requests: {len(susp_events)}."
                ),
                event_ids=json.dumps([e.id for e in susp_events]),
                ip_addresses=json.dumps([ip] if ip != "UNKNOWN_ORIGIN" else []),
                usernames=json.dumps(users),
                created_at=datetime.utcnow(),
                alert_type="RECONNAISSANCE_OR_EXPLOITATION",
            )
            alerts.append(alert)

        return alerts

    def rule_5_privilege_escalation(self) -> List[DetectionAlert]:
        """Rule 5: Privilege escalation (sudo / su after login or elevated commands)."""
        alerts: List[DetectionAlert] = []
        priv_events = [e for e in self.events if e.event_category == "PRIVILEGE_CHANGE"]

        if not priv_events:
            return alerts

        for ev in priv_events:
            users = [ev.username] if ev.username else []
            alert = DetectionAlert(
                id=generate_uuid(),
                investigation_id=self.investigation_id,
                rule_name="Privilege Escalation Detected",
                severity="HIGH",
                explanation=(
                    f"Elevated execution detected by '{ev.username or 'unknown'}' on {ev.source_system or 'system'}: "
                    f"{ev.description or ev.raw_record}"
                ),
                event_ids=json.dumps([ev.id]),
                ip_addresses=json.dumps([ev.source_ip] if ev.source_ip else []),
                usernames=json.dumps(users),
                created_at=datetime.utcnow(),
                alert_type="PRIVILEGE_ESCALATION",
            )
            alerts.append(alert)

        return alerts

    def rule_6_application_errors_following_activity(self) -> List[DetectionAlert]:
        """Rule 6: Application errors following suspicious activity or probes."""
        alerts: List[DetectionAlert] = []
        app_errors = [e for e in self.events if e.event_category == "APPLICATION_ERROR"]
        suspicious_events = [
            e for e in self.events if e.event_category in ("LOGIN_FAILURE", "PRIVILEGE_CHANGE")
        ]

        if app_errors and (suspicious_events or len(app_errors) >= 3):
            event_ids = [e.id for e in app_errors] + [e.id for e in suspicious_events[:10]]
            ips = list({e.source_ip for e in app_errors if e.source_ip} | {e.source_ip for e in suspicious_events if e.source_ip})
            users = list({e.username for e in app_errors if e.username} | {e.username for e in suspicious_events if e.username})

            alert = DetectionAlert(
                id=generate_uuid(),
                investigation_id=self.investigation_id,
                rule_name="Application Errors Correlated with Suspicious Activity",
                severity="MEDIUM",
                explanation=(
                    f"Observed {len(app_errors)} application error / 500 events concurrent with security anomalies. "
                    "Indicates potential system degradation, payload crash, or injection error."
                ),
                event_ids=json.dumps(event_ids),
                ip_addresses=json.dumps(ips),
                usernames=json.dumps(users),
                created_at=datetime.utcnow(),
                alert_type="SYSTEM_INSTABILITY_OR_ATTACK_IMPACT",
            )
            alerts.append(alert)

        return alerts

    def rule_7_after_hours_activity(self) -> List[DetectionAlert]:
        """Rule 7: After-hours activity (outside 07:00-19:00 UTC)."""
        alerts: List[DetectionAlert] = []
        off_hour_events: List[Event] = []

        for ev in self.events:
            if ev.normalized_timestamp:
                hour = ev.normalized_timestamp.hour
                # Outside 07:00 to 19:00
                if hour < 7 or hour >= 19:
                    # Focus on high-impact actions
                    if ev.event_category in ("LOGIN_SUCCESS", "PRIVILEGE_CHANGE", "ACCOUNT_CHANGE"):
                        off_hour_events.append(ev)

        if off_hour_events:
            users = list({e.username for e in off_hour_events if e.username})
            ips = list({e.source_ip for e in off_hour_events if e.source_ip})
            alert = DetectionAlert(
                id=generate_uuid(),
                investigation_id=self.investigation_id,
                rule_name="Anomalous After-Hours Security Activity",
                severity="MEDIUM",
                explanation=(
                    f"Identified {len(off_hour_events)} sensitive security actions (logins, privilege escalations) "
                    f"conducted during off-hours (between 19:00 and 07:00 UTC). "
                    f"Involved users: {', '.join(users) if users else 'system'}."
                ),
                event_ids=json.dumps([e.id for e in off_hour_events]),
                ip_addresses=json.dumps(ips),
                usernames=json.dumps(users),
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

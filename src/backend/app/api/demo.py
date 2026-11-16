"""Demo scenarios loader and catalog API routes."""

import json
from pathlib import Path
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.services.cache import invalidate_cache
from app.models.models import (
    Investigation,
    AuditLog,
    generate_uuid,
)
from app.schemas.schemas import (
    ScenarioInfo,
    LoadScenarioRequest,
    LoadScenarioResponse,
)
from app.services.ingestion.ingestor import IngestionService
from app.services.analysis.rule_engine import run_all_rules

router = APIRouter(tags=["Demo Scenarios"])


def _load_scenario_metadata(sample_dir: Path) -> dict:
    """Read optional per-scenario metadata used for timezone and clock-skew handling."""
    meta_file = sample_dir / "scenario_metadata.json"
    if not meta_file.is_file():
        return {}
    try:
        with open(meta_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _get_available_scenarios() -> List[ScenarioInfo]:
    """Retrieve catalog of built-in demo scenarios from disk."""
    sample_dir = Path(settings.SAMPLE_DATA_PATH)
    scenarios: List[ScenarioInfo] = []

    scenario_defaults = {
        "scenario_1": {
            "name": "Scenario 1: SSH Brute Force & Privilege Escalation",
            "description": "Multi-stage attack involving sustained SSH brute forcing from an external IP, followed by successful authentication and subsequent sudo root escalation.",
            "difficulty": "Intermediate",
            "source_types": ["auth_log.csv", "firewall.json"],
            "expected_findings": [
                "Multiple failed logins from 192.168.100.5",
                "Successful login after repeated failures",
                "Root privilege escalation via sudo",
                "Correlated firewall drop and accept events",
            ],
        },
        "scenario_2": {
            "name": "Scenario 2: Web Reconnaissance & Sensitive Path Traversal",
            "description": "Targeted web application reconnaissance probing administrative endpoints (/admin, /wp-admin, /.env, /passwd) resulting in server error anomalies.",
            "difficulty": "Beginner",
            "source_types": ["web_access.csv"],
            "expected_findings": [
                "Suspicious path access attempts from 10.0.0.42",
                "Sensitive configuration probing (.env, passwd)",
                "Correlated HTTP 500 application crashes",
            ],
        },
        "scenario_3": {
            "name": "Scenario 3: Multi-Source Linux Syslog & Clock Skew Triage",
            "description": "Enterprise multi-host incident combining legacy BSD syslog (auth.log lacking year), cloud JSON events with +05:30 offset, and firewall telemetry with 5-minute clock skew.",
            "difficulty": "Advanced",
            "source_types": ["linux_auth.log", "app_events.json", "firewall_events.csv"],
            "expected_findings": [
                "Syslog format lacking year accurately reconstructed",
                "Timezone conversion from +05:30 to UTC",
                "Clock skew anomaly identified and reconciled",
                "Off-hours privileged activity detection",
            ],
        },
    }

    for sc_id, meta in scenario_defaults.items():
        meta_file = sample_dir / sc_id / "scenario.json"
        if meta_file.is_file():
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    file_meta = json.load(f)
                    scenarios.append(
                        ScenarioInfo(
                            id=sc_id,
                            name=file_meta.get("name", meta["name"]),
                            description=file_meta.get("description", meta["description"]),
                            difficulty=file_meta.get("difficulty", meta["difficulty"]),
                            source_types=file_meta.get("source_types", meta["source_types"]),
                            file_count=len(meta["source_types"]),
                            expected_findings=file_meta.get("expected_findings", meta["expected_findings"]),
                        )
                    )
                    continue
            except Exception:
                pass

        scenarios.append(
            ScenarioInfo(
                id=sc_id,
                name=meta["name"],
                description=meta["description"],
                difficulty=meta["difficulty"],
                source_types=meta["source_types"],
                file_count=len(meta["source_types"]),
                expected_findings=meta["expected_findings"],
            )
        )

    return scenarios


@router.get("/demo/scenarios", response_model=List[ScenarioInfo])
def list_demo_scenarios():
    """List available pre-packaged cyber forensic demonstration scenarios."""
    return _get_available_scenarios()


@router.get("/demo/status")
def demo_status():
    """Report whether demo-only controls (such as tamper simulation) are enabled."""
    return {"demo_mode": settings.DEMO_MODE}


@router.post("/demo/load-scenario", response_model=LoadScenarioResponse, status_code=status.HTTP_201_CREATED)
def load_demo_scenario(payload: LoadScenarioRequest, db: Session = Depends(get_db)):
    """Instantiate a demo scenario: creates investigation, ingests evidence files, runs rules and sets triage benchmarks."""
    scenarios = {s.id: s for s in _get_available_scenarios()}
    sc_id = payload.scenario_id.strip()

    if sc_id not in scenarios:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{sc_id}' not found. Available: {list(scenarios.keys())}"
        )

    scenario_meta = scenarios[sc_id]
    sample_dir = Path(settings.SAMPLE_DATA_PATH) / sc_id

    # 1. Create Investigation
    inv_id = generate_uuid()
    inv_name = f"DEMO: {scenario_meta.name}"
    inv = Investigation(
        id=inv_id,
        name=inv_name,
        description=scenario_meta.description,
        category="Demo Incident Scenario",
        status="ACTIVE",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(inv)
    db.commit()

    # 2. Ingest Sample Files
    ingestor = IngestionService(db)
    files_ingested = 0
    total_events = 0

    scenario_meta_files = _load_scenario_metadata(sample_dir)
    file_meta_map = {
        item.get("filename"): item
        for item in scenario_meta_files.get("files", [])
        if item.get("filename")
    }
    try:
        reference_year = int(scenario_meta_files["reference_year"])
    except (KeyError, TypeError, ValueError):
        reference_year = None

    if sample_dir.is_dir():
        for file_path in sorted(sample_dir.glob("*")):
            if file_path.suffix.lower() in settings.ALLOWED_EXTENSIONS and file_path.name not in {"scenario.json", "scenario_metadata.json"}:
                try:
                    with open(file_path, "rb") as f:
                        file_bytes = f.read()

                    file_meta = file_meta_map.get(file_path.name, {})
                    tz_hint = file_meta.get("timezone") or ("+05:30" if "app_events" in file_path.name else None)
                    try:
                        clock_skew_seconds = int(file_meta.get("clock_skew_seconds") or 0)
                    except (TypeError, ValueError):
                        clock_skew_seconds = 0
                    src_sys = file_meta.get("source_system") or (
                        "Firewall-01" if "firewall" in file_path.name else ("WebServer-DMZ" if "web" in file_path.name else "Linux-Host-01")
                    )
                    src_cat = file_meta.get("source_category") or "Security Telemetry"

                    evidence, job = ingestor.ingest_file(
                        investigation_id=inv_id,
                        file_bytes=file_bytes,
                        original_filename=file_path.name,
                        source_system=src_sys,
                        source_category=src_cat,
                        timezone_hint=tz_hint,
                        reference_year=reference_year,
                        clock_skew_seconds=clock_skew_seconds,
                        actor="DEMO_LOADER",
                    )
                    files_ingested += 1
                    total_events += job.total_records
                except Exception as e:
                    # Continue loading remaining scenario files
                    pass

    # 3. Automatically run Rule Engine
    alerts = run_all_rules(inv_id, db)

    # 4. Triage baselines are not hardcoded here. The comparison endpoint derives
    #    a human-effort estimate from the ingested logs and uses the real,
    #    measured ingestion duration for the VIGILANCE side.

    # Log audit
    audit = AuditLog(
        investigation_id=inv_id,
        action="DEMO_SCENARIO_LOADED",
        actor="DEMO_LOADER",
        timestamp=datetime.utcnow(),
        details=json.dumps({
            "scenario_id": sc_id,
            "files_ingested": files_ingested,
            "total_events": total_events,
            "alerts_generated": len(alerts),
        }),
    )
    db.add(audit)
    db.commit()
    invalidate_cache()

    return LoadScenarioResponse(
        investigation_id=inv_id,
        investigation_name=inv_name,
        scenario_id=sc_id,
        files_ingested=files_ingested,
        total_events=total_events,
        total_alerts=len(alerts),
        status="LOADED",
    )

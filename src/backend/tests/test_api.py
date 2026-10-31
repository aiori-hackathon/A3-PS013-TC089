"""Integration tests for FastAPI endpoints."""

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, get_db

# Set up test database
test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_health_check():
    """Verify health endpoint returns healthy status and metadata."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "VIGILANCE" in data["service"]


def test_investigation_crud_lifecycle():
    """Verify full investigation lifecycle: create, get, list, update, archive, and delete."""
    # 1. Create
    payload = {
        "name": "Integration Test Case",
        "description": "Validating end-to-end API workflows",
        "category": "Incident Response"
    }
    create_res = client.post("/api/investigations", json=payload)
    assert create_res.status_code == 201
    created_data = create_res.json()
    inv_id = created_data["id"]
    assert created_data["name"] == payload["name"]
    assert created_data["status"] == "ACTIVE"

    # 2. Get Single
    get_res = client.get(f"/api/investigations/{inv_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == inv_id

    # 3. List
    list_res = client.get("/api/investigations")
    assert list_res.status_code == 200
    assert any(i["id"] == inv_id for i in list_res.json())

    # 4. Update
    update_res = client.put(f"/api/investigations/{inv_id}", json={"name": "Renamed Test Case"})
    assert update_res.status_code == 200
    assert update_res.json()["name"] == "Renamed Test Case"

    # 5. Archive
    archive_res = client.post(f"/api/investigations/{inv_id}/archive")
    assert archive_res.status_code == 200
    assert archive_res.json()["status"] == "ARCHIVED"

    # 6. Delete
    delete_res = client.delete(f"/api/investigations/{inv_id}")
    assert delete_res.status_code == 200

    # 7. Confirm 404 after deletion
    get_after_delete = client.get(f"/api/investigations/{inv_id}")
    assert get_after_delete.status_code == 404


def test_demo_scenarios_list():
    """Verify demo scenarios catalog is returned."""
    res = client.get("/api/demo/scenarios")
    assert res.status_code == 200
    scenarios = res.json()
    assert len(scenarios) >= 3
    scenario_ids = [s["id"] for s in scenarios]
    assert "scenario_1" in scenario_ids
    assert "scenario_2" in scenario_ids
    assert "scenario_3" in scenario_ids


def test_triage_comparison_flow():
    """Verify triage measurement submission and comparison calculation."""
    # Create investigation
    inv_res = client.post("/api/investigations", json={"name": "Triage Benchmark Case"})
    inv_id = inv_res.json()["id"]

    # Submit Manual measurement
    manual_data = {
        "method": "MANUAL",
        "scenario": "Benchmark Scenario",
        "start_time": "2026-10-30T10:00:00Z",
        "end_time": "2026-10-30T10:30:00Z",  # 1800s
        "events_identified": 10,
        "records_processed": 500,
        "notes": "Manual review"
    }
    res_m = client.post(f"/api/investigations/{inv_id}/triage", json=manual_data)
    assert res_m.status_code == 201

    # Submit VIGILANCE measurement
    vigilance_data = {
        "method": "VIGILANCE",
        "scenario": "Benchmark Scenario",
        "start_time": "2026-10-30T10:00:00Z",
        "end_time": "2026-10-30T10:03:00Z",  # 180s
        "events_identified": 12,
        "records_processed": 500,
        "notes": "Automated triage"
    }
    res_v = client.post(f"/api/investigations/{inv_id}/triage", json=vigilance_data)
    assert res_v.status_code == 201

    # Get comparison
    comp_res = client.get(f"/api/investigations/{inv_id}/triage/comparison")
    assert comp_res.status_code == 200
    comp = comp_res.json()
    assert comp["manual_duration_seconds"] == 1800.0
    assert comp["vigilance_duration_seconds"] == 180.0
    assert comp["time_saved_seconds"] == 1620.0
    assert comp["speedup_factor"] == 10.0
    assert comp["efficiency_gain_percent"] == 90.0

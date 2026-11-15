"""Pydantic schemas for request and response validation in VIGILANCE."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# ==========================================
# INVESTIGATION SCHEMAS
# ==========================================

class InvestigationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Name of the forensic investigation")
    description: Optional[str] = Field(None, description="Detailed description")
    category: Optional[str] = Field("General Investigation", description="Category or incident type")


class InvestigationCreate(InvestigationBase):
    pass


class InvestigationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    category: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(ACTIVE|CLOSED|ARCHIVED)$")


class InvestigationResponse(InvestigationBase):
    id: str
    status: str
    created_at: datetime
    updated_at: datetime
    archived_at: Optional[datetime] = None
    evidence_count: int = 0
    event_count: int = 0
    alert_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class InvestigationDetailResponse(InvestigationResponse):
    pass


# ==========================================
# EVIDENCE SCHEMAS
# ==========================================

class EvidenceFileResponse(BaseModel):
    id: str
    investigation_id: str
    original_filename: str
    stored_filename: str
    file_size: int
    sha256_hash: str
    collection_timestamp: Optional[datetime] = None
    upload_timestamp: datetime
    source_system: Optional[str] = None
    source_category: Optional[str] = None
    file_format: Optional[str] = None
    processing_status: str
    timezone_hint: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EvidenceVerifyResponse(BaseModel):
    id: str
    verification_id: str
    evidence_id: str
    verified_at: datetime
    original_hash: str
    recalculated_hash: str
    result: str  # MATCH, MISMATCH, ERROR
    notes: Optional[str] = None


class IntegrityVerificationResponse(BaseModel):
    id: str
    evidence_id: str
    verified_at: datetime
    original_hash: str
    recalculated_hash: str
    result: str  # MATCH, MISMATCH, ERROR
    notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EvidenceUploadSummary(BaseModel):
    evidence_id: str
    job_id: Optional[str] = None
    filename: str
    file_size: int
    sha256: str
    detected_format: str
    records_processed: int
    parsed_ok: int
    parsed_partial: int
    parsed_failed: int
    missing_timestamps: int
    reference_year: Optional[int] = None
    clock_skew_seconds: int = 0
    status: str = "COMPLETED"


class ProcessingJobStatus(BaseModel):
    job_id: str
    evidence_id: str
    investigation_id: str
    filename: str
    file_size: int
    sha256: str
    detected_format: str
    status: str
    total_records: int
    parsed_ok: int
    parsed_partial: int
    parsed_failed: int
    missing_timestamps: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    errors: List[str] = []


# ==========================================
# EVENT SCHEMAS
# ==========================================

class EventResponse(BaseModel):
    id: str
    investigation_id: str
    evidence_id: str
    source_system: Optional[str] = None
    original_timestamp: Optional[str] = None
    normalized_timestamp: Optional[datetime] = None
    timestamp_status: str
    event_type: Optional[str] = None
    event_category: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    severity: str
    description: Optional[str] = None
    raw_record: str
    parsing_status: str
    extra_fields: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(from_attributes=True)


class PaginatedEventsResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    events: List[EventResponse]


class ProcessingSummaryResponse(BaseModel):
    investigation_id: str
    total_evidence_files: int
    total_events: int
    status_counts: Dict[str, int]
    timestamp_status_counts: Dict[str, int]
    severity_counts: Dict[str, int]
    category_counts: Dict[str, int]
    total_files: int = 0
    total_records: int = 0
    parsed_ok: int = 0
    parsed_partial: int = 0
    parsed_failed: int = 0
    missing_timestamps: int = 0


# ==========================================
# ANALYSIS & ALERT SCHEMAS
# ==========================================

class DetectionAlertResponse(BaseModel):
    id: str
    investigation_id: str
    rule_name: str
    severity: str
    explanation: str
    event_ids: List[str]
    ip_addresses: List[str]
    usernames: List[str]
    created_at: datetime
    alert_type: str

    model_config = ConfigDict(from_attributes=True)


class AnalyzeResponse(BaseModel):
    investigation_id: str
    rules_evaluated: int
    alerts_generated: int
    alerts: List[DetectionAlertResponse]


# ==========================================
# REPORT SCHEMAS
# ==========================================

class ReportGenerateRequest(BaseModel):
    format: str = Field("pdf", pattern="^(pdf|csv|json)$")
    include_raw_events: bool = False
    include_alerts: bool = True
    include_evidence_inventory: bool = True


class ReportResponse(BaseModel):
    id: str
    investigation_id: str
    filename: str
    format: str
    file_path: str
    generated_at: datetime
    file_size: int
    download_url: str

    model_config = ConfigDict(from_attributes=True)


# ==========================================
# TRIAGE SCHEMAS
# ==========================================

class TriageMeasurementCreate(BaseModel):
    method: str = Field(..., pattern="^(MANUAL|VIGILANCE)$")
    scenario: str
    start_time: datetime
    end_time: datetime
    events_identified: int = 0
    records_processed: int = 0
    notes: Optional[str] = None


class TriageMeasurementResponse(BaseModel):
    id: str
    investigation_id: str
    method: str
    scenario: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    events_identified: int
    records_processed: int
    notes: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TriageEstimateBreakdown(BaseModel):
    phase: str
    seconds: float
    detail: str


class HumanTriageEstimateResponse(BaseModel):
    available: bool = False
    estimated_seconds: float = 0.0
    estimated_minutes: float = 0.0
    records: int = 0
    sources: int = 0
    findings: int = 0
    complexity: str = "LOW"
    confidence: str = "LOW"
    breakdown: List[TriageEstimateBreakdown] = []
    assumptions: List[str] = []
    method: str = "Heuristic manual-triage model v1"


class TriageComparisonResponse(BaseModel):
    scenario: str
    investigation_id: str
    manual_duration_seconds: Optional[float] = None
    vigilance_duration_seconds: Optional[float] = None
    time_saved_seconds: Optional[float] = None
    speedup_factor: Optional[float] = None
    efficiency_gain_percent: Optional[float] = None
    manual_events_identified: Optional[int] = None
    vigilance_events_identified: Optional[int] = None
    manual_is_estimated: bool = False
    vigilance_is_estimated: bool = False
    estimation_method: Optional[str] = None


# ==========================================
# DEMO & SCENARIO SCHEMAS
# ==========================================

class ScenarioInfo(BaseModel):
    id: str
    name: str
    description: str
    difficulty: str
    source_types: List[str]
    file_count: int
    expected_findings: List[str]


class LoadScenarioRequest(BaseModel):
    scenario_id: str


class LoadScenarioResponse(BaseModel):
    investigation_id: str
    investigation_name: str
    scenario_id: str
    files_ingested: int
    total_events: int
    total_alerts: int
    status: str


# ==========================================
# DASHBOARD STATS SCHEMA
# ==========================================

class SeverityCount(BaseModel):
    severity: str
    count: int

class CategoryCount(BaseModel):
    category: str
    count: int

class TimeSeriesPoint(BaseModel):
    date: str
    count: int

class DashboardStatsResponse(BaseModel):
    # Primary metrics
    total_investigations: int
    active_investigations: int
    total_evidence_files: int
    total_events: int
    total_alerts: int
    critical_alerts: int
    avg_triage_time_saved_percent: float
    # Fields expected by frontend
    parsed_ok: int = 0
    parsed_failed: int = 0
    integrity_verified: int = 0
    suspicious_events: int = 0
    # Lists
    recent_investigations: List[InvestigationResponse]
    recent_alerts: List[DetectionAlertResponse]
    recent_evidence: List["EvidenceFileResponse"] = []
    # Chart data
    events_by_severity: List[SeverityCount] = []
    events_by_category: List[CategoryCount] = []
    events_over_time: List[TimeSeriesPoint] = []

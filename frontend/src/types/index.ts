export interface Investigation {
  id: string;
  name: string;
  description?: string;
  category: string;
  status: 'ACTIVE' | 'ARCHIVED' | 'CLOSED';
  created_at: string;
  updated_at: string;
  event_count?: number;
  evidence_count?: number;
}

export interface EvidenceFile {
  id: string;
  investigation_id: string;
  original_filename: string;
  stored_filename: string;
  file_size: number;
  sha256_hash: string;
  collection_timestamp: string;
  upload_timestamp: string;
  source_system: string;
  source_category: string;
  file_format: string;
  processing_status: string;
  timezone_hint?: string;
}

export interface EvidenceUploadSummary {
  evidence_id: string;
  filename: string;
  file_size: number;
  sha256: string;
  detected_format: string;
  records_processed: number;
  parsed_ok: number;
  parsed_partial: number;
  parsed_failed: number;
  missing_timestamps: number;
}

export interface Event {
  id: string;
  investigation_id: string;
  evidence_id: string;
  source_system: string;
  original_timestamp?: string;
  normalized_timestamp?: string;
  timestamp_status: string;
  event_type: string;
  event_category: string;
  username?: string;
  source_ip?: string;
  dest_ip?: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'INFO';
  description: string;
  raw_record: string;
  parsing_status: string;
  extra_fields?: Record<string, unknown>;
}

export interface IntegrityVerification {
  id: string;
  evidence_id: string;
  verified_at: string;
  original_hash: string;
  recalculated_hash: string;
  result: 'MATCH' | 'MISMATCH' | 'ERROR';
  notes?: string;
}

export interface DetectionAlert {
  id: string;
  investigation_id: string;
  rule_name: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  explanation: string;
  event_ids: string[];
  ip_addresses: string[];
  usernames: string[];
  created_at: string;
  alert_type: string;
}

export interface ProcessingJob {
  id: string;
  evidence_id: string;
  investigation_id: string;
  started_at: string;
  completed_at?: string;
  status: string;
  total_records: number;
  parsed_ok: number;
  parsed_partial: number;
  parsed_failed: number;
  missing_timestamps: number;
}

export interface TriageMeasurement {
  id: string;
  investigation_id: string;
  method: 'MANUAL' | 'VIGILANCE';
  scenario: string;
  start_time: string;
  end_time?: string;
  duration_seconds?: number;
  events_identified: number;
  records_processed: number;
  notes?: string;
}

export interface DashboardStats {
  total_investigations: number;
  active_investigations?: number;
  total_evidence_files: number;
  total_events: number;
  total_alerts?: number;
  critical_alerts?: number;
  avg_triage_time_saved_percent?: number;
  parsed_ok: number;
  parsed_failed: number;
  integrity_verified: number;
  suspicious_events: number;
  recent_investigations: Investigation[];
  recent_alerts?: DetectionAlert[];
  recent_evidence: EvidenceFile[];
  events_by_severity: Array<{ severity: string; count: number }>;
  events_by_category: Array<{ category: string; count: number }>;
  events_over_time: Array<{ date: string; count: number }>;
}

export interface ProcessingSummary {
  total_files: number;
  total_records: number;
  parsed_ok: number;
  parsed_partial: number;
  parsed_failed: number;
  missing_timestamps: number;
  jobs?: ProcessingJob[];
  total_evidence_files?: number;
  total_events?: number;
  status_counts?: Record<string, number>;
  timestamp_status_counts?: Record<string, number>;
  severity_counts?: Record<string, number>;
  category_counts?: Record<string, number>;
}

export interface DemoScenario {
  id: string;
  name: string;
  description: string;
  difficulty: string;
  source_types: string[];
  file_count: number;
  expected_findings?: string[];
}

export interface ReportItem {
  id?: string;
  investigation_id: string;
  filename?: string;
  format: 'PDF' | 'CSV' | 'JSON' | string;
  file_size?: number;
  generated_at: string;
  download_url?: string;
}

export interface TriageComparisonData {
  scenario: string;
  investigation_id: string;
  manual_duration_seconds?: number;
  vigilance_duration_seconds?: number;
  time_saved_seconds?: number;
  speedup_factor?: number;
  efficiency_gain_percent?: number;
  manual_events_identified?: number;
  vigilance_events_identified?: number;
}

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
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH';
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
  total_evidence_files: number;
  total_events: number;
  parsed_ok: number;
  parsed_failed: number;
  integrity_verified: number;
  suspicious_events: number;
  recent_investigations: Investigation[];
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
  jobs: ProcessingJob[];
}

export interface DemoScenario {
  id: string;
  name: string;
  description: string;
  category: string;
  records_count?: number;
  evidence_files?: string[];
}

export interface ReportItem {
  id?: string;
  investigation_id: string;
  filename: string;
  format: 'PDF' | 'CSV' | 'JSON' | string;
  file_size?: number;
  generated_at: string;
  download_url?: string;
}

export interface TriageComparisonData {
  manual?: TriageMeasurement;
  vigilance?: TriageMeasurement;
  time_saved_seconds?: number;
  percentage_reduction?: number;
}

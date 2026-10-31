export const INVESTIGATION_CATEGORIES = [
  'Unauthorized Access',
  'Data Breach',
  'Malware',
  'Insider Threat',
  'Ransomware',
  'Phishing',
  'Other'
] as const;

export const SOURCE_CATEGORIES = [
  'Authentication / IAM',
  'Firewall / Perimeter',
  'Web Server / Application',
  'Endpoint / OS',
  'Network / IDS',
  'Database / Storage',
  'Cloud Audit Log',
  'Other'
] as const;

export const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

export const INVESTIGATION_STATUSES = ['ACTIVE', 'ARCHIVED', 'CLOSED'] as const;

export const STORAGE_KEYS = {
  BACKEND_URL: 'vigilance_backend_url',
  ACTIVE_INVESTIGATION_ID: 'vigilance_active_investigation_id'
} as const;

export const DEFAULT_API_BASE = 'http://localhost:8000/api';

import axios from 'axios';
import { STORAGE_KEYS, DEFAULT_API_BASE } from '../utils/constants';
import type {
  Investigation,
  EvidenceFile,
  Event,
  IntegrityVerification,
  DetectionAlert,
  ProcessingSummary,
  TriageMeasurement,
  TriageComparisonData,
  DashboardStats,
  DemoScenario,
  ReportItem
} from '../types';

export function getApiBaseUrl(): string {
  if (typeof window !== 'undefined') {
    const saved = localStorage.getItem(STORAGE_KEYS.BACKEND_URL);
    if (saved) return saved;
  }
  return DEFAULT_API_BASE;
}

export function getBackendRootUrl(): string {
  const apiBase = getApiBaseUrl();
  return apiBase.replace(/\/api\/?$/, '');
}

export const api = axios.create();

// Interceptor to always use the current base URL
api.interceptors.request.use((config) => {
  config.baseURL = getApiBaseUrl();
  return config;
});

export interface CreateInvestigationPayload {
  name: string;
  description?: string;
  category: string;
}

export interface UpdateInvestigationPayload {
  name?: string;
  description?: string;
  category?: string;
  status?: 'ACTIVE' | 'ARCHIVED' | 'CLOSED';
}

export interface EventQueryParams {
  search?: string;
  source_ip?: string;
  dest_ip?: string;
  username?: string;
  event_category?: string;
  severity?: string;
  start_time?: string;
  end_time?: string;
  evidence_id?: string;
  sort_order?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

export interface CreateTriagePayload {
  method: 'MANUAL' | 'VIGILANCE';
  scenario: string;
  duration_seconds: number;
  events_identified: number;
  records_processed: number;
  notes?: string;
  start_time?: string;
  end_time?: string;
}

// Investigations
export const investigationsApi = {
  list: () => api.get<Investigation[]>('/investigations'),
  get: (id: string) => api.get<Investigation>(`/investigations/${id}`),
  create: (data: CreateInvestigationPayload) => api.post<Investigation>('/investigations', data),
  update: (id: string, data: UpdateInvestigationPayload) => api.put<Investigation>(`/investigations/${id}`, data),
  delete: (id: string) => api.delete<{ success: boolean; message?: string }>(`/investigations/${id}`),
  archive: (id: string) => api.post<Investigation>(`/investigations/${id}/archive`),
  getEvents: (id: string, params?: EventQueryParams) =>
    api.get<{ events: Event[]; total: number; page?: number; limit?: number } | Event[]>(`/investigations/${id}/events`, { params }),
  getTimeline: (id: string, params?: EventQueryParams) =>
    api.get<{ events: Event[]; uncertain_events?: Event[]; total?: number } | Event[]>(`/investigations/${id}/timeline`, { params }),
  getAlerts: (id: string) => api.get<DetectionAlert[]>(`/investigations/${id}/alerts`),
  analyze: (id: string) => api.post<{ alerts: DetectionAlert[]; count: number; message?: string }>(`/investigations/${id}/analyze`),
  getEvidence: (id: string) => api.get<EvidenceFile[]>(`/investigations/${id}/evidence`),
  getProcessingSummary: (id: string) => api.get<ProcessingSummary>(`/investigations/${id}/processing-summary`),
  generateReport: (id: string, format: string) =>
    api.post<ReportItem>(`/investigations/${id}/report`, { format }),
  getReports: (id: string) => api.get<ReportItem[]>(`/investigations/${id}/reports`),
  getTriage: (id: string) => api.get<TriageMeasurement[]>(`/investigations/${id}/triage`),
  createTriage: (id: string, data: CreateTriagePayload) =>
    api.post<TriageMeasurement>(`/investigations/${id}/triage`, data),
  getTriageComparison: (id: string) =>
    api.get<TriageComparisonData>(`/investigations/${id}/triage/comparison`),
};

// Evidence
export const evidenceApi = {
  listAll: () => api.get<EvidenceFile[]>('/evidence'),
  upload: (formData: FormData, onUploadProgress?: (progressEvent: { loaded: number; total?: number }) => void) =>
    api.post<EvidenceFile>('/evidence/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress
    }),
  get: (id: string) => api.get<EvidenceFile>(`/evidence/${id}`),
  verify: (id: string) => api.post<IntegrityVerification>(`/evidence/${id}/verify`),
  getVerifications: (id: string) => api.get<IntegrityVerification[]>(`/evidence/${id}/verifications`),
  download: (id: string) => `${getApiBaseUrl()}/evidence/${id}/download`,
};

// Demo
export const demoApi = {
  getScenarios: () => api.get<DemoScenario[]>('/demo/scenarios'),
  loadScenario: (scenario_name: string) =>
    api.post<{ success: boolean; investigation_id: string; message: string }>('/demo/load-scenario', { scenario_name }),
};

// Dashboard
export const dashboardApi = {
  getStats: () => api.get<DashboardStats>('/dashboard/stats'),
};

// System Health
export const systemApi = {
  checkHealth: async () => {
    const root = getBackendRootUrl();
    try {
      // First try root /health
      return await axios.get(`${root}/health`, { timeout: 4000 });
    } catch {
      // Fallback try /api/health
      return await axios.get(`${getApiBaseUrl()}/health`, { timeout: 4000 });
    }
  }
};

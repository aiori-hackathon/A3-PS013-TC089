import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  FolderOpen,
  Database,
  Clock,
  AlertTriangle,
  FileText,
  Upload,
  Play,
  Download,
  HardDrive,
  ShieldCheck,
  Search,
  Code,
  Archive,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { investigationsApi, evidenceApi, getBackendRootUrl } from '../services/api';
import type {
  Investigation,
  EvidenceFile,
  Event,
  DetectionAlert,
  ReportItem,
  ProcessingSummary,
} from '../types';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Modal } from '../components/ui/Modal';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table';
import { HashDisplay } from '../components/ui/HashDisplay';
import { formatDate, formatBytes } from '../utils/formatters';

type TabType = 'overview' | 'evidence' | 'events' | 'alerts' | 'reports';

export const InvestigationDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [evidenceList, setEvidenceList] = useState<EvidenceFile[]>([]);
  const [eventsList, setEventsList] = useState<Event[]>([]);
  const [alertsList, setAlertsList] = useState<DetectionAlert[]>([]);
  const [reportsList, setReportsList] = useState<ReportItem[]>([]);
  const [processingSummary, setProcessingSummary] = useState<ProcessingSummary | null>(null);

  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);
  const [generatingReport, setGeneratingReport] = useState<string | null>(null);
  const [verifyingEvidenceId, setVerifyingEvidenceId] = useState<string | null>(null);

  // Events filtering
  const [eventSearch, setEventSearch] = useState('');
  const [eventSeverity, setEventSeverity] = useState('ALL');
  const [eventPage, setEventPage] = useState(1);
  const [totalEvents, setTotalEvents] = useState(0);
  const [eventTotalPages, setEventTotalPages] = useState(1);

  // Raw Event Modal
  const [selectedRawEvent, setSelectedRawEvent] = useState<Event | null>(null);

  const loadInvestigationData = useCallback(async () => {
    if (!id) return;
    try {
      setLoading(true);
      const [invRes, evRes, summaryRes, alertsRes, reportsRes] = await Promise.allSettled([
        investigationsApi.get(id),
        investigationsApi.getEvidence(id),
        investigationsApi.getProcessingSummary(id),
        investigationsApi.getAlerts(id),
        investigationsApi.getReports(id),
      ]);

      if (invRes.status === 'fulfilled') setInvestigation(invRes.value.data);
      if (evRes.status === 'fulfilled') setEvidenceList(Array.isArray(evRes.value.data) ? evRes.value.data : []);
      if (summaryRes.status === 'fulfilled') setProcessingSummary(summaryRes.value.data);
      if (alertsRes.status === 'fulfilled') setAlertsList(Array.isArray(alertsRes.value.data) ? alertsRes.value.data : []);
      if (reportsRes.status === 'fulfilled') setReportsList(Array.isArray(reportsRes.value.data) ? reportsRes.value.data : []);
    } catch {
      toast.error('Failed to load investigation details');
    } finally {
      setLoading(false);
    }
  }, [id]);

  const loadEvents = useCallback(async () => {
    if (!id) return;
    try {
      const res = await investigationsApi.getEvents(id, {
        search: eventSearch || undefined,
        severity: eventSeverity === 'ALL' ? undefined : eventSeverity,
        page: eventPage,
        page_size: 50,
      });

      if (res.data && 'events' in res.data) {
        setEventsList(res.data.events || []);
        setTotalEvents(res.data.total || (res.data.events || []).length);
        setEventTotalPages(
          res.data.total_pages ||
            Math.max(1, Math.ceil((res.data.total || 0) / 50))
        );
      } else if (Array.isArray(res.data)) {
        setEventsList(res.data);
        setTotalEvents(res.data.length);
        setEventTotalPages(1);
      }
    } catch {
      setEventsList([]);
    }
  }, [id, eventSearch, eventSeverity, eventPage]);

  useEffect(() => {
    loadInvestigationData();
  }, [loadInvestigationData]);

  useEffect(() => {
    if (activeTab === 'events') {
      loadEvents();
    }
  }, [activeTab, loadEvents]);

  const handleRunAnalysis = async () => {
    if (!id) return;
    try {
      setAnalyzing(true);
      const res = await investigationsApi.analyze(id);
      toast.success(res.data?.message || 'Correlation engine finished analysis');
      const alertsRes = await investigationsApi.getAlerts(id);
      setAlertsList(Array.isArray(alertsRes.data) ? alertsRes.data : []);
    } catch {
      toast.error('Detection analysis failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleVerifyEvidence = async (evidenceId: string) => {
    try {
      setVerifyingEvidenceId(evidenceId);
      const res = await evidenceApi.verify(evidenceId);
      if (res.data?.result === 'MATCH') {
        toast.success(`Integrity MATCH for ${evidenceId.slice(0, 8)}`);
      } else if (res.data?.result === 'MISMATCH') {
        toast.error(`ALERT: SHA-256 hash MISMATCH for ${evidenceId.slice(0, 8)}!`);
      } else {
        toast('Verification executed with status: ' + res.data?.result);
      }
      loadInvestigationData();
    } catch {
      toast.error('Integrity baseline verification failed');
    } finally {
      setVerifyingEvidenceId(null);
    }
  };

  const handleGenerateReport = async (format: 'PDF' | 'CSV' | 'JSON') => {
    if (!id) return;
    try {
      setGeneratingReport(format);
      await investigationsApi.generateReport(id, format.toLowerCase());
      toast.success(`${format} forensic report generated successfully`);
      const reportsRes = await investigationsApi.getReports(id);
      setReportsList(Array.isArray(reportsRes.data) ? reportsRes.data : []);
    } catch {
      toast.error(`Failed to generate ${format} report`);
    } finally {
      setGeneratingReport(null);
    }
  };

  const handleArchive = async () => {
    if (!id) return;
    try {
      await investigationsApi.archive(id);
      toast.success('Investigation archived');
      loadInvestigationData();
    } catch {
      toast.error('Failed to archive investigation');
    }
  };

  if (loading && !investigation) {
    return <LoadingSpinner label="Loading investigation case file..." />;
  }

  if (!investigation) {
    return (
      <EmptyState
        icon={<AlertTriangle className="w-8 h-8 text-red-400" />}
        title="Investigation Not Found"
        description="The requested investigation could not be retrieved from the server."
        actionLabel="Back to Investigations"
        onAction={() => navigate('/investigations')}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#1e293b]">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
              <FolderOpen className="w-5 h-5 text-sky-400" />
              {investigation.name}
            </h1>
            <Badge variant={investigation.status} label={investigation.status} />
          </div>
          <div className="flex items-center gap-4 text-xs font-mono text-slate-400 mt-1">
            <span>CATEGORY: {investigation.category}</span>
            <span>•</span>
            <span>CREATED: {formatDate(investigation.created_at)}</span>
            <span>•</span>
            <span>ID: {investigation.id}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="secondary"
            size="sm"
            icon={<Upload className="w-4 h-4" />}
            onClick={() => navigate(`/ingestion?investigation_id=${investigation.id}`)}
          >
            Add Evidence
          </Button>
          <Button
            variant="outline"
            size="sm"
            loading={analyzing}
            icon={<Play className="w-4 h-4 text-sky-400" />}
            onClick={handleRunAnalysis}
          >
            Run Threat Analysis
          </Button>
          {investigation.status !== 'ARCHIVED' && (
            <Button
              variant="ghost"
              size="sm"
              icon={<Archive className="w-4 h-4" />}
              onClick={handleArchive}
            >
              Archive
            </Button>
          )}
        </div>
      </div>

      {/* Tabs Bar */}
      <div className="flex items-center gap-1 border-b border-[#1e293b] overflow-x-auto pb-px">
        {[
          { key: 'overview', label: 'Overview', icon: FolderOpen },
          { key: 'evidence', label: `Evidence (${evidenceList.length})`, icon: Database },
          { key: 'events', label: `Events (${investigation.event_count ?? eventsList.length})`, icon: Clock },
          { key: 'alerts', label: `Alerts (${alertsList.length})`, icon: AlertTriangle },
          { key: 'reports', label: `Reports (${reportsList.length})`, icon: FileText },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as TabType)}
              className={`flex items-center gap-2 px-4 py-2.5 text-xs font-mono uppercase tracking-wider rounded-t-md transition-all border-b-2 cursor-pointer shrink-0 ${
                isActive
                  ? 'border-sky-500 text-sky-400 bg-[#161f30]'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-[#111827]'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB CONTENT */}

      {/* Tab 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Quick Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card className="py-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded bg-sky-950 text-sky-400 border border-sky-800">
                  <Database className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-mono text-slate-400 uppercase">Evidence Files</div>
                  <div className="text-xl font-bold font-mono text-slate-100">
                    {evidenceList.length}
                  </div>
                </div>
              </div>
            </Card>

            <Card className="py-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                  <Clock className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-mono text-slate-400 uppercase">Parsed Events</div>
                  <div className="text-xl font-bold font-mono text-slate-100">
                    {investigation.event_count ?? 0}
                  </div>
                </div>
              </div>
            </Card>

            <Card className="py-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded bg-red-950 text-red-400 border border-red-800">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-mono text-slate-400 uppercase">Detection Alerts</div>
                  <div className="text-xl font-bold font-mono text-red-400">
                    {alertsList.length}
                  </div>
                </div>
              </div>
            </Card>

            <Card className="py-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-mono text-slate-400 uppercase">Reports Ready</div>
                  <div className="text-xl font-bold font-mono text-slate-100">
                    {reportsList.length}
                  </div>
                </div>
              </div>
            </Card>
          </div>

          {/* Description & Processing Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="lg:col-span-2 space-y-4">
              <CardHeader title="Case Scope & Incident Overview" />
              <div className="text-sm text-slate-300 leading-relaxed bg-[#0d1117] p-4 rounded-md border border-[#1e293b]">
                {investigation.description || (
                  <span className="text-slate-500 italic">No detailed case description recorded.</span>
                )}
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-2 text-xs font-mono">
                <div className="p-2.5 rounded bg-[#0d1117] border border-[#1e293b]">
                  <span className="text-slate-500 block uppercase">Created At</span>
                  <span className="text-slate-200 mt-1 block">{formatDate(investigation.created_at)}</span>
                </div>
                <div className="p-2.5 rounded bg-[#0d1117] border border-[#1e293b]">
                  <span className="text-slate-500 block uppercase">Updated At</span>
                  <span className="text-slate-200 mt-1 block">{formatDate(investigation.updated_at)}</span>
                </div>
                <div className="p-2.5 rounded bg-[#0d1117] border border-[#1e293b]">
                  <span className="text-slate-500 block uppercase">Threat Category</span>
                  <span className="text-sky-400 mt-1 block">{investigation.category}</span>
                </div>
              </div>
            </Card>

            <Card className="space-y-4">
              <CardHeader title="Log Parsing Telemetry" />
              {processingSummary ? (
                <div className="space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between p-2 rounded bg-[#0d1117] border border-[#1e293b]">
                    <span className="text-slate-400">Total Records</span>
                    <span className="text-slate-200 font-bold">{processingSummary.total_records}</span>
                  </div>
                  <div className="flex items-center justify-between p-2 rounded bg-[#0d1117] border border-[#1e293b]">
                    <span className="text-emerald-400">Parsed Successfully</span>
                    <span className="text-emerald-400 font-bold">{processingSummary.parsed_ok}</span>
                  </div>
                  <div className="flex items-center justify-between p-2 rounded bg-[#0d1117] border border-[#1e293b]">
                    <span className="text-yellow-400">Partial / Missing TS</span>
                    <span className="text-yellow-400 font-bold">
                      {processingSummary.parsed_partial + processingSummary.missing_timestamps}
                    </span>
                  </div>
                  <div className="flex items-center justify-between p-2 rounded bg-[#0d1117] border border-[#1e293b]">
                    <span className="text-red-400">Parsing Failed</span>
                    <span className="text-red-400 font-bold">{processingSummary.parsed_failed}</span>
                  </div>
                </div>
              ) : (
                <div className="text-xs font-mono text-slate-500 text-center py-6">
                  No ingestion jobs logged for this case.
                </div>
              )}
            </Card>
          </div>
        </div>
      )}

      {/* Tab 2: EVIDENCE */}
      {activeTab === 'evidence' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold font-mono text-slate-300 uppercase">
              Cryptographically Baseline Files ({evidenceList.length})
            </h3>
            <Button
              size="sm"
              icon={<Upload className="w-4 h-4" />}
              onClick={() => navigate(`/ingestion?investigation_id=${investigation.id}`)}
            >
              Ingest More Evidence
            </Button>
          </div>

          {evidenceList.length === 0 ? (
            <EmptyState
              icon={<Database className="w-8 h-8" />}
              title="No evidence files bound to case"
              description="Ingest syslog, CSV, JSON or Windows Event artifacts into this case."
              actionLabel="Ingest Log Evidence"
              onAction={() => navigate(`/ingestion?investigation_id=${investigation.id}`)}
            />
          ) : (
            <div className="space-y-3">
              {evidenceList.map((ev) => (
                <div
                  key={ev.id}
                  className="bg-[#111827] border border-[#1e293b] rounded-lg p-4 transition-all hover:border-slate-700 space-y-3"
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <div className="p-2.5 rounded-md bg-[#1a2235] text-sky-400 shrink-0">
                        <HardDrive className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <h4 className="font-semibold text-slate-100 text-sm">
                            {ev.original_filename}
                          </h4>
                          <Badge variant="INFO" size="sm" label={ev.file_format || 'LOG'} />
                          <Badge variant={ev.processing_status} size="sm" label={ev.processing_status} />
                        </div>
                        <div className="flex items-center gap-4 text-xs text-slate-400 mt-1 font-mono">
                          <span>Size: {formatBytes(ev.file_size)}</span>
                          <span>System: {ev.source_system}</span>
                          <span>Category: {ev.source_category}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <Button
                        size="sm"
                        variant="outline"
                        loading={verifyingEvidenceId === ev.id}
                        icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
                        onClick={() => handleVerifyEvidence(ev.id)}
                      >
                        Verify Baseline
                      </Button>
                      <a
                        href={evidenceApi.download(ev.id)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-[#1a2235] text-slate-200 hover:bg-[#243049] border border-[#1e293b]"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Download
                      </a>
                    </div>
                  </div>

                  <div className="bg-[#0a0e1a] rounded p-2.5 border border-[#1e293b] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                    <div className="flex items-center gap-2 overflow-hidden">
                      <span className="text-slate-500 uppercase tracking-wider text-[11px] shrink-0">
                        SHA-256:
                      </span>
                      <HashDisplay hash={ev.sha256_hash} />
                    </div>
                    <span className="text-slate-400 shrink-0 text-[11px]">
                      Uploaded: {formatDate(ev.upload_timestamp)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: EVENTS */}
      {activeTab === 'events' && (
        <div className="space-y-4">
          <Card className="py-3 px-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="md:col-span-2">
                <Input
                  icon={<Search className="w-4 h-4" />}
                  placeholder="Filter events by IP, username, description, or event type..."
                  value={eventSearch}
                  onChange={(e) => {
                    setEventSearch(e.target.value);
                    setEventPage(1);
                  }}
                />
              </div>
              <div>
                <Select
                  value={eventSeverity}
                  onChange={(e) => {
                    setEventSeverity(e.target.value);
                    setEventPage(1);
                  }}
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFO">INFO</option>
                </Select>
              </div>
            </div>
          </Card>

          {eventsList.length === 0 ? (
            <EmptyState
              icon={<Clock className="w-8 h-8" />}
              title="No events matching criteria"
              description="Either no log files have been parsed or no events match the current filter query."
              actionLabel="View All Timeline"
              onAction={() => navigate('/timeline')}
            />
          ) : (
            <Card className="p-0 overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Normalized Timestamp (UTC)</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Category / Type</TableHead>
                    <TableHead>Source IP</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead className="text-right">Raw</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {eventsList.map((evt) => (
                    <TableRow key={evt.id}>
                      <TableCell className="font-mono text-xs whitespace-nowrap text-sky-400">
                        {formatDate(evt.normalized_timestamp || evt.original_timestamp)}
                      </TableCell>
                      <TableCell>
                        <Badge variant={evt.severity} size="sm" label={evt.severity} />
                      </TableCell>
                      <TableCell>
                        <span className="text-xs font-mono text-slate-300">
                          {evt.event_category}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-300">
                        {evt.source_ip || '—'}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-300">
                        {evt.username || '—'}
                      </TableCell>
                      <TableCell className="text-xs text-slate-300 max-w-sm truncate">
                        {evt.description}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          icon={<Code className="w-3.5 h-3.5" />}
                          onClick={() => setSelectedRawEvent(evt)}
                        >
                          Raw
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          )}

          {totalEvents > 50 && (
            <div className="flex items-center justify-between text-xs font-mono text-slate-400 px-2">
              <span>Showing up to 50 of {totalEvents} recorded events</span>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={eventPage <= 1}
                  onClick={() => setEventPage((p) => Math.max(1, p - 1))}
                >
                  Previous
                </Button>
                <span>Page {eventPage} of {eventTotalPages}</span>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={eventPage >= eventTotalPages}
                  onClick={() => setEventPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: ALERTS */}
      {activeTab === 'alerts' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold font-mono text-slate-300 uppercase">
              Threat Rule Engine Alerts ({alertsList.length})
            </h3>
            <Button
              size="sm"
              variant="primary"
              loading={analyzing}
              icon={<Play className="w-4 h-4" />}
              onClick={handleRunAnalysis}
            >
              Execute Correlation Rules
            </Button>
          </div>

          {alertsList.length === 0 ? (
            <EmptyState
              icon={<AlertTriangle className="w-8 h-8" />}
              title="No alerts detected"
              description="Run the automated correlation analysis to evaluate Sigma and threat detection heuristics against this case's log telemetry."
              actionLabel="Run Threat Analysis"
              onAction={handleRunAnalysis}
            />
          ) : (
            <div className="space-y-3">
              {alertsList.map((alert) => (
                <div
                  key={alert.id}
                  className="bg-[#111827] border border-[#1e293b] rounded-lg p-4 space-y-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3">
                      <div className="p-2 rounded bg-red-950/60 text-red-400 border border-red-800/80 shrink-0">
                        <AlertTriangle className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <h4 className="font-semibold text-slate-100 text-sm">
                            {alert.rule_name}
                          </h4>
                          <Badge variant={alert.severity} size="sm" label={alert.severity} />
                          <Badge variant="DEFAULT" size="sm" label={alert.alert_type} />
                        </div>
                        <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                          {alert.explanation}
                        </p>
                      </div>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500 shrink-0">
                      {formatDate(alert.created_at)}
                    </span>
                  </div>

                  <div className="bg-[#0d1117] p-2.5 rounded border border-[#1e293b] text-xs font-mono flex flex-wrap gap-4 text-slate-400">
                    <div>
                      <span className="text-slate-500 uppercase">Affected IPs: </span>
                      <span className="text-sky-400">
                        {alert.ip_addresses?.length ? alert.ip_addresses.join(', ') : 'None'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 uppercase">Accounts: </span>
                      <span className="text-emerald-400">
                        {alert.usernames?.length ? alert.usernames.join(', ') : 'None'}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 uppercase">Correlated Events: </span>
                      <span className="text-yellow-400">{alert.event_ids?.length ?? 0}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 5: REPORTS */}
      {activeTab === 'reports' && (
        <div className="space-y-6">
          <Card>
            <CardHeader
              title="Generate Digital Forensic Report"
              subtitle="Export cryptographically verifiable incident chain-of-custody packages"
            />
            <div className="flex flex-wrap gap-3">
              <Button
                variant="primary"
                loading={generatingReport === 'PDF'}
                icon={<FileText className="w-4 h-4" />}
                onClick={() => handleGenerateReport('PDF')}
              >
                Generate Executive PDF
              </Button>
              <Button
                variant="secondary"
                loading={generatingReport === 'CSV'}
                icon={<Download className="w-4 h-4" />}
                onClick={() => handleGenerateReport('CSV')}
              >
                Export Normalized CSV
              </Button>
              <Button
                variant="outline"
                loading={generatingReport === 'JSON'}
                icon={<Code className="w-4 h-4" />}
                onClick={() => handleGenerateReport('JSON')}
              >
                Export Structured JSON
              </Button>
            </div>
          </Card>

          <Card className="p-0 overflow-hidden">
            <div className="p-4 border-b border-[#1e293b]">
              <h3 className="text-sm font-semibold font-mono text-slate-300 uppercase">
                Generated Forensic Reports ({reportsList.length})
              </h3>
            </div>

            {reportsList.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-slate-500">
                No reports generated yet. Click above to generate an executive briefing or export.
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Report Artifact</TableHead>
                    <TableHead>Format</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead>Generated Timestamp</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reportsList.map((rep, idx) => (
                    <TableRow key={rep.id || idx}>
                      <TableCell className="font-mono text-xs text-slate-200">
                        {rep.filename}
                      </TableCell>
                      <TableCell>
                        <Badge variant="INFO" size="sm" label={rep.format} />
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-400">
                        {rep.file_size ? formatBytes(rep.file_size) : '—'}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-400">
                        {formatDate(rep.generated_at)}
                      </TableCell>
                      <TableCell className="text-right">
                        <a
                          href={rep.download_url ? `${getBackendRootUrl()}${rep.download_url}` : '#'}
                          download={rep.filename}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded bg-[#1a2235] text-sky-400 hover:bg-[#243049] border border-[#1e293b]"
                        >
                          <Download className="w-3.5 h-3.5" />
                          Download
                        </a>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Card>
        </div>
      )}

      {/* Raw Event Modal */}
      <Modal
        isOpen={!!selectedRawEvent}
        onClose={() => setSelectedRawEvent(null)}
        title="Forensic Raw Event Record Inspection"
        maxWidth="2xl"
      >
        {selectedRawEvent && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-[#0d1117] border border-[#1e293b]">
                <span className="text-slate-500 block uppercase">Event Type</span>
                <span className="text-sky-400 mt-0.5 block">{selectedRawEvent.event_type}</span>
              </div>
              <div className="p-2.5 rounded bg-[#0d1117] border border-[#1e293b]">
                <span className="text-slate-500 block uppercase">Timestamp Status</span>
                <span className="text-emerald-400 mt-0.5 block">
                  {selectedRawEvent.timestamp_status}
                </span>
              </div>
            </div>

            <div>
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1">
                Raw Log Payload
              </span>
              <pre className="p-3 bg-[#0a0e1a] border border-[#1e293b] rounded-md text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap select-all">
                {selectedRawEvent.raw_record}
              </pre>
            </div>

            {selectedRawEvent.extra_fields && Object.keys(selectedRawEvent.extra_fields).length > 0 && (
              <div>
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  Extracted Dynamic Metadata
                </span>
                <pre className="p-3 bg-[#0a0e1a] border border-[#1e293b] rounded-md text-xs font-mono text-slate-400 overflow-x-auto">
                  {JSON.stringify(selectedRawEvent.extra_fields, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-[#1e293b]">
              <Button variant="secondary" onClick={() => setSelectedRawEvent(null)}>
                Close
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default InvestigationDetail;

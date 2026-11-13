import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertTriangle,
  Play,
  Layers,
  User,
  Globe,
  FileSearch,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { investigationsApi } from '../services/api';
import type { Investigation, DetectionAlert, Event } from '../types';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Select } from '../components/ui/Select';
import { Modal } from '../components/ui/Modal';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table';
import { formatDate } from '../utils/formatters';

export const IncidentAnalysis: React.FC = () => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedInvId, setSelectedInvId] = useState<string>('');
  const [alerts, setAlerts] = useState<DetectionAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [analyzing, setAnalyzing] = useState(false);

  // Related events modal state
  const [selectedAlert, setSelectedAlert] = useState<DetectionAlert | null>(null);
  const [relatedEvents, setRelatedEvents] = useState<Event[]>([]);
  const [loadingEvents, setLoadingEvents] = useState(false);

  useEffect(() => {
    const fetchInvs = async () => {
      try {
        const res = await investigationsApi.list();
        const list = Array.isArray(res.data) ? res.data : [];
        setInvestigations(list);
        if (list.length > 0 && !selectedInvId) {
          setSelectedInvId(list[0].id);
        }
      } catch {
        toast.error('Failed to load investigations');
      }
    };
    fetchInvs();
  }, [selectedInvId]);

  const loadAlerts = useCallback(async () => {
    if (!selectedInvId) {
      setAlerts([]);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const res = await investigationsApi.getAlerts(selectedInvId);
      setAlerts(Array.isArray(res.data) ? res.data : []);
    } catch {
      toast.error('Failed to load detection alerts');
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, [selectedInvId]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  const handleRunAnalysis = async () => {
    if (!selectedInvId) return;
    try {
      setAnalyzing(true);
      const res = await investigationsApi.analyze(selectedInvId);
      toast.success(res.data?.message || 'Correlation engine finished analysis');
      loadAlerts();
    } catch {
      toast.error('Automated incident analysis failed');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleViewRelatedEvents = async (alert: DetectionAlert) => {
    setSelectedAlert(alert);
    setLoadingEvents(true);
    try {
      // Fetch all case events and filter by alert.event_ids
      const res = await investigationsApi.getEvents(alert.investigation_id, { page_size: 200 });
      let allEvs: Event[] = [];
      if (res.data && 'events' in res.data) {
        allEvs = res.data.events;
      } else if (Array.isArray(res.data)) {
        allEvs = res.data;
      }

      if (alert.event_ids && alert.event_ids.length > 0) {
        const matched = allEvs.filter((e) => alert.event_ids.includes(e.id));
        setRelatedEvents(matched.length > 0 ? matched : allEvs.slice(0, 10));
      } else {
        setRelatedEvents(allEvs.slice(0, 10));
      }
    } catch {
      toast.error('Failed to load related event telemetry');
      setRelatedEvents([]);
    } finally {
      setLoadingEvents(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-sky-400" />
            AUTOMATED INCIDENT ANALYSIS & CORRELATION
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            MULTI-STAGE ATTACK PATTERN DETECTION AND HEURISTIC RULE EVALUATION
          </p>
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          <div className="w-64">
            <Select
              value={selectedInvId}
              onChange={(e) => setSelectedInvId(e.target.value)}
            >
              {investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.name}
                </option>
              ))}
            </Select>
          </div>
          <Button
            variant="primary"
            loading={analyzing}
            icon={<Play className="w-4 h-4" />}
            onClick={handleRunAnalysis}
          >
            Run Threat Analysis
          </Button>
        </div>
      </div>

      {/* Alerts Stream */}
      {loading ? (
        <LoadingSpinner label="Evaluating correlation heuristics..." />
      ) : alerts.length === 0 ? (
        <EmptyState
          icon={<AlertTriangle className="w-8 h-8 text-sky-400" />}
          title="No alerts detected"
          description="No suspicious attack patterns detected for this investigation yet. Run the automated analysis engine to evaluate log telemetry."
          actionLabel="Execute Threat Correlation"
          onAction={handleRunAnalysis}
        />
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 px-1">
            <span>DETECTION HITS: {alerts.length} SUSPICIOUS BEHAVIORS</span>
            <span>ENGINE: VIGILANCE FORENSIC RULESET v1.0</span>
          </div>

          <div className="space-y-3">
            {alerts.map((alert) => (
              <div
                key={alert.id}
                className="bg-[#111827] border border-[#1e293b] rounded-lg p-5 transition-all hover:border-slate-700 space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <div className="p-2.5 rounded-lg bg-red-950/60 text-red-400 border border-red-800/80 shrink-0">
                      <AlertTriangle className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="font-bold text-slate-100 text-sm">{alert.rule_name}</h3>
                        <Badge variant={alert.severity} size="sm" label={alert.severity} />
                        <Badge variant="DEFAULT" size="sm" label={alert.alert_type} />
                      </div>
                      <p className="text-xs text-slate-300 mt-1.5 leading-relaxed max-w-3xl">
                        {alert.explanation}
                      </p>
                    </div>
                  </div>

                  <span className="text-xs font-mono text-slate-500 shrink-0">
                    {formatDate(alert.created_at)}
                  </span>
                </div>

                {/* Metadata & Actions row */}
                <div className="bg-[#0d1117] p-3 rounded-md border border-[#1e293b] flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono">
                  <div className="flex flex-wrap items-center gap-4 text-slate-400">
                    <div className="flex items-center gap-1.5">
                      <Globe className="w-3.5 h-3.5 text-slate-500" />
                      <span className="text-slate-500">IPs:</span>
                      <span className="text-cyan-400 font-semibold">
                        {alert.ip_addresses?.length ? alert.ip_addresses.join(', ') : 'N/A'}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 text-slate-500" />
                      <span className="text-slate-500">Users:</span>
                      <span className="text-emerald-400 font-semibold">
                        {alert.usernames?.length ? alert.usernames.join(', ') : 'N/A'}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5 text-slate-500" />
                      <span className="text-slate-500">Linked Events:</span>
                      <span className="text-yellow-400 font-semibold">
                        {alert.event_ids?.length ?? 0}
                      </span>
                    </div>
                  </div>

                  <Button
                    size="sm"
                    variant="outline"
                    icon={<FileSearch className="w-3.5 h-3.5" />}
                    onClick={() => handleViewRelatedEvents(alert)}
                  >
                    View Related Events
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Related Events Inspection Modal */}
      <Modal
        isOpen={!!selectedAlert}
        onClose={() => setSelectedAlert(null)}
        title={`Correlated Events: ${selectedAlert?.rule_name || ''}`}
        maxWidth="4xl"
      >
        <div className="space-y-4">
          <div className="bg-[#0d1117] p-3 rounded border border-[#1e293b] text-xs font-mono text-slate-300">
            {selectedAlert?.explanation}
          </div>

          {loadingEvents ? (
            <LoadingSpinner label="Extracting related timeline events..." />
          ) : relatedEvents.length === 0 ? (
            <div className="text-center py-6 text-xs font-mono text-slate-500">
              No matching individual event logs found.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp (UTC)</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>System</TableHead>
                  <TableHead>User / IP</TableHead>
                  <TableHead>Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {relatedEvents.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="font-mono text-xs text-sky-400 whitespace-nowrap">
                      {formatDate(e.normalized_timestamp || e.original_timestamp)}
                    </TableCell>
                    <TableCell>
                      <Badge variant={e.severity} size="sm" label={e.severity} />
                    </TableCell>
                    <TableCell className="font-mono text-xs text-slate-300">
                      {e.source_system}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-slate-300">
                      {e.username || e.source_ip || '—'}
                    </TableCell>
                    <TableCell className="text-xs text-slate-300 max-w-sm truncate">
                      {e.description}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          <div className="flex justify-end pt-2 border-t border-[#1e293b]">
            <Button variant="secondary" onClick={() => setSelectedAlert(null)}>
              Close
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default IncidentAnalysis;

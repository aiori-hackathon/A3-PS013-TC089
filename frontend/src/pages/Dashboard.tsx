import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderOpen,
  Database,
  Clock,
  AlertTriangle,
  Plus,
  Upload,
  CheckCircle2,
  FileText,
  Activity,
  ArrowRight,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { dashboardApi, investigationsApi } from '../services/api';
import type { DashboardStats } from '../types';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Modal } from '../components/ui/Modal';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';
import { HashDisplay } from '../components/ui/HashDisplay';
import { SeverityChart } from '../components/charts/SeverityChart';
import { EventsOverTime } from '../components/charts/EventsOverTime';
import { INVESTIGATION_CATEGORIES } from '../utils/constants';
import { formatDate, formatBytes } from '../utils/formatters';

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // Form state for new investigation modal
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState<string>(INVESTIGATION_CATEGORIES[0]);

  const loadStats = useCallback(async () => {
    try {
      setLoading(true);
      const res = await dashboardApi.getStats();
      setStats(res.data);
    } catch {
      // In case stats endpoint is not yet seeded, set empty default structure
      setStats({
        total_investigations: 0,
        total_evidence_files: 0,
        total_events: 0,
        parsed_ok: 0,
        parsed_failed: 0,
        integrity_verified: 0,
        suspicious_events: 0,
        recent_investigations: [],
        recent_evidence: [],
        events_by_severity: [],
        events_by_category: [],
        events_over_time: [],
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const handleCreateInvestigation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      toast.error('Investigation name is required');
      return;
    }

    try {
      setSubmitting(true);
      const res = await investigationsApi.create({
        name: name.trim(),
        description: description.trim() || undefined,
        category,
      });
      toast.success('Investigation initialized');
      setIsModalOpen(false);
      setName('');
      setDescription('');
      loadStats();
      if (res.data?.id) {
        navigate(`/investigations/${res.data.id}`);
      }
    } catch {
      toast.error('Failed to create investigation');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading && !stats) {
    return <LoadingSpinner label="Loading mission telemetry..." />;
  }

  const statCards = [
    {
      title: 'Active Cases',
      value: stats?.total_investigations ?? 0,
      icon: FolderOpen,
      color: 'text-sky-400',
      bgColor: 'bg-sky-950/40',
      borderColor: 'border-sky-800/40',
    },
    {
      title: 'Evidence Baselines',
      value: stats?.total_evidence_files ?? 0,
      icon: Database,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-950/40',
      borderColor: 'border-cyan-800/40',
    },
    {
      title: 'Parsed Events',
      value: (stats?.total_events ?? 0).toLocaleString(),
      icon: Clock,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-950/40',
      borderColor: 'border-emerald-800/40',
    },
    {
      title: 'Suspicious Telemetry',
      value: stats?.suspicious_events ?? 0,
      icon: AlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-950/40',
      borderColor: 'border-red-800/40',
    },
  ];

  const hasTelemetry =
    (stats?.total_investigations ?? 0) > 0 ||
    (stats?.total_evidence_files ?? 0) > 0 ||
    (stats?.total_events ?? 0) > 0;

  return (
    <div className="space-y-6">
      {/* Top Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <Activity className="w-5 h-5 text-sky-400" />
            FORENSIC SITUATION DASHBOARD
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            EVIDENCE INTEGRITY AND TIME-SERIES AUDIT TELEMETRY
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            icon={<Upload className="w-4 h-4" />}
            onClick={() => navigate('/ingestion')}
          >
            Upload Evidence
          </Button>
          <Button
            variant="primary"
            icon={<Plus className="w-4 h-4" />}
            onClick={() => setIsModalOpen(true)}
          >
            New Investigation
          </Button>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((card) => {
          const Icon = card.icon;
          return (
            <Card
              key={card.title}
              className="relative overflow-hidden transition-all hover:border-slate-700"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                    {card.title}
                  </p>
                  <p className="text-2xl font-bold font-mono text-slate-100 mt-1">
                    {card.value}
                  </p>
                </div>
                <div className={`p-3 rounded-lg border ${card.bgColor} ${card.borderColor} ${card.color}`}>
                  <Icon className="w-5 h-5" />
                </div>
              </div>
            </Card>
          );
        })}
      </div>

      {/* Secondary Status Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="flex items-center gap-4 py-3">
          <div className="p-2.5 rounded-md bg-emerald-950/50 text-emerald-400 border border-emerald-800/40">
            <CheckCircle2 className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs font-mono text-slate-400 uppercase">Records Parsed OK</div>
            <div className="text-lg font-bold font-mono text-emerald-400">
              {stats?.parsed_ok ?? 0}
            </div>
          </div>
        </Card>
        <Card className="flex items-center gap-4 py-3">
          <div className="p-2.5 rounded-md bg-red-950/50 text-red-400 border border-red-800/40">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs font-mono text-slate-400 uppercase">Records Failed / Corrupt</div>
            <div className="text-lg font-bold font-mono text-red-400">
              {stats?.parsed_failed ?? 0}
            </div>
          </div>
        </Card>
        <Card className="flex items-center gap-4 py-3">
          <div className="p-2.5 rounded-md bg-cyan-950/50 text-cyan-400 border border-cyan-800/40">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xs font-mono text-slate-400 uppercase">Verified Baselines</div>
            <div className="text-lg font-bold font-mono text-cyan-400">
              {stats?.integrity_verified ?? 0}
            </div>
          </div>
        </Card>
      </div>

      {/* Visual Analytics Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Log Ingestion & Event Velocity"
            subtitle="Normalized forensic events chronological frequency"
          />
          <EventsOverTime data={stats?.events_over_time || []} />
        </Card>

        <Card>
          <CardHeader
            title="Event Severity Triage"
            subtitle="Distribution across threat severity"
          />
          <SeverityChart data={stats?.events_by_severity || []} />
        </Card>
      </div>

      {/* Recent Investigations & Evidence Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Cases */}
        <Card>
          <CardHeader
            title="Recent Investigations"
            subtitle="Recently active forensic cases"
            action={
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate('/investigations')}
                icon={<ArrowRight className="w-3.5 h-3.5" />}
              >
                View All
              </Button>
            }
          />

          {!stats?.recent_investigations || stats.recent_investigations.length === 0 ? (
            <EmptyState
              icon={<FolderOpen className="w-6 h-6" />}
              title="No active investigations"
              description="Start a forensic case by creating an investigation or loading a demo scenario."
              actionLabel="Create Investigation"
              onAction={() => setIsModalOpen(true)}
            />
          ) : (
            <div className="space-y-2">
              {stats.recent_investigations.map((inv) => (
                <div
                  key={inv.id}
                  onClick={() => navigate(`/investigations/${inv.id}`)}
                  className="flex items-center justify-between p-3 rounded-md bg-[#0d1117] border border-[#1e293b] hover:border-sky-500/50 transition-colors cursor-pointer group"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded bg-[#1a2235] text-sky-400 group-hover:text-sky-300">
                      <FolderOpen className="w-4 h-4" />
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-slate-200 group-hover:text-sky-400 transition-colors">
                        {inv.name}
                      </h4>
                      <span className="text-xs font-mono text-slate-500">
                        {inv.category} • {formatDate(inv.created_at, 'yyyy-MM-dd')}
                      </span>
                    </div>
                  </div>
                  <Badge variant={inv.status} label={inv.status} size="sm" />
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Recent Evidence Baselines */}
        <Card>
          <CardHeader
            title="Recent Evidence Baselines"
            subtitle="Cryptographically sealed evidence artifacts"
            action={
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate('/evidence')}
                icon={<ArrowRight className="w-3.5 h-3.5" />}
              >
                View All
              </Button>
            }
          />

          {!stats?.recent_evidence || stats.recent_evidence.length === 0 ? (
            <EmptyState
              icon={<Database className="w-6 h-6" />}
              title="No evidence ingested"
              description="Ingest log files or network PCAPs to generate cryptographic baseline hashes."
              actionLabel="Ingest Files"
              onAction={() => navigate('/ingestion')}
            />
          ) : (
            <div className="space-y-2">
              {stats.recent_evidence.map((ev) => (
                <div
                  key={ev.id}
                  className="p-3 rounded-md bg-[#0d1117] border border-[#1e293b] space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <FileText className="w-4 h-4 text-sky-400 shrink-0" />
                      <span className="text-xs font-semibold text-slate-200 truncate max-w-[200px]">
                        {ev.original_filename}
                      </span>
                    </div>
                    <span className="text-xs font-mono text-slate-400">
                      {formatBytes(ev.file_size)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <HashDisplay hash={ev.sha256_hash} truncate />
                    <span className="text-[11px] font-mono text-slate-500">
                      {formatDate(ev.upload_timestamp, 'HH:mm:ss')}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {!hasTelemetry && (
        <Card className="border-sky-500/30 bg-sky-950/10 p-6 text-center">
          <h3 className="text-base font-semibold text-sky-400 mb-1">
            Welcome to VIGILANCE Digital Forensics Platform
          </h3>
          <p className="text-xs text-slate-400 max-w-xl mx-auto mb-4">
            Begin by loading one of the realistic attack scenarios on the Investigations page or create a blank case to ingest forensic artifacts.
          </p>
          <div className="flex justify-center gap-3">
            <Button variant="primary" onClick={() => navigate('/investigations')}>
              Browse Scenarios
            </Button>
            <Button variant="secondary" onClick={() => navigate('/ingestion')}>
              Ingest Log File
            </Button>
          </div>
        </Card>
      )}

      {/* New Investigation Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Initialize New Investigation Case"
      >
        <form onSubmit={handleCreateInvestigation} className="space-y-4">
          <Input
            label="Investigation Name"
            placeholder="e.g., INC-2026-0812-Unauthorized-Exfil"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            autoFocus
          />

          <Select
            label="Category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            options={INVESTIGATION_CATEGORIES.map((cat) => ({
              value: cat,
              label: cat,
            }))}
          />

          <div className="w-full space-y-1.5">
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
              Description / Case Notes
            </label>
            <textarea
              rows={3}
              className="w-full bg-[#0d1117] border border-[#1e293b] text-slate-200 placeholder-slate-500 rounded-md p-2.5 text-sm focus:outline-none focus:border-sky-500 font-sans"
              placeholder="Provide context regarding the alert origin, affected assets, or scope..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div className="flex justify-end gap-3 pt-3 border-t border-[#1e293b]">
            <Button
              type="button"
              variant="secondary"
              onClick={() => setIsModalOpen(false)}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={submitting}>
              Create Case
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default Dashboard;

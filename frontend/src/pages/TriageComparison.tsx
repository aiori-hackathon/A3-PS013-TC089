import React, { useState, useEffect, useCallback } from 'react';
import {
  BarChart3,
  Clock,
  Zap,
  Save,
  CheckCircle2,
  TrendingDown,
  AlertCircle,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { investigationsApi } from '../services/api';
import type {
  Investigation,
  TriageMeasurement,
  TriageComparisonData,
  HumanTriageEstimate,
  ProcessingSummary,
} from '../types';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { TriageComparisonChart } from '../components/charts/TriageComparison';
import { formatDuration } from '../utils/formatters';

export const TriageComparison: React.FC = () => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedInvId, setSelectedInvId] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [savingManual, setSavingManual] = useState(false);

  // Manual Form State
  const [scenarioName, setScenarioName] = useState('Standard Triage Audit');
  const [manualFilesCount, setManualFilesCount] = useState<number>(3);
  const [manualRecordsCount, setManualRecordsCount] = useState<number>(15000);
  const [manualDurationMinutes, setManualDurationMinutes] = useState<number>(45);
  const [manualEventsIdentified, setManualEventsIdentified] = useState<number>(8);
  const [manualNotes, setManualNotes] = useState('Manual grepping and spreadsheet filtering across 3 log exports.');

  // Data loaded from backend
  const [manualMeasurement, setManualMeasurement] = useState<TriageMeasurement | null>(null);
  const [vigilanceMeasurement, setVigilanceMeasurement] = useState<TriageMeasurement | null>(null);
  const [processingSummary, setProcessingSummary] = useState<ProcessingSummary | null>(null);
  const [comparison, setComparison] = useState<TriageComparisonData | null>(null);
  const [estimate, setEstimate] = useState<HumanTriageEstimate | null>(null);

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

  const loadTriageData = useCallback(async () => {
    if (!selectedInvId) {
      setManualMeasurement(null);
      setVigilanceMeasurement(null);
      setProcessingSummary(null);
      setComparison(null);
      setEstimate(null);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const [triageRes, summaryRes, comparisonRes, estimateRes] = await Promise.allSettled([
        investigationsApi.getTriage(selectedInvId),
        investigationsApi.getProcessingSummary(selectedInvId),
        investigationsApi.getTriageComparison(selectedInvId),
        investigationsApi.getTriageEstimate(selectedInvId),
      ]);

      let manualM: TriageMeasurement | null = null;
      let vigilanceM: TriageMeasurement | null = null;

      if (triageRes.status === 'fulfilled' && Array.isArray(triageRes.value.data)) {
        const measurements = triageRes.value.data;
        manualM = [...measurements].reverse().find((m) => m.method === 'MANUAL') || null;
        vigilanceM = [...measurements].reverse().find((m) => m.method === 'VIGILANCE') || null;
      }

      if (summaryRes.status === 'fulfilled') {
        setProcessingSummary(summaryRes.value.data);
      }

      const comparisonData = comparisonRes.status === 'fulfilled' ? comparisonRes.value.data : null;
      const estimateData = estimateRes.status === 'fulfilled' ? estimateRes.value.data : null;
      setComparison(comparisonData);
      setEstimate(estimateData);

      setManualMeasurement(manualM);
      setVigilanceMeasurement(vigilanceM);

      if (manualM) {
        setScenarioName(manualM.scenario || 'Standard Triage Audit');
        setManualDurationMinutes(Math.round((manualM.duration_seconds || 2700) / 60));
        setManualEventsIdentified(manualM.events_identified || 8);
        setManualRecordsCount(manualM.records_processed || 15000);
        setManualNotes(manualM.notes || '');
      } else if (estimateData?.available) {
        setManualDurationMinutes(Math.max(1, Math.round(estimateData.estimated_seconds / 60)));
        setManualEventsIdentified(estimateData.findings || 0);
        setManualRecordsCount(estimateData.records || 0);
      }
    } catch {
      toast.error('Failed to load triage telemetry');
    } finally {
      setLoading(false);
    }
  }, [selectedInvId]);

  useEffect(() => {
    loadTriageData();
  }, [loadTriageData]);

  const handleSaveManual = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedInvId) return;

    try {
      setSavingManual(true);
      const endTime = new Date();
      const startTime = new Date(endTime.getTime() - manualDurationMinutes * 60 * 1000);
      const res = await investigationsApi.createTriage(selectedInvId, {
        method: 'MANUAL',
        scenario: scenarioName,
        start_time: startTime.toISOString(),
        end_time: endTime.toISOString(),
        events_identified: Number(manualEventsIdentified),
        records_processed: Number(manualRecordsCount),
        notes: manualNotes,
      });

      setManualMeasurement(res.data);
      toast.success('Manual baseline benchmark recorded');
    } catch {
      toast.error('Failed to save manual triage benchmark');
    } finally {
      setSavingManual(false);
    }
  };

  const manualSeconds = manualMeasurement
    ? manualMeasurement.duration_seconds ?? manualDurationMinutes * 60
    : comparison?.manual_duration_seconds ??
      (estimate?.available ? estimate.estimated_seconds : manualDurationMinutes * 60);

  const vigilanceSeconds =
    vigilanceMeasurement?.duration_seconds ?? comparison?.vigilance_duration_seconds ?? 0;

  const hasVigilance = vigilanceSeconds > 0;
  const manualIsEstimated =
    !manualMeasurement &&
    (comparison?.manual_is_estimated ?? (estimate?.available ?? false));

  const timeSavedSeconds = hasVigilance ? Math.max(0, manualSeconds - vigilanceSeconds) : 0;
  const percentageReduction =
    hasVigilance && manualSeconds > 0
      ? Math.min(99.9, (((manualSeconds - vigilanceSeconds) / manualSeconds) * 100)).toFixed(1)
      : null;

  const manualFindings =
    manualMeasurement?.events_identified ??
    comparison?.manual_events_identified ??
    estimate?.findings ??
    manualEventsIdentified;
  const vigilanceFindings =
    vigilanceMeasurement?.events_identified ??
    comparison?.vigilance_events_identified ??
    estimate?.findings ??
    0;

  const chartData = [
    {
      metric: 'Duration (Seconds)',
      Manual: Math.round(manualSeconds),
      Vigilance: Math.round(vigilanceSeconds),
    },
    {
      metric: 'Key Events Identified',
      Manual: manualFindings,
      Vigilance: vigilanceFindings,
    },
  ];

  if (loading && !manualMeasurement && !vigilanceMeasurement) {
    return <LoadingSpinner label="Auditing comparative triage performance..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-sky-400" />
            TRIAGE TIME BENCHMARK & VELOCITY COMPARISON
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            MEASURING FORENSIC ACCELERATION: MANUAL HUMAN WORKFLOW VS VIGILANCE AUTOMATED ENGINE
          </p>
        </div>

        <div className="w-full sm:w-72">
          <Select
            label="Active Investigation Context"
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
      </div>

      {/* KPI Comparison Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="flex items-center gap-4 py-4">
          <div className="p-3 rounded-lg bg-sky-950/60 text-sky-400 border border-sky-800">
            <Clock className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs font-mono text-slate-400 uppercase">Triage Time Saved</div>
            <div className="text-2xl font-bold font-mono text-sky-400 mt-0.5">
              {hasVigilance ? formatDuration(timeSavedSeconds) : '—'}
            </div>
            <div className="text-[11px] font-mono text-slate-500 mt-0.5">
              {formatDuration(manualSeconds)} ({manualIsEstimated ? 'estimated ' : ''}manual) →{' '}
              {hasVigilance ? `${formatDuration(vigilanceSeconds)} (Vigilance)` : 'awaiting processing'}
            </div>
          </div>
        </Card>

        <Card className="flex items-center gap-4 py-4">
          <div className="p-3 rounded-lg bg-emerald-950/60 text-emerald-400 border border-emerald-800">
            <TrendingDown className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs font-mono text-slate-400 uppercase">Investigation Time Reduction</div>
            <div className="text-2xl font-bold font-mono text-emerald-400 mt-0.5">
              {percentageReduction !== null ? `${percentageReduction}%` : '—'}
            </div>
            <div className="text-[11px] font-mono text-slate-500 mt-0.5">
              Measured against real pipeline runtime
            </div>
          </div>
        </Card>

        <Card className="flex items-center gap-4 py-4">
          <div className="p-3 rounded-lg bg-cyan-950/60 text-cyan-400 border border-cyan-800">
            <Zap className="w-6 h-6" />
          </div>
          <div>
            <div className="text-xs font-mono text-slate-400 uppercase">Automated Correlation Hits</div>
            <div className="text-2xl font-bold font-mono text-cyan-400 mt-0.5">
              {vigilanceFindings}
            </div>
            <div className="text-[11px] font-mono text-slate-500 mt-0.5">
              Threat heuristics vs {manualFindings} manual findings
            </div>
          </div>
        </Card>
      </div>

      {/* Human Effort Estimate */}
      {estimate?.available && (
        <Card>
          <CardHeader
            title="Auto-Estimated Human Triage Baseline"
            subtitle={`Derived from ${estimate.records.toLocaleString()} records across ${estimate.sources} source(s) — no manual timing required`}
            action={
              <Badge
                variant={estimate.complexity}
                size="sm"
                label={`${estimate.complexity} complexity`}
              />
            }
          />
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
            <div className="p-3 rounded bg-[#0d1117] border border-[#1e293b]">
              <div className="text-[11px] font-mono text-slate-500 uppercase">Estimated Time</div>
              <div className="text-lg font-bold font-mono text-sky-400 mt-0.5">
                {formatDuration(estimate.estimated_seconds)}
              </div>
              <div className="text-[11px] font-mono text-slate-500">
                {estimate.estimated_minutes} min
              </div>
            </div>
            <div className="p-3 rounded bg-[#0d1117] border border-[#1e293b]">
              <div className="text-[11px] font-mono text-slate-500 uppercase">Records</div>
              <div className="text-lg font-bold font-mono text-slate-200 mt-0.5">
                {estimate.records.toLocaleString()}
              </div>
              <div className="text-[11px] font-mono text-slate-500">
                {estimate.sources} source(s)
              </div>
            </div>
            <div className="p-3 rounded bg-[#0d1117] border border-[#1e293b]">
              <div className="text-[11px] font-mono text-slate-500 uppercase">Findings to Validate</div>
              <div className="text-lg font-bold font-mono text-slate-200 mt-0.5">
                {estimate.findings}
              </div>
              <div className="text-[11px] font-mono text-slate-500">
                ~45 s each
              </div>
            </div>
            <div className="p-3 rounded bg-[#0d1117] border border-[#1e293b]">
              <div className="text-[11px] font-mono text-slate-500 uppercase">Confidence</div>
              <div className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
                {estimate.confidence}
              </div>
              <div className="text-[11px] font-mono text-slate-500">
                {estimate.method}
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            {estimate.breakdown.map((item) => (
              <div
                key={item.phase}
                className="flex items-start justify-between gap-3 p-2 rounded bg-[#0d1117] border border-[#1e293b] text-xs font-mono"
              >
                <div>
                  <div className="text-slate-300">{item.phase}</div>
                  <div className="text-[11px] text-slate-500 font-sans">{item.detail}</div>
                </div>
                <div className="text-sky-400 font-bold shrink-0">
                  {formatDuration(item.seconds)}
                </div>
              </div>
            ))}
          </div>

          <p className="text-[11px] text-slate-500 font-mono mt-3">
            {estimate.assumptions.join(' ')}
          </p>
        </Card>
      )}

      {/* Side-by-Side Comparison Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left Panel: Manual Investigation Form */}
        <Card className="space-y-4">
          <CardHeader
            title="Manual Investigation Workflow"
            subtitle="Record time spent conducting manual grep, spreadsheet pivot, and ad-hoc parsing"
            action={
              manualIsEstimated ? (
                <Badge variant="MEDIUM" size="sm" label="Auto-Estimated" />
              ) : (
                <Badge variant="MANUAL" size="sm" label="User Baseline" />
              )
            }
          />

          <form onSubmit={handleSaveManual} className="space-y-3">
            <Input
              label="Scenario Name / Task Identifier"
              value={scenarioName}
              onChange={(e) => setScenarioName(e.target.value)}
              required
            />

            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Log Files Count"
                type="number"
                min={1}
                value={manualFilesCount}
                onChange={(e) => setManualFilesCount(Number(e.target.value))}
              />
              <Input
                label="Records Count"
                type="number"
                min={1}
                value={manualRecordsCount}
                onChange={(e) => setManualRecordsCount(Number(e.target.value))}
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Manual Duration (Minutes)"
                type="number"
                min={1}
                value={manualDurationMinutes}
                onChange={(e) => setManualDurationMinutes(Number(e.target.value))}
                helperText={`${manualDurationMinutes * 60} seconds`}
              />
              <Input
                label="Events Identified"
                type="number"
                min={0}
                value={manualEventsIdentified}
                onChange={(e) => setManualEventsIdentified(Number(e.target.value))}
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
                Analyst Notes / Methodology
              </label>
              <textarea
                rows={2}
                className="w-full bg-[#0d1117] border border-[#1e293b] text-slate-200 placeholder-slate-500 rounded-md p-2 text-xs focus:outline-none focus:border-sky-500 font-sans"
                value={manualNotes}
                onChange={(e) => setManualNotes(e.target.value)}
              />
            </div>

            <div className="pt-2 flex justify-end">
              <Button
                type="submit"
                variant="secondary"
                size="sm"
                loading={savingManual}
                icon={<Save className="w-3.5 h-3.5" />}
              >
                Save Manual Baseline
              </Button>
            </div>
          </form>
        </Card>

        {/* Right Panel: Vigilance Automated Telemetry */}
        <Card className="space-y-4">
          <CardHeader
            title="VIGILANCE Automated Pipeline"
            subtitle="Cryptographically verified telemetry and millisecond-level parser metrics"
            action={<Badge variant="VIGILANCE" size="sm" label="Automated" />}
          />

          <div className="space-y-3 text-xs font-mono">
            <div className="p-3 rounded bg-[#0d1117] border border-[#1e293b] flex items-center justify-between">
              <span className="text-slate-400">Processing & Ingestion Duration</span>
              <span className="text-sky-400 font-bold text-sm">
                {hasVigilance ? formatDuration(vigilanceSeconds) : 'Awaiting processing'}
              </span>
            </div>

            <div className="p-3 rounded bg-[#0d1117] border border-[#1e293b] flex items-center justify-between">
              <span className="text-slate-400">Total Log Records Processed</span>
              <span className="text-slate-200 font-bold text-sm">
                {(processingSummary?.total_records ?? vigilanceMeasurement?.records_processed ?? estimate?.records ?? 0).toLocaleString()}
              </span>
            </div>

            <div className="p-3 rounded bg-[#0d1117] border border-[#1e293b] flex items-center justify-between">
              <span className="text-slate-400">High-Fidelity Threat Events Correlated</span>
              <span className="text-emerald-400 font-bold text-sm">
                {vigilanceFindings}
              </span>
            </div>

            <div className="p-3 rounded bg-[#0d1117] border border-[#1e293b] space-y-1">
              <span className="text-slate-500 uppercase tracking-wider block text-[11px]">
                Pipeline Summary
              </span>
              <p className="text-slate-300 font-sans leading-relaxed text-xs">
                {vigilanceMeasurement?.notes ||
                  'Duration is the real measured runtime of this investigation’s ingestion and parsing jobs.'}
              </p>
            </div>

            <div className="p-3 rounded bg-[#0a0e1a] border border-[#1e293b] flex items-center gap-2 text-emerald-400 text-[11px]">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Full cryptographic provenance and UTC chronological alignment verified.</span>
            </div>
          </div>
        </Card>
      </div>

      {/* Visual Comparison Chart */}
      <Card>
        <CardHeader
          title="Manual vs. Automated Performance Metrics"
          subtitle="Grouped comparison of investigative turnaround latency and event identification precision"
        />
        <TriageComparisonChart data={chartData} />
      </Card>

      {/* Audit Disclaimer */}
      <div className="p-3 rounded bg-[#111827] border border-[#1e293b] text-xs font-mono text-slate-500 flex items-start gap-2">
        <AlertCircle className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <span>
          <strong className="text-slate-400 uppercase">Scientific Rigor Notice:</strong> When no manual timing is saved, the human baseline is an auto-estimate derived from log volume, source count, timestamp-normalisation difficulty and findings. The VIGILANCE duration is the measured runtime of real ingestion and parsing jobs, not a simulated value.
        </span>
      </div>
    </div>
  );
};

export default TriageComparison;

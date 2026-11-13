import React, { useState, useEffect, useCallback } from 'react';
import {
  FileText,
  Download,
  FileSpreadsheet,
  FileCode,
  Sparkles,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { investigationsApi, getBackendRootUrl } from '../services/api';
import type { Investigation, ReportItem } from '../types';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table';
import { formatBytes, formatDate } from '../utils/formatters';

export const Reports: React.FC = () => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedInvId, setSelectedInvId] = useState<string>('');
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFormat, setSelectedFormat] = useState<'PDF' | 'CSV' | 'JSON'>('PDF');
  const [generating, setGenerating] = useState(false);

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

  const loadReports = useCallback(async () => {
    if (!selectedInvId) {
      setReports([]);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const res = await investigationsApi.getReports(selectedInvId);
      setReports(Array.isArray(res.data) ? res.data : []);
    } catch {
      toast.error('Failed to load reports for investigation');
      setReports([]);
    } finally {
      setLoading(false);
    }
  }, [selectedInvId]);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const handleGenerate = async () => {
    if (!selectedInvId) return;
    try {
      setGenerating(true);
      const res = await investigationsApi.generateReport(selectedInvId, selectedFormat.toLowerCase());
      toast.success(`${selectedFormat} forensic report created`);
      if (res.data) {
        setReports((prev) => [res.data, ...prev]);
      }
      loadReports();
    } catch {
      toast.error(`Failed to generate ${selectedFormat} report`);
    } finally {
      setGenerating(false);
    }
  };

  const activeInvestigation = investigations.find((i) => i.id === selectedInvId);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-sky-400" />
            FORENSIC REPORT GENERATION & EXPORT
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            CERTIFIED INCIDENT BRIEFS, BITSTREAM MANIFESTS, AND DATA NORMALIZATION EXPORTS
          </p>
        </div>

        <div className="w-full sm:w-72">
          <Select
            label="Target Investigation Case"
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

      {/* Report Generator Controls */}
      <Card>
        <CardHeader
          title="Export Investigation Case Package"
          subtitle="Produces court-ready digital forensic manifests with cryptographic baseline hashes"
        />

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 items-end">
          <div className="sm:col-span-2">
            <Select
              label="Select Output Format"
              value={selectedFormat}
              onChange={(e) => setSelectedFormat(e.target.value as 'PDF' | 'CSV' | 'JSON')}
            >
              <option value="PDF">Executive Briefing & Forensic Chronology (PDF)</option>
              <option value="CSV">Normalized Time-Series Event Telemetry (CSV)</option>
              <option value="JSON">Structured Attack Correlation & Evidence Manifest (JSON)</option>
            </Select>
          </div>

          <Button
            variant="primary"
            loading={generating}
            icon={<Sparkles className="w-4 h-4" />}
            onClick={handleGenerate}
            className="w-full justify-center"
          >
            Generate {selectedFormat} Report
          </Button>
        </div>

        {activeInvestigation && (
          <div className="mt-4 p-3 rounded bg-[#0d1117] border border-[#1e293b] flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-400">
            <span>
              BOUND CASE: <strong className="text-slate-200">{activeInvestigation.name}</strong>
            </span>
            <span>CATEGORY: {activeInvestigation.category}</span>
            <span>STATUS: {activeInvestigation.status}</span>
          </div>
        )}
      </Card>

      {/* Generated Reports List */}
      <Card className="p-0 overflow-hidden">
        <div className="p-4 border-b border-[#1e293b]">
          <h3 className="text-sm font-semibold font-mono text-slate-300 uppercase">
            Generated Reports Archive ({reports.length})
          </h3>
        </div>

        {loading ? (
          <LoadingSpinner label="Auditing generated reports..." />
        ) : reports.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No reports generated yet for this investigation. Choose a format above to compile an export.
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Report Artifact</TableHead>
                <TableHead>Format</TableHead>
                <TableHead>Artifact Size</TableHead>
                <TableHead>Generated At</TableHead>
                <TableHead className="text-right">Download</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {reports.map((rep, idx) => {
                const isPdf = rep.format?.toUpperCase() === 'PDF';
                const isCsv = rep.format?.toUpperCase() === 'CSV';

                return (
                  <TableRow key={rep.id || idx}>
                    <TableCell>
                      <div className="flex items-center gap-2 font-mono text-xs text-slate-200">
                        {isPdf ? (
                          <FileText className="w-4 h-4 text-red-400 shrink-0" />
                        ) : isCsv ? (
                          <FileSpreadsheet className="w-4 h-4 text-emerald-400 shrink-0" />
                        ) : (
                          <FileCode className="w-4 h-4 text-sky-400 shrink-0" />
                        )}
                        <span className="font-semibold">{rep.filename}</span>
                      </div>
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
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono bg-[#1a2235] text-sky-400 hover:bg-[#243049] border border-[#1e293b] transition-colors"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Download
                      </a>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>
    </div>
  );
};

export default Reports;

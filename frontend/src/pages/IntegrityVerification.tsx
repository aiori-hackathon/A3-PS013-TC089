import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  CheckCircle,
  XCircle,
  AlertTriangle,
  HardDrive,
  RefreshCw,
  FileCode,
  Bug,
  RotateCcw,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { investigationsApi, evidenceApi, demoApi } from '../services/api';
import type { Investigation, EvidenceFile, IntegrityVerification as VerificationType } from '../types';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table';
import { HashDisplay } from '../components/ui/HashDisplay';
import { formatBytes, formatDate } from '../utils/formatters';

export const IntegrityVerificationPage: React.FC = () => {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedInvId, setSelectedInvId] = useState<string>('');
  const [evidenceList, setEvidenceList] = useState<EvidenceFile[]>([]);
  const [loading, setLoading] = useState(true);

  // Active verification execution
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [activeResult, setActiveResult] = useState<VerificationType | null>(null);
  const [activeFile, setActiveFile] = useState<EvidenceFile | null>(null);

  // Verification history
  const [history, setHistory] = useState<VerificationType[]>([]);

  // Demo-only tamper simulation controls
  const [demoMode, setDemoMode] = useState(false);
  const [demoBusy, setDemoBusy] = useState<string | null>(null);

  useEffect(() => {
    demoApi
      .status()
      .then((res) => setDemoMode(Boolean(res.data?.demo_mode)))
      .catch(() => setDemoMode(false));
  }, []);

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

  const loadEvidence = useCallback(async () => {
    if (!selectedInvId) {
      setEvidenceList([]);
      setHistory([]);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const res = await investigationsApi.getEvidence(selectedInvId);
      const evs = Array.isArray(res.data) ? res.data : [];
      setEvidenceList(evs);

      // Load verification history across every evidence file in the case
      if (evs.length > 0) {
        const histResults = await Promise.allSettled(
          evs.map((ev) => evidenceApi.getVerifications(ev.id))
        );
        const combined = histResults.flatMap((result) =>
          result.status === 'fulfilled' && Array.isArray(result.value.data)
            ? result.value.data
            : []
        );
        combined.sort(
          (a, b) => new Date(b.verified_at).getTime() - new Date(a.verified_at).getTime()
        );
        setHistory(combined);
      } else {
        setHistory([]);
      }
    } catch {
      toast.error('Failed to load evidence files for case');
      setEvidenceList([]);
      setHistory([]);
    } finally {
      setLoading(false);
    }
  }, [selectedInvId]);

  useEffect(() => {
    loadEvidence();
  }, [loadEvidence]);

  const handleVerify = async (ev: EvidenceFile) => {
    try {
      setVerifyingId(ev.id);
      setActiveFile(ev);
      const res = await evidenceApi.verify(ev.id);
      setActiveResult(res.data);

      if (res.data?.result === 'MATCH') {
        toast.success(`Integrity MATCH for ${ev.original_filename}`);
      } else if (res.data?.result === 'MISMATCH') {
        toast.error(`ALERT: SHA-256 hash MISMATCH for ${ev.original_filename}!`);
      }

      // Add to running history list
      if (res.data) {
        setHistory((prev) => [res.data, ...prev]);
      }
    } catch {
      toast.error('Verification failed to execute');
    } finally {
      setVerifyingId(null);
    }
  };

  const handleDemoTamper = async (ev: EvidenceFile) => {
    setDemoBusy(`${ev.id}:tamper`);
    try {
      await evidenceApi.demoTamper(ev.id);
      toast('Demo tamper applied to the stored artifact', { icon: '!' });
      await handleVerify(ev);
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      toast.error(detail || 'Demo tamper unavailable');
    } finally {
      setDemoBusy(null);
    }
  };

  const handleDemoRestore = async (ev: EvidenceFile) => {
    setDemoBusy(`${ev.id}:restore`);
    try {
      await evidenceApi.demoRestore(ev.id);
      toast.success('Original artifact restored from demo backup');
      await handleVerify(ev);
    } catch (err) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      toast.error(detail || 'Demo restore unavailable');
    } finally {
      setDemoBusy(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-sky-400" />
            CRYPTOGRAPHIC INTEGRITY & CHAIN OF CUSTODY
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            RECALCULATE AND COMPARE SHA-256 BASES TO DETECT EVIDENCE TAMPERING
          </p>
        </div>

        <div className="w-full sm:w-72">
          <Select
            label="Target Investigation Case"
            value={selectedInvId}
            onChange={(e) => {
              setSelectedInvId(e.target.value);
              setActiveResult(null);
            }}
          >
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.name}
              </option>
            ))}
          </Select>
        </div>
      </div>

      {/* Verification Result Panel if available */}
      {activeResult && activeFile && (
        <Card glow className="border-sky-500/50 bg-[#0d1527] space-y-4">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              {activeResult.result === 'MATCH' ? (
                <div className="p-3 rounded-full bg-emerald-950/80 border border-emerald-800 text-emerald-400">
                  <CheckCircle className="w-8 h-8" />
                </div>
              ) : activeResult.result === 'MISMATCH' ? (
                <div className="p-3 rounded-full bg-red-950/80 border border-red-800 text-red-400">
                  <XCircle className="w-8 h-8" />
                </div>
              ) : (
                <div className="p-3 rounded-full bg-yellow-950/80 border border-yellow-800 text-yellow-400">
                  <AlertTriangle className="w-8 h-8" />
                </div>
              )}
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-slate-100 uppercase tracking-wide">
                    INTEGRITY VERIFICATION RESULT:
                  </h3>
                  <Badge variant={activeResult.result} label={activeResult.result} size="md" />
                </div>
                <p className="text-xs text-slate-300 mt-0.5 font-mono">
                  ARTIFACT: {activeFile.original_filename} ({formatBytes(activeFile.file_size)})
                </p>
              </div>
            </div>

            <span className="text-xs font-mono text-slate-400">
              Verified: {formatDate(activeResult.verified_at)}
            </span>
          </div>

          <div className="space-y-3 bg-[#0a0e1a] p-4 rounded-md border border-[#1e293b] font-mono text-xs">
            <div>
              <span className="text-slate-500 uppercase block mb-1">
                Baseline SHA-256 (Sealed at Ingestion):
              </span>
              <span className="text-sky-400 font-bold select-all block break-all">
                {activeResult.original_hash}
              </span>
            </div>
            <div>
              <span className="text-slate-500 uppercase block mb-1">
                Recalculated SHA-256 (Current Bitstream):
              </span>
              <span
                className={`font-bold select-all block break-all ${
                  activeResult.result === 'MATCH' ? 'text-emerald-400' : 'text-red-400'
                }`}
              >
                {activeResult.recalculated_hash}
              </span>
            </div>
          </div>

          <div className="p-3 rounded bg-[#111827] border border-[#1e293b] text-xs font-mono text-slate-400 leading-relaxed">
            <span className="text-sky-400 font-bold block mb-0.5">LEGAL / FORENSIC DISCLAIMER:</span>
            A matching hash indicates the file has not been modified since baseline recording. It does not verify authenticity prior to collection.
          </div>
        </Card>
      )}

      {/* Evidence Files List */}
      <Card className="space-y-4">
        <CardHeader
          title="Case Evidence Baselines"
          subtitle="Cryptographically sealed artifacts available for integrity validation"
        />

        {loading ? (
          <LoadingSpinner label="Auditing case baselines..." />
        ) : evidenceList.length === 0 ? (
          <EmptyState
            icon={<FileCode className="w-8 h-8" />}
            title="No evidence files bound to case"
            description="Ingest log files into this case to record initial baseline hashes."
          />
        ) : (
          <div className="space-y-3">
            {evidenceList.map((ev) => (
              <div
                key={ev.id}
                className="bg-[#0d1117] border border-[#1e293b] rounded-lg p-4 transition-all hover:border-slate-700 space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <HardDrive className="w-4 h-4 text-sky-400" />
                      <span className="font-semibold text-sm text-slate-200">
                        {ev.original_filename}
                      </span>
                      <Badge variant="INFO" size="sm" label={ev.file_format || 'FILE'} />
                    </div>
                    <div className="flex items-center gap-4 text-xs font-mono text-slate-400 mt-1">
                      <span>Size: {formatBytes(ev.file_size)}</span>
                      <span>System: {ev.source_system}</span>
                      <span>Uploaded: {formatDate(ev.upload_timestamp)}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    {demoMode && (
                      <>
                        <Button
                          size="sm"
                          variant="danger"
                          loading={demoBusy === `${ev.id}:tamper`}
                          icon={<Bug className="w-3.5 h-3.5" />}
                          onClick={() => handleDemoTamper(ev)}
                        >
                          Tamper (demo)
                        </Button>
                        <Button
                          size="sm"
                          variant="secondary"
                          loading={demoBusy === `${ev.id}:restore`}
                          icon={<RotateCcw className="w-3.5 h-3.5" />}
                          onClick={() => handleDemoRestore(ev)}
                        >
                          Restore (demo)
                        </Button>
                      </>
                    )}
                    <Button
                      size="sm"
                      variant="outline"
                      loading={verifyingId === ev.id}
                      icon={<RefreshCw className="w-3.5 h-3.5 text-sky-400" />}
                      onClick={() => handleVerify(ev)}
                    >
                      Recalculate &amp; Verify
                    </Button>
                  </div>
                </div>

                <div className="bg-[#111827] p-2.5 rounded border border-[#1e293b] font-mono text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 overflow-hidden">
                    <span className="text-slate-500 uppercase text-[11px] shrink-0">
                      Baseline Hash:
                    </span>
                    <HashDisplay hash={ev.sha256_hash} />
                  </div>
                  <span className="text-[11px] text-slate-500 shrink-0">
                    STATUS: {ev.processing_status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Verification History Table */}
      {history.length > 0 && (
        <Card className="p-0 overflow-hidden">
          <div className="p-4 border-b border-[#1e293b]">
            <h3 className="text-sm font-semibold font-mono text-slate-300 uppercase">
              Recent Integrity Verifications ({history.length})
            </h3>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Verified Timestamp</TableHead>
                <TableHead>Baseline Hash</TableHead>
                <TableHead>Recalculated Hash</TableHead>
                <TableHead>Result</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {history.map((h, i) => (
                <TableRow key={h.id || i}>
                  <TableCell className="font-mono text-xs text-slate-400">
                    {formatDate(h.verified_at)}
                  </TableCell>
                  <TableCell>
                    <HashDisplay hash={h.original_hash} truncate />
                  </TableCell>
                  <TableCell>
                    <HashDisplay hash={h.recalculated_hash} truncate />
                  </TableCell>
                  <TableCell>
                    <Badge variant={h.result} size="sm" label={h.result} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </div>
  );
};

export default IntegrityVerificationPage;

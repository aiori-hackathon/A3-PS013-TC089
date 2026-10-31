import React, { useState, useEffect, useCallback } from 'react';
import {
  Database,
  Search,
  ShieldCheck,
  Download,
  CheckCircle,
  XCircle,
  AlertCircle,
  HardDrive,
  Calendar,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { evidenceApi, investigationsApi } from '../services/api';
import type { EvidenceFile, Investigation, IntegrityVerification } from '../types';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Modal } from '../components/ui/Modal';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table';
import { HashDisplay } from '../components/ui/HashDisplay';
import { formatBytes, formatDate } from '../utils/formatters';

export const EvidenceManagement: React.FC = () => {
  const [evidenceList, setEvidenceList] = useState<EvidenceFile[]>([]);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');

  // Verification state
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<IntegrityVerification | null>(null);
  const [verificationFile, setVerificationFile] = useState<EvidenceFile | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [evRes, invRes] = await Promise.allSettled([
        evidenceApi.listAll(),
        investigationsApi.list(),
      ]);

      if (evRes.status === 'fulfilled') {
        setEvidenceList(Array.isArray(evRes.value.data) ? evRes.value.data : []);
      } else {
        // If listAll fails or isn't populated, try fetching evidence for all investigations
        if (invRes.status === 'fulfilled' && Array.isArray(invRes.value.data)) {
          const invList = invRes.value.data;
          setInvestigations(invList);
          const allEvPromises = invList.map((i) => investigationsApi.getEvidence(i.id));
          const allEvResults = await Promise.allSettled(allEvPromises);
          const combined: EvidenceFile[] = [];
          allEvResults.forEach((r) => {
            if (r.status === 'fulfilled' && Array.isArray(r.value.data)) {
              combined.push(...r.value.data);
            }
          });
          setEvidenceList(combined);
          return;
        }
      }

      if (invRes.status === 'fulfilled') {
        setInvestigations(Array.isArray(invRes.value.data) ? invRes.value.data : []);
      }
    } catch {
      toast.error('Failed to load evidence repository');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleVerify = async (ev: EvidenceFile) => {
    try {
      setVerifyingId(ev.id);
      setVerificationFile(ev);
      const res = await evidenceApi.verify(ev.id);
      setVerificationResult(res.data);
      if (res.data?.result === 'MATCH') {
        toast.success('SHA-256 baseline MATCH confirmed!');
      } else if (res.data?.result === 'MISMATCH') {
        toast.error('CRITICAL: Evidence hash MISMATCH detected!');
      }
    } catch {
      toast.error('Verification query failed');
    } finally {
      setVerifyingId(null);
    }
  };

  const filteredEvidence = evidenceList.filter((ev) => {
    const matchesInv =
      selectedInvestigationId === 'ALL' || ev.investigation_id === selectedInvestigationId;
    const matchesSearch =
      ev.original_filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.sha256_hash.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ev.source_system.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus =
      selectedStatus === 'ALL' || ev.processing_status.toUpperCase() === selectedStatus.toUpperCase();
    return matchesInv && matchesSearch && matchesStatus;
  });

  const getInvestigationName = (invId: string) => {
    const inv = investigations.find((i) => i.id === invId);
    return inv ? inv.name : invId.slice(0, 8);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <Database className="w-5 h-5 text-sky-400" />
            CROSS-INVESTIGATION EVIDENCE REPOSITORY
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            CRYPTOGRAPHIC BASES, SHA-256 HASH VERIFICATION, AND CHAIN-OF-CUSTODY AUDIT
          </p>
        </div>
      </div>

      {/* Filter Toolbar */}
      <Card className="py-3 px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-center">
          <div className="md:col-span-2">
            <Input
              icon={<Search className="w-4 h-4" />}
              placeholder="Search filename, SHA-256 hash, or source system..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <div>
            <Select
              value={selectedInvestigationId}
              onChange={(e) => setSelectedInvestigationId(e.target.value)}
            >
              <option value="ALL">All Investigations</option>
              {investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.name}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
            >
              <option value="ALL">All Ingestion Statuses</option>
              <option value="PARSED">PARSED</option>
              <option value="PENDING">PENDING</option>
              <option value="FAILED">FAILED</option>
            </Select>
          </div>
        </div>
      </Card>

      {/* Evidence Table */}
      {loading ? (
        <LoadingSpinner label="Auditing evidence records..." />
      ) : filteredEvidence.length === 0 ? (
        <EmptyState
          icon={<Database className="w-8 h-8" />}
          title="No evidence files found"
          description={
            searchTerm || selectedInvestigationId !== 'ALL'
              ? 'No evidence records match your search criteria.'
              : 'No log or PCAP files have been ingested yet.'
          }
        />
      ) : (
        <Card className="p-0 overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>File Artifact & Case</TableHead>
                <TableHead>Source Context</TableHead>
                <TableHead>SHA-256 Baseline</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Ingestion Date</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Verification</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredEvidence.map((ev) => (
                <TableRow key={ev.id}>
                  <TableCell>
                    <div>
                      <div className="font-semibold text-slate-100 flex items-center gap-1.5">
                        <HardDrive className="w-3.5 h-3.5 text-sky-400" />
                        <span>{ev.original_filename}</span>
                      </div>
                      <span className="text-xs font-mono text-slate-500">
                        Case: {getInvestigationName(ev.investigation_id)}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="text-xs font-mono text-slate-300">
                      <div>{ev.source_system}</div>
                      <span className="text-slate-500">{ev.source_category}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <HashDisplay hash={ev.sha256_hash} truncate />
                  </TableCell>
                  <TableCell className="font-mono text-xs text-slate-300">
                    {formatBytes(ev.file_size)}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-slate-400">
                    <span className="flex items-center gap-1">
                      <Calendar className="w-3.5 h-3.5 text-slate-500" />
                      {formatDate(ev.upload_timestamp, 'yyyy-MM-dd HH:mm')}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={ev.processing_status}
                      size="sm"
                      label={ev.processing_status}
                    />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="inline-flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        loading={verifyingId === ev.id}
                        icon={<ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />}
                        onClick={() => handleVerify(ev)}
                      >
                        Verify
                      </Button>
                      <a
                        href={evidenceApi.download(ev.id)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-[#1a2235] transition-colors"
                        title="Download Evidence"
                      >
                        <Download className="w-4 h-4" />
                      </a>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Verification Result Modal */}
      <Modal
        isOpen={!!verificationResult}
        onClose={() => setVerificationResult(null)}
        title="Evidence Baseline Cryptographic Verification"
        maxWidth="lg"
      >
        {verificationResult && (
          <div className="space-y-4">
            <div
              className={`p-4 rounded-lg border flex items-center gap-3 ${
                verificationResult.result === 'MATCH'
                  ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                  : verificationResult.result === 'MISMATCH'
                  ? 'bg-red-950/40 border-red-800 text-red-300'
                  : 'bg-yellow-950/40 border-yellow-800 text-yellow-300'
              }`}
            >
              {verificationResult.result === 'MATCH' ? (
                <CheckCircle className="w-6 h-6 text-emerald-400 shrink-0" />
              ) : verificationResult.result === 'MISMATCH' ? (
                <XCircle className="w-6 h-6 text-red-400 shrink-0" />
              ) : (
                <AlertCircle className="w-6 h-6 text-yellow-400 shrink-0" />
              )}
              <div>
                <h4 className="font-bold text-sm uppercase tracking-wide">
                  INTEGRITY STATUS: {verificationResult.result}
                </h4>
                <p className="text-xs opacity-90 mt-0.5">
                  {verificationResult.result === 'MATCH'
                    ? 'The recalculated SHA-256 checksum exactly matches the recorded baseline hash. Artifact is intact.'
                    : verificationResult.result === 'MISMATCH'
                    ? 'WARNING: The file hash differs from the baseline. Data tampering or bit corruption may have occurred.'
                    : 'Verification query could not complete hash calculation.'}
                </p>
              </div>
            </div>

            <div className="space-y-3 bg-[#0d1117] p-3 rounded border border-[#1e293b] font-mono text-xs">
              {verificationFile && (
                <div>
                  <span className="text-slate-500 uppercase block mb-0.5">Artifact:</span>
                  <span className="text-slate-200 font-bold">{verificationFile.original_filename}</span>
                </div>
              )}
              <div>
                <span className="text-slate-500 uppercase block mb-0.5">Original Baseline Hash:</span>
                <span className="text-sky-400 break-all">{verificationResult.original_hash}</span>
              </div>
              <div>
                <span className="text-slate-500 uppercase block mb-0.5">Recalculated Hash:</span>
                <span
                  className={`break-all ${
                    verificationResult.result === 'MATCH' ? 'text-emerald-400' : 'text-red-400'
                  }`}
                >
                  {verificationResult.recalculated_hash}
                </span>
              </div>
              <div>
                <span className="text-slate-500 uppercase block mb-0.5">Verified At:</span>
                <span className="text-slate-400">{formatDate(verificationResult.verified_at)}</span>
              </div>
            </div>

            <div className="text-[11px] font-mono text-slate-500 leading-relaxed bg-[#0a0e1a] p-2.5 rounded border border-[#1e293b]">
              NOTE: A matching hash confirms the file contents match the baseline stored when first collected. It does not verify host authenticity prior to initial collection.
            </div>

            <div className="flex justify-end pt-2 border-t border-[#1e293b]">
              <Button variant="secondary" onClick={() => setVerificationResult(null)}>
                Dismiss
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default EvidenceManagement;

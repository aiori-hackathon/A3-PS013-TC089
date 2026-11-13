import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Upload,
  Plus,
  FileCode,
  CheckCircle2,
  HardDrive,
  X,
  ArrowRight,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { investigationsApi, evidenceApi } from '../services/api';
import type { Investigation, EvidenceUploadSummary } from '../types';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { HashDisplay } from '../components/ui/HashDisplay';
import { SOURCE_CATEGORIES, INVESTIGATION_CATEGORIES } from '../utils/constants';
import { formatBytes } from '../utils/formatters';

interface QueuedFile {
  file: File;
  sourceSystem: string;
  sourceCategory: string;
  timezoneHint: string;
  progress: number;
  status: 'idle' | 'uploading' | 'completed' | 'error';
  result?: EvidenceUploadSummary;
  errorMessage?: string;
}

export const LogIngestion: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedInvId, setSelectedInvId] = useState<string>('');
  const [isCreatingNewInv, setIsCreatingNewInv] = useState(false);
  const [newInvName, setNewInvName] = useState('');
  const [newInvCategory, setNewInvCategory] = useState<string>(INVESTIGATION_CATEGORIES[0]);

  // Queue of files to upload
  const [queuedFiles, setQueuedFiles] = useState<QueuedFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const fetchInvs = async () => {
      try {
        const res = await investigationsApi.list();
        const list = Array.isArray(res.data) ? res.data : [];
        setInvestigations(list);

        const paramId = searchParams.get('investigation_id');
        if (paramId && list.some((i) => i.id === paramId)) {
          setSelectedInvId(paramId);
        } else if (list.length > 0 && !selectedInvId) {
          setSelectedInvId(list[0].id);
        }
      } catch {
        toast.error('Failed to load active investigations');
      }
    };
    fetchInvs();
  }, [searchParams, selectedInvId]);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      appendFiles(Array.from(e.dataTransfer.files));
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      appendFiles(Array.from(e.target.files));
    }
  };

  const appendFiles = (files: File[]) => {
    const newItems: QueuedFile[] = files.map((file) => {
      const lowerName = file.name.toLowerCase();
      let defaultCategory: string = SOURCE_CATEGORIES[0];
      if (lowerName.includes('firewall') || lowerName.includes('palo') || lowerName.includes('fw')) {
        defaultCategory = 'Firewall / Perimeter';
      } else if (lowerName.includes('auth') || lowerName.includes('login') || lowerName.includes('security')) {
        defaultCategory = 'Authentication / IAM';
      } else if (lowerName.includes('access') || lowerName.includes('nginx') || lowerName.includes('apache')) {
        defaultCategory = 'Web Server / Application';
      } else if (lowerName.includes('sysmon') || lowerName.includes('win') || lowerName.includes('evtx')) {
        defaultCategory = 'Endpoint / OS';
      }

      return {
        file,
        sourceSystem: 'ENDPOINT-PRIMARY',
        sourceCategory: defaultCategory,
        timezoneHint: 'UTC',
        progress: 0,
        status: 'idle',
      };
    });

    setQueuedFiles((prev) => [...prev, ...newItems]);
  };

  const removeQueuedFile = (index: number) => {
    setQueuedFiles((prev) => prev.filter((_, idx) => idx !== index));
  };

  const updateQueuedFile = (index: number, updates: Partial<QueuedFile>) => {
    setQueuedFiles((prev) =>
      prev.map((item, idx) => (idx === index ? { ...item, ...updates } : item))
    );
  };

  const handleUploadAll = async () => {
    let targetInvId = selectedInvId;

    if (isCreatingNewInv) {
      if (!newInvName.trim()) {
        toast.error('Investigation name is required');
        return;
      }
      try {
        const createRes = await investigationsApi.create({
          name: newInvName.trim(),
          category: newInvCategory,
        });
        targetInvId = createRes.data.id;
        setSelectedInvId(targetInvId);
        setIsCreatingNewInv(false);
        window.dispatchEvent(new Event('vigilance_investigations_changed'));
      } catch {
        toast.error('Failed to create new investigation for upload');
        return;
      }
    }

    if (!targetInvId) {
      toast.error('Please select or create an investigation first');
      return;
    }

    if (queuedFiles.length === 0) {
      toast.error('No files queued for ingestion');
      return;
    }

    setIsUploading(true);

    for (const [i, item] of queuedFiles.entries()) {
      if (item.status === 'completed') continue;

      updateQueuedFile(i, { status: 'uploading', progress: 10 });

      const formData = new FormData();
      formData.append('files', item.file);
      formData.append('investigation_id', targetInvId);
      formData.append('source_system', item.sourceSystem);
      formData.append('source_category', item.sourceCategory);
      if (item.timezoneHint) {
        formData.append('timezone_hint', item.timezoneHint);
      }

      try {
        const res = await evidenceApi.upload(formData, (progressEvent) => {
          if (progressEvent.total) {
            const pct = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            updateQueuedFile(i, { progress: Math.max(10, Math.min(95, pct)) });
          }
        });

        const uploaded = Array.isArray(res.data) ? res.data[0] : res.data;
        updateQueuedFile(i, {
          status: 'completed',
          progress: 100,
          result: uploaded,
        });
        toast.success(`Ingested & parsed: ${item.file.name}`);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Upload failed';
        updateQueuedFile(i, {
          status: 'error',
          errorMessage: msg,
        });
        toast.error(`Failed to ingest ${item.file.name}`);
      }
    }

    setIsUploading(false);
  };

  const completedCount = queuedFiles.filter((f) => f.status === 'completed').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <Upload className="w-5 h-5 text-sky-400" />
            FORENSIC LOG INGESTION ENGINE
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            AUTOMATIC HASH BASELINING, NORMALIZATION, AND TIME-SERIES PARSING
          </p>
        </div>
      </div>

      {/* Step 1: Target Investigation Context */}
      <Card>
        <CardHeader
          title="Step 1: Select Target Investigation Case"
          subtitle="All baseline hashes and normalized events will be bound to this case"
        />

        {!isCreatingNewInv ? (
          <div className="flex flex-col sm:flex-row items-end gap-4">
            <div className="flex-1">
              <Select
                label="Target Case"
                value={selectedInvId}
                onChange={(e) => setSelectedInvId(e.target.value)}
              >
                {investigations.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    [{inv.category.toUpperCase()}] {inv.name}
                  </option>
                ))}
              </Select>
            </div>
            <Button
              type="button"
              variant="secondary"
              icon={<Plus className="w-4 h-4" />}
              onClick={() => setIsCreatingNewInv(true)}
            >
              Create New Case Inline
            </Button>
          </div>
        ) : (
          <div className="space-y-3 bg-[#0d1117] p-4 rounded-md border border-[#1e293b]">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-sky-400 uppercase font-semibold">
                Initialize New Case Inline
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setIsCreatingNewInv(false)}
              >
                Cancel / Use Existing
              </Button>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Input
                label="Investigation Name"
                placeholder="e.g. INC-2026-PCAP-DEEPDIVE"
                value={newInvName}
                onChange={(e) => setNewInvName(e.target.value)}
              />
              <Select
                label="Threat Category"
                value={newInvCategory}
                onChange={(e) => setNewInvCategory(e.target.value)}
                options={INVESTIGATION_CATEGORIES.map((c) => ({ value: c, label: c }))}
              />
            </div>
          </div>
        )}
      </Card>

      {/* Step 2: Drag & Drop Dropzone */}
      <Card>
        <CardHeader
          title="Step 2: Upload Log Artifacts & PCAPs"
          subtitle="Supported formats: Syslog, CSV, JSON, Apache/Nginx access logs, Windows EVTX/Security, Suricata/Snort"
        />

        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-lg p-8 text-center transition-all cursor-pointer flex flex-col items-center justify-center min-h-[180px] ${
            isDragging
              ? 'border-sky-400 bg-sky-950/20'
              : 'border-[#1e293b] hover:border-slate-600 bg-[#0d1117]/50'
          }`}
        >
          <input
            type="file"
            ref={fileInputRef}
            multiple
            className="hidden"
            onChange={handleFileSelect}
          />
          <div className="p-3 rounded-full bg-[#1a2235] text-sky-400 mb-3">
            <Upload className="w-8 h-8" />
          </div>
          <h4 className="text-base font-semibold text-slate-200">
            Drag and drop forensic log files here, or click to browse
          </h4>
          <p className="text-xs text-slate-400 font-mono mt-1 max-w-md">
            Files will be sealed with a SHA-256 cryptographic baseline hash immediately upon ingestion.
          </p>
        </div>
      </Card>

      {/* Queued Files Details */}
      {queuedFiles.length > 0 && (
        <Card className="space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#1e293b]">
            <h3 className="text-sm font-bold font-mono text-slate-200 uppercase flex items-center gap-2">
              <FileCode className="w-4 h-4 text-sky-400" />
              Ingestion Queue ({queuedFiles.length} files)
            </h3>
            <div className="flex items-center gap-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setQueuedFiles([])}
                disabled={isUploading}
              >
                Clear Queue
              </Button>
              <Button
                variant="primary"
                loading={isUploading}
                disabled={isUploading || queuedFiles.every((f) => f.status === 'completed')}
                icon={<Upload className="w-4 h-4" />}
                onClick={handleUploadAll}
              >
                Ingest & Seal Queue ({queuedFiles.filter((f) => f.status !== 'completed').length})
              </Button>
            </div>
          </div>

          <div className="space-y-3">
            {queuedFiles.map((item, idx) => (
              <div
                key={idx}
                className="p-4 rounded-lg bg-[#0d1117] border border-[#1e293b] space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <HardDrive className="w-4 h-4 text-sky-400 shrink-0" />
                    <span className="font-semibold text-sm text-slate-200 truncate max-w-sm">
                      {item.file.name}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      ({formatBytes(item.file.size)})
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {item.status === 'completed' && (
                      <Badge variant="MATCH" size="sm" label="INGESTED & SEALED" />
                    )}
                    {item.status === 'uploading' && (
                      <Badge variant="INFO" size="sm" label="PARSING & HASHING..." />
                    )}
                    {item.status === 'error' && (
                      <Badge variant="MISMATCH" size="sm" label="FAILED" />
                    )}
                    {item.status === 'idle' && (
                      <button
                        onClick={() => removeQueuedFile(idx)}
                        className="text-slate-500 hover:text-slate-300 transition-colors p-1"
                        title="Remove from queue"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>

                {/* Progress bar */}
                {item.status === 'uploading' && (
                  <div className="w-full bg-[#1e293b] rounded-full h-1.5 overflow-hidden">
                    <div
                      className="bg-sky-500 h-1.5 rounded-full transition-all duration-300"
                      style={{ width: `${item.progress}%` }}
                    />
                  </div>
                )}

                {/* File Metadata Form if not yet completed */}
                {item.status !== 'completed' ? (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
                    <Input
                      label="Source System / Host"
                      placeholder="e.g. DC-01, AWS-S3-PROD"
                      value={item.sourceSystem}
                      disabled={isUploading}
                      onChange={(e) => updateQueuedFile(idx, { sourceSystem: e.target.value })}
                    />
                    <Select
                      label="Telemetry Category"
                      value={item.sourceCategory}
                      disabled={isUploading}
                      onChange={(e) => updateQueuedFile(idx, { sourceCategory: e.target.value })}
                      options={SOURCE_CATEGORIES.map((c) => ({ value: c, label: c }))}
                    />
                    <Input
                      label="Timezone Hint"
                      placeholder="UTC or America/New_York"
                      value={item.timezoneHint}
                      disabled={isUploading}
                      onChange={(e) => updateQueuedFile(idx, { timezoneHint: e.target.value })}
                    />
                  </div>
                ) : (
                  // Completed result summary
                  <div className="bg-[#111827] p-3 rounded border border-[#1e293b] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500 uppercase text-[11px]">Computed SHA-256:</span>
                      <HashDisplay hash={item.result?.sha256 || ''} truncate />
                    </div>
                    <div className="flex items-center gap-3 text-slate-400">
                      <span>Status: {item.result ? 'COMPLETED' : 'PARSED'}</span>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => navigate(`/timeline?investigation_id=${selectedInvId}`)}
                        icon={<ArrowRight className="w-3.5 h-3.5 text-sky-400" />}
                      >
                        Inspect Timeline
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          {completedCount > 0 && (
            <div className="pt-3 border-t border-[#1e293b] flex items-center justify-between">
              <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                {completedCount} artifacts successfully parsed and cryptographically hashed.
              </span>
              <Button
                variant="primary"
                size="sm"
                onClick={() => navigate(`/investigations/${selectedInvId}`)}
              >
                Go to Investigation Detail
              </Button>
            </div>
          )}
        </Card>
      )}
    </div>
  );
};

export default LogIngestion;

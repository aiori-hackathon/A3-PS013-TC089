import React from 'react';
import { FileCode, ShieldCheck, Download, HardDrive } from 'lucide-react';
import type { EvidenceFile } from '../../types';
import { Badge } from '../ui/Badge';
import { HashDisplay } from '../ui/HashDisplay';
import { Button } from '../ui/Button';
import { formatBytes, formatDate } from '../../utils/formatters';
import { evidenceApi } from '../../services/api';

interface EvidenceCardProps {
  evidence: EvidenceFile;
  onVerify?: (id: string) => void;
  isVerifying?: boolean;
}

export const EvidenceCard: React.FC<EvidenceCardProps> = ({
  evidence,
  onVerify,
  isVerifying = false,
}) => {
  const downloadUrl = evidenceApi.download(evidence.id);

  return (
    <div className="bg-[#111827] border border-[#1e293b] rounded-lg p-4 transition-all hover:border-slate-700">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-3">
        <div className="flex items-start gap-3">
          <div className="p-2.5 rounded-md bg-[#1a2235] text-sky-400 shrink-0">
            <FileCode className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h4 className="font-semibold text-slate-100 text-sm">{evidence.original_filename}</h4>
              <Badge variant="INFO" size="sm" label={evidence.file_format || 'FILE'} />
              <Badge
                variant={evidence.processing_status}
                size="sm"
                label={evidence.processing_status || 'PARSED'}
              />
            </div>
            <div className="flex items-center gap-4 text-xs text-slate-400 mt-1 font-mono">
              <span className="flex items-center gap-1">
                <HardDrive className="w-3.5 h-3.5 text-slate-500" />
                {formatBytes(evidence.file_size)}
              </span>
              <span>System: {evidence.source_system || 'Generic'}</span>
              <span>Category: {evidence.source_category || 'Log'}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {onVerify && (
            <Button
              size="sm"
              variant="outline"
              loading={isVerifying}
              icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
              onClick={() => onVerify(evidence.id)}
            >
              Verify Baseline
            </Button>
          )}
          <a
            href={downloadUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-[#1a2235] text-slate-200 hover:bg-[#243049] border border-[#1e293b] transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download
          </a>
        </div>
      </div>

      <div className="bg-[#0a0e1a]/80 rounded p-2.5 border border-[#1e293b]/70 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
        <div className="flex items-center gap-2 overflow-hidden">
          <span className="text-slate-500 text-[11px] uppercase tracking-wider shrink-0">SHA-256:</span>
          <HashDisplay hash={evidence.sha256_hash} truncate />
        </div>
        <div className="text-slate-400 shrink-0 text-[11px]">
          Uploaded: {formatDate(evidence.upload_timestamp)}
        </div>
      </div>
    </div>
  );
};

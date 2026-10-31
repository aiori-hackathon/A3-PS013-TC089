import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import toast from 'react-hot-toast';
import { truncateHash, chunkHash } from '../../utils/formatters';

interface HashDisplayProps {
  hash: string;
  truncate?: boolean;
  chunked?: boolean;
  className?: string;
}

export const HashDisplay: React.FC<HashDisplayProps> = ({
  hash,
  truncate = false,
  chunked = false,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  if (!hash) {
    return <span className="text-slate-500 font-mono text-xs">—</span>;
  }

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(hash);
      setCopied(true);
      toast.success('SHA-256 hash copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error('Failed to copy hash');
    }
  };

  const displayText = truncate
    ? truncateHash(hash, 8, 8)
    : chunked
    ? chunkHash(hash)
    : hash;

  return (
    <div className={`inline-flex items-center gap-1.5 font-mono text-xs bg-[#0d1117] px-2 py-1 rounded border border-[#1e293b] select-all ${className}`}>
      <span className="text-cyan-400 break-all">{displayText}</span>
      <button
        onClick={handleCopy}
        title="Copy full SHA-256 hash"
        className="p-1 rounded text-slate-400 hover:text-cyan-300 hover:bg-[#1a2235] transition-colors cursor-pointer shrink-0"
      >
        {copied ? (
          <Check className="w-3.5 h-3.5 text-emerald-400" />
        ) : (
          <Copy className="w-3.5 h-3.5" />
        )}
      </button>
    </div>
  );
};

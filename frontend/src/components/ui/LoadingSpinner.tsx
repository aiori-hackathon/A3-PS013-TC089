import React from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  label?: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  label = 'Loading forensic telemetry...',
  size = 'md',
  className = '',
}) => {
  const iconSize = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
  }[size];

  return (
    <div className={`flex flex-col items-center justify-center p-8 space-y-3 ${className}`}>
      <Loader2 className={`${iconSize} animate-spin text-sky-400`} />
      {label && <p className="text-xs font-mono text-slate-400 tracking-wider uppercase">{label}</p>}
    </div>
  );
};

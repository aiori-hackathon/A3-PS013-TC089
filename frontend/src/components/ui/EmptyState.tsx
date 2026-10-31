import React from 'react';
import { ShieldAlert } from 'lucide-react';
import { Button } from './Button';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  actionLabel,
  onAction,
  className = '',
}) => {
  return (
    <div
      className={`flex flex-col items-center justify-center p-8 text-center rounded-lg border border-dashed border-[#1e293b] bg-[#0d1117]/50 ${className}`}
    >
      <div className="p-3 mb-3 rounded-full bg-[#1a2235] text-sky-400">
        {icon || <ShieldAlert className="w-8 h-8" />}
      </div>
      <h4 className="text-base font-semibold text-slate-200">{title}</h4>
      <p className="max-w-md mt-1 text-sm text-slate-400">{description}</p>
      {actionLabel && onAction && (
        <Button onClick={onAction} size="sm" className="mt-4">
          {actionLabel}
        </Button>
      )}
    </div>
  );
};

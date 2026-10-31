import React from 'react';

export type BadgeVariant =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFO'
  | 'MATCH'
  | 'MISMATCH'
  | 'ERROR'
  | 'ACTIVE'
  | 'ARCHIVED'
  | 'CLOSED'
  | 'PARSED'
  | 'PENDING'
  | 'FAILED'
  | 'PARTIAL'
  | 'DEFAULT';

interface BadgeProps {
  variant?: BadgeVariant | string;
  label?: string;
  children?: React.ReactNode;
  className?: string;
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({
  variant = 'DEFAULT',
  label,
  children,
  className = '',
  size = 'md',
}) => {
  const normalizedVariant = (variant || '').toUpperCase();

  let colorClasses = 'bg-slate-800 text-slate-300 border border-slate-700';

  switch (normalizedVariant) {
    case 'CRITICAL':
    case 'HIGH':
    case 'MISMATCH':
    case 'CLOSED':
    case 'FAILED':
      colorClasses = 'bg-red-950/60 text-red-400 border border-red-800/80';
      break;
    case 'MEDIUM':
    case 'PARTIAL':
      colorClasses = 'bg-orange-950/60 text-orange-400 border border-orange-800/80';
      break;
    case 'LOW':
    case 'PENDING':
    case 'ERROR':
      colorClasses = 'bg-yellow-950/60 text-yellow-400 border border-yellow-800/80';
      break;
    case 'INFO':
      colorClasses = 'bg-blue-950/60 text-blue-400 border border-blue-800/80';
      break;
    case 'MATCH':
    case 'ACTIVE':
    case 'PARSED':
    case 'VIGILANCE':
      colorClasses = 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/80';
      break;
    case 'ARCHIVED':
    case 'MANUAL':
      colorClasses = 'bg-slate-800/80 text-slate-400 border border-slate-700';
      break;
    default:
      colorClasses = 'bg-slate-800/80 text-slate-300 border border-slate-700';
      break;
  }

  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1 font-medium rounded-full tracking-wide uppercase transition-colors ${sizeClasses} ${colorClasses} ${className}`}
    >
      {label || children}
    </span>
  );
};

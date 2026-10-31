import React from 'react';
import { Loader2 } from 'lucide-react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'outline' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  icon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  loading = false,
  icon,
  className = '',
  disabled,
  ...props
}) => {
  let variantStyles = 'bg-sky-600 hover:bg-sky-500 text-white shadow-sm shadow-sky-950/40';

  switch (variant) {
    case 'secondary':
      variantStyles = 'bg-[#1a2235] hover:bg-[#243049] text-slate-200 border border-[#1e293b]';
      break;
    case 'danger':
      variantStyles = 'bg-red-700 hover:bg-red-600 text-white shadow-sm shadow-red-950/40';
      break;
    case 'outline':
      variantStyles = 'bg-transparent border border-sky-500/50 text-sky-400 hover:bg-sky-950/30';
      break;
    case 'ghost':
      variantStyles = 'bg-transparent hover:bg-[#1a2235] text-slate-300';
      break;
  }

  const sizeStyles = {
    sm: 'px-2.5 py-1.5 text-xs font-medium',
    md: 'px-3.5 py-2 text-sm font-medium',
    lg: 'px-5 py-2.5 text-base font-semibold',
  }[size];

  return (
    <button
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center gap-2 rounded-md transition-all duration-150 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${variantStyles} ${sizeStyles} ${className}`}
      {...props}
    >
      {loading ? (
        <Loader2 className="w-4 h-4 animate-spin text-current" />
      ) : icon ? (
        <span className="shrink-0">{icon}</span>
      ) : null}
      <span>{children}</span>
    </button>
  );
};

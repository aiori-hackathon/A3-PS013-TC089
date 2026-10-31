import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Folder, Database, Clock, Calendar, ArrowRight } from 'lucide-react';
import type { Investigation } from '../../types';
import { Badge } from '../ui/Badge';
import { formatDate } from '../../utils/formatters';

interface InvestigationCardProps {
  investigation: Investigation;
  onSelect?: (id: string) => void;
}

export const InvestigationCard: React.FC<InvestigationCardProps> = ({
  investigation,
  onSelect,
}) => {
  const navigate = useNavigate();

  const handleClick = () => {
    if (onSelect) onSelect(investigation.id);
    navigate(`/investigations/${investigation.id}`);
  };

  return (
    <div
      onClick={handleClick}
      className="group relative bg-[#111827] border border-[#1e293b] hover:border-sky-500/60 rounded-lg p-5 transition-all duration-200 hover:shadow-lg hover:shadow-sky-950/20 cursor-pointer flex flex-col justify-between"
    >
      <div>
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded bg-[#1a2235] text-sky-400 group-hover:bg-sky-950/60 group-hover:text-sky-300 transition-colors">
              <Folder className="w-5 h-5" />
            </div>
            <div>
              <h4 className="font-semibold text-slate-100 group-hover:text-sky-400 transition-colors line-clamp-1">
                {investigation.name}
              </h4>
              <span className="text-xs text-slate-400 uppercase tracking-wider font-mono">
                {investigation.category}
              </span>
            </div>
          </div>
          <Badge variant={investigation.status} label={investigation.status} size="sm" />
        </div>

        {investigation.description && (
          <p className="text-xs text-slate-400 line-clamp-2 mb-4 leading-relaxed">
            {investigation.description}
          </p>
        )}
      </div>

      <div className="pt-3 border-t border-[#1e293b] flex items-center justify-between text-xs text-slate-400 font-mono">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5" title="Evidence Files">
            <Database className="w-3.5 h-3.5 text-sky-400" />
            <span>{investigation.evidence_count ?? 0}</span>
          </span>
          <span className="flex items-center gap-1.5" title="Parsed Events">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>{investigation.event_count ?? 0}</span>
          </span>
        </div>

        <div className="flex items-center gap-2 text-slate-400">
          <Calendar className="w-3.5 h-3.5" />
          <span>{formatDate(investigation.created_at, 'MMM dd, yyyy')}</span>
          <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-sky-400 group-hover:translate-x-0.5 transition-all ml-1" />
        </div>
      </div>
    </div>
  );
};

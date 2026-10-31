import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Clock,
  Search,
  ArrowUpDown,
  Code,
  User,
  Globe,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { investigationsApi } from '../services/api';
import type { Event, Investigation } from '../types';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { Badge } from '../components/ui/Badge';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';
import { formatDate } from '../utils/formatters';

export const Timeline: React.FC = () => {
  const [searchParams] = useSearchParams();

  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedInvId, setSelectedInvId] = useState<string>('');
  const [events, setEvents] = useState<Event[]>([]);
  const [uncertainEvents, setUncertainEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [ipFilter, setIpFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [page, setPage] = useState(1);
  const [expandedRawIds, setExpandedRawIds] = useState<Record<string, boolean>>({});

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
        toast.error('Failed to load investigations');
      }
    };
    fetchInvs();
  }, [searchParams, selectedInvId]);

  const loadTimelineEvents = useCallback(async () => {
    if (!selectedInvId) return;
    try {
      setLoading(true);
      const res = await investigationsApi.getTimeline(selectedInvId, {
        search: searchTerm || undefined,
        source_ip: ipFilter || undefined,
        username: userFilter || undefined,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        event_category: categoryFilter === 'ALL' ? undefined : categoryFilter,
        sort_order: sortOrder,
        page,
        limit: 50,
      });

      if (res.data && 'events' in res.data) {
        setEvents(res.data.events || []);
        setUncertainEvents(res.data.uncertain_events || []);
      } else if (Array.isArray(res.data)) {
        setEvents(res.data);
        setUncertainEvents([]);
      }
    } catch {
      toast.error('Failed to load timeline events');
      setEvents([]);
      setUncertainEvents([]);
    } finally {
      setLoading(false);
    }
  }, [selectedInvId, searchTerm, ipFilter, userFilter, severityFilter, categoryFilter, sortOrder, page]);

  useEffect(() => {
    loadTimelineEvents();
  }, [loadTimelineEvents]);

  const toggleRaw = (id: string) => {
    setExpandedRawIds((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const getBorderColorBySeverity = (severity: string) => {
    const s = severity?.toUpperCase();
    switch (s) {
      case 'CRITICAL':
      case 'HIGH':
        return 'border-l-4 border-l-red-500';
      case 'MEDIUM':
        return 'border-l-4 border-l-orange-500';
      case 'LOW':
        return 'border-l-4 border-l-yellow-500';
      case 'INFO':
      default:
        return 'border-l-4 border-l-sky-500';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <Clock className="w-5 h-5 text-sky-400" />
            UNIFIED FORENSIC TIMELINE & CHRONOLOGY
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            NORMALIZED UTC CROSS-SOURCE EVENT RECONSTRUCTION
          </p>
        </div>

        {/* Case selector dropdown */}
        <div className="w-full sm:w-72">
          <Select
            label="Active Investigation Context"
            value={selectedInvId}
            onChange={(e) => {
              setSelectedInvId(e.target.value);
              setPage(1);
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

      {/* Filter Bar */}
      <Card className="py-3 px-4">
        <div className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="md:col-span-2">
              <Input
                icon={<Search className="w-4 h-4" />}
                placeholder="Search description, event payload, or keyword..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setPage(1);
                }}
              />
            </div>
            <div>
              <Input
                icon={<Globe className="w-4 h-4" />}
                placeholder="Filter by IP..."
                value={ipFilter}
                onChange={(e) => {
                  setIpFilter(e.target.value);
                  setPage(1);
                }}
              />
            </div>
            <div>
              <Input
                icon={<User className="w-4 h-4" />}
                placeholder="Filter by User..."
                value={userFilter}
                onChange={(e) => {
                  setUserFilter(e.target.value);
                  setPage(1);
                }}
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#1e293b]">
            <div className="flex items-center gap-3 flex-wrap">
              <div className="w-40">
                <Select
                  value={severityFilter}
                  onChange={(e) => {
                    setSeverityFilter(e.target.value);
                    setPage(1);
                  }}
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFO">INFO</option>
                </Select>
              </div>

              <div className="w-48">
                <Select
                  value={categoryFilter}
                  onChange={(e) => {
                    setCategoryFilter(e.target.value);
                    setPage(1);
                  }}
                >
                  <option value="ALL">All Event Types</option>
                  <option value="Authentication">Authentication</option>
                  <option value="Network Connection">Network Connection</option>
                  <option value="Process Creation">Process Creation</option>
                  <option value="File Modification">File Modification</option>
                  <option value="Privilege Escalation">Privilege Escalation</option>
                  <option value="Web Request">Web Request</option>
                </Select>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="secondary"
                icon={<ArrowUpDown className="w-3.5 h-3.5" />}
                onClick={() => setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')}
              >
                Sort: {sortOrder === 'desc' ? 'Newest First' : 'Oldest First'}
              </Button>
            </div>
          </div>
        </div>
      </Card>

      {/* Timeline Stream */}
      {loading ? (
        <LoadingSpinner label="Reconstructing chronological events..." />
      ) : events.length === 0 ? (
        <EmptyState
          icon={<Clock className="w-8 h-8" />}
          title="No timeline events recorded"
          description={
            !selectedInvId
              ? 'Please select an active investigation above to inspect its chronological timeline.'
              : 'No normalized events match your current filter parameters or log files have not yet been ingested.'
          }
        />
      ) : (
        <div className="space-y-3">
          {events.map((evt) => {
            const isExpanded = !!expandedRawIds[evt.id];
            const borderStyle = getBorderColorBySeverity(evt.severity);

            return (
              <div
                key={evt.id}
                className={`bg-[#111827] border border-[#1e293b] rounded-lg p-4 transition-all hover:border-slate-700 ${borderStyle}`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="font-mono text-sm font-bold text-sky-400">
                      {formatDate(evt.normalized_timestamp || evt.original_timestamp)}
                    </span>
                    {evt.original_timestamp && (
                      <span className="text-[11px] font-mono text-slate-500">
                        (Raw: {evt.original_timestamp})
                      </span>
                    )}
                    <Badge variant={evt.severity} size="sm" label={evt.severity} />
                    <Badge variant="DEFAULT" size="sm" label={evt.event_category} />
                    {evt.source_system && (
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#1a2235] text-slate-300 border border-[#1e293b]">
                        {evt.source_system}
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-3 text-xs font-mono text-slate-400 shrink-0">
                    {evt.username && (
                      <span className="flex items-center gap-1 text-emerald-400">
                        <User className="w-3.5 h-3.5" />
                        {evt.username}
                      </span>
                    )}
                    {evt.source_ip && (
                      <span className="flex items-center gap-1 text-cyan-400">
                        <Globe className="w-3.5 h-3.5" />
                        {evt.source_ip}
                        {evt.dest_ip ? ` → ${evt.dest_ip}` : ''}
                      </span>
                    )}
                  </div>
                </div>

                <p className="text-xs text-slate-200 leading-relaxed font-sans mb-3">
                  {evt.description}
                </p>

                <div className="flex items-center justify-between pt-2 border-t border-[#1e293b]/60">
                  <span className="text-[11px] font-mono text-slate-500">
                    STATUS: {evt.timestamp_status}
                  </span>
                  <button
                    onClick={() => toggleRaw(evt.id)}
                    className="inline-flex items-center gap-1 text-xs font-mono text-sky-400 hover:text-sky-300 cursor-pointer"
                  >
                    <Code className="w-3.5 h-3.5" />
                    {isExpanded ? 'Hide Raw Record' : 'View Raw Record'}
                    {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                  </button>
                </div>

                {isExpanded && (
                  <div className="mt-3 p-3 rounded bg-[#0a0e1a] border border-[#1e293b] font-mono text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap select-all">
                    {evt.raw_record}
                  </div>
                )}
              </div>
            );
          })}

          {/* Pagination */}
          <div className="flex items-center justify-between pt-4 border-t border-[#1e293b] text-xs font-mono text-slate-400">
            <span>Showing page {page} (50 events/page)</span>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="secondary"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </Button>
              <Button
                size="sm"
                variant="secondary"
                disabled={events.length < 50}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Uncertain Timestamps Section */}
      {uncertainEvents.length > 0 && (
        <div className="pt-6 border-t border-[#1e293b] space-y-4">
          <div className="p-3 rounded-lg bg-yellow-950/30 border border-yellow-800/40 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" />
            <div>
              <h4 className="font-semibold text-sm text-yellow-300">
                Uncertain / Ambiguous Timestamp Telemetry ({uncertainEvents.length} events)
              </h4>
              <p className="text-xs text-yellow-400/80 mt-0.5">
                The following records have missing, ambiguous, or out-of-order time markers. They are separated to prevent timeline corruption.
              </p>
            </div>
          </div>

          <div className="space-y-2">
            {uncertainEvents.map((evt) => (
              <div
                key={evt.id}
                className="p-3 rounded bg-[#111827] border border-yellow-800/30 font-mono text-xs text-slate-300"
              >
                <div className="flex items-center justify-between mb-1">
                  <Badge variant="ERROR" size="sm" label={evt.timestamp_status} />
                  <span className="text-slate-500">{evt.source_system}</span>
                </div>
                <p className="text-slate-300">{evt.description}</p>
                <div className="mt-2 p-2 bg-[#0a0e1a] rounded text-[11px] text-slate-400 break-all">
                  {evt.raw_record}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default Timeline;

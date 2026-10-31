import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderOpen,
  Plus,
  Archive,
  Trash2,
  PlayCircle,
  Clock,
  Database,
  ArrowRight,
  ShieldCheck,
  Search,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { investigationsApi, demoApi } from '../services/api';
import type { Investigation, DemoScenario } from '../types';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { Modal } from '../components/ui/Modal';
import { Input } from '../components/ui/Input';
import { Select } from '../components/ui/Select';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { EmptyState } from '../components/ui/EmptyState';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table';
import { INVESTIGATION_CATEGORIES } from '../utils/constants';
import { formatDate } from '../utils/formatters';

export const Investigations: React.FC = () => {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');

  // Modal & Form State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState<string>(INVESTIGATION_CATEGORIES[0]);
  const [submitting, setSubmitting] = useState(false);

  // Delete confirmation
  const [deleteTarget, setDeleteTarget] = useState<Investigation | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Demo scenarios
  const [demoScenarios, setDemoScenarios] = useState<DemoScenario[]>([]);
  const [loadingScenario, setLoadingScenario] = useState<string | null>(null);

  const fetchInvestigations = useCallback(async () => {
    try {
      setLoading(true);
      const res = await investigationsApi.list();
      setInvestigations(Array.isArray(res.data) ? res.data : []);
    } catch {
      toast.error('Failed to load investigations');
      setInvestigations([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchDemoScenarios = useCallback(async () => {
    try {
      const res = await demoApi.getScenarios();
      if (Array.isArray(res.data)) {
        setDemoScenarios(res.data);
      }
    } catch {
      // Demo scenarios fallback default list if backend endpoint returns empty
      setDemoScenarios([
        {
          id: 'apt-lateral-movement',
          name: 'APT-29 Lateral Movement & Credential Dumping',
          description: 'Multi-host Windows security logs, Sysmon process creation, and Mimikatz execution telemetry.',
          category: 'Unauthorized Access',
          records_count: 14200,
        },
        {
          id: 'insider-data-exfiltration',
          name: 'Insider Threat: Cloud Storage Data Exfiltration',
          description: 'Web proxy and AWS CloudTrail audit logs showing abnormal volume transfer after work hours.',
          category: 'Data Breach',
          records_count: 8900,
        },
        {
          id: 'ransomware-staging',
          name: 'LockBit Ransomware Canary & File Encryption',
          description: 'Endpoint file modification velocity, shadow copy deletion commands, and C2 beaconing.',
          category: 'Malware',
          records_count: 5600,
        },
      ]);
    }
  }, []);

  useEffect(() => {
    fetchInvestigations();
    fetchDemoScenarios();
  }, [fetchInvestigations, fetchDemoScenarios]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      toast.error('Name is required');
      return;
    }

    try {
      setSubmitting(true);
      const res = await investigationsApi.create({
        name: name.trim(),
        description: description.trim() || undefined,
        category,
      });
      toast.success('Investigation case created');
      setIsModalOpen(false);
      setName('');
      setDescription('');
      fetchInvestigations();
      if (res.data?.id) {
        navigate(`/investigations/${res.data.id}`);
      }
    } catch {
      toast.error('Failed to create investigation case');
    } finally {
      setSubmitting(false);
    }
  };

  const handleArchive = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    try {
      await investigationsApi.archive(id);
      toast.success('Investigation case archived');
      fetchInvestigations();
    } catch {
      toast.error('Failed to archive investigation');
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      setIsDeleting(true);
      await investigationsApi.delete(deleteTarget.id);
      toast.success('Investigation deleted');
      setDeleteTarget(null);
      fetchInvestigations();
    } catch {
      toast.error('Failed to delete investigation');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleLoadDemo = async (scenarioName: string) => {
    try {
      setLoadingScenario(scenarioName);
      const res = await demoApi.loadScenario(scenarioName);
      toast.success(res.data?.message || 'Demo scenario loaded successfully');
      fetchInvestigations();
      if (res.data?.investigation_id) {
        navigate(`/investigations/${res.data.investigation_id}`);
      }
    } catch {
      toast.error('Failed to load demo scenario');
    } finally {
      setLoadingScenario(null);
    }
  };

  const filteredInvestigations = investigations.filter((inv) => {
    const matchesSearch =
      inv.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (inv.description && inv.description.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesCategory =
      filterCategory === 'ALL' || inv.category.toUpperCase() === filterCategory.toUpperCase();
    const matchesStatus =
      filterStatus === 'ALL' || inv.status.toUpperCase() === filterStatus.toUpperCase();
    return matchesSearch && matchesCategory && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <FolderOpen className="w-5 h-5 text-sky-400" />
            INVESTIGATION CASE MANAGEMENT
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            ORGANIZED FORENSIC INCIDENTS, EVIDENCE STACKS, AND AUDIT TRAILS
          </p>
        </div>
        <Button
          variant="primary"
          icon={<Plus className="w-4 h-4" />}
          onClick={() => setIsModalOpen(true)}
        >
          New Investigation
        </Button>
      </div>

      {/* Filters Toolbar */}
      <Card className="py-3 px-4">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-center">
          <div className="md:col-span-2">
            <Input
              icon={<Search className="w-4 h-4" />}
              placeholder="Search case name, keywords, or incident notes..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <div>
            <Select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
            >
              <option value="ALL">All Threat Categories</option>
              {INVESTIGATION_CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
            >
              <option value="ALL">All Statuses</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="ARCHIVED">ARCHIVED</option>
              <option value="CLOSED">CLOSED</option>
            </Select>
          </div>
        </div>
      </Card>

      {/* Investigations Table / List */}
      {loading ? (
        <LoadingSpinner label="Retrieving investigation registry..." />
      ) : filteredInvestigations.length === 0 ? (
        <EmptyState
          icon={<FolderOpen className="w-8 h-8" />}
          title="No investigations found"
          description={
            searchTerm || filterCategory !== 'ALL' || filterStatus !== 'ALL'
              ? 'No cases match your filter criteria. Try resetting the filters.'
              : 'There are currently no active forensic cases registered.'
          }
          actionLabel="Create First Case"
          onAction={() => setIsModalOpen(true)}
        />
      ) : (
        <Card className="p-0 overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Case Identifier & Description</TableHead>
                <TableHead>Threat Category</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Evidence Files</TableHead>
                <TableHead>Events</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredInvestigations.map((inv) => (
                <TableRow
                  key={inv.id}
                  onClick={() => navigate(`/investigations/${inv.id}`)}
                  className="cursor-pointer group"
                >
                  <TableCell>
                    <div>
                      <div className="font-semibold text-slate-100 group-hover:text-sky-400 transition-colors flex items-center gap-2">
                        {inv.name}
                        <ArrowRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity text-sky-400" />
                      </div>
                      {inv.description && (
                        <div className="text-xs text-slate-400 line-clamp-1 mt-0.5 max-w-md">
                          {inv.description}
                        </div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <span className="text-xs font-mono text-slate-300">
                      {inv.category}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge variant={inv.status} label={inv.status} size="sm" />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5 font-mono text-xs text-slate-300">
                      <Database className="w-3.5 h-3.5 text-sky-400" />
                      <span>{inv.evidence_count ?? 0}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5 font-mono text-xs text-slate-300">
                      <Clock className="w-3.5 h-3.5 text-cyan-400" />
                      <span>{inv.event_count ?? 0}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <span className="text-xs font-mono text-slate-400">
                      {formatDate(inv.created_at, 'yyyy-MM-dd')}
                    </span>
                  </TableCell>
                  <TableCell className="text-right">
                    <div
                      className="inline-flex items-center gap-1"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {inv.status !== 'ARCHIVED' && (
                        <button
                          onClick={(e) => handleArchive(e, inv.id)}
                          title="Archive Investigation"
                          className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-[#1a2235] transition-colors cursor-pointer"
                        >
                          <Archive className="w-4 h-4" />
                        </button>
                      )}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setDeleteTarget(inv);
                        }}
                        title="Delete Investigation"
                        className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-red-950/40 transition-colors cursor-pointer"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}

      {/* Demo Attack Scenarios Section */}
      <div className="pt-4 border-t border-[#1e293b]">
        <div className="mb-4">
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-sky-400" />
            BENCHMARK ATTACK SCENARIOS & DATASETS
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            LOAD REALISTIC ATTACK LOGS TO BENCHMARK VIGILANCE DETECTION SPEED AND CORRELATION
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {demoScenarios.map((scenario) => (
            <Card
              key={scenario.id}
              className="flex flex-col justify-between hover:border-sky-500/50 transition-colors"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <Badge variant="INFO" size="sm" label={scenario.category} />
                  {scenario.records_count && (
                    <span className="text-[11px] font-mono text-slate-400">
                      ~{scenario.records_count.toLocaleString()} recs
                    </span>
                  )}
                </div>
                <h3 className="font-semibold text-slate-100 text-sm mb-1.5">
                  {scenario.name}
                </h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  {scenario.description}
                </p>
              </div>

              <Button
                variant="outline"
                size="sm"
                className="w-full justify-center"
                loading={loadingScenario === scenario.id || loadingScenario === scenario.name}
                icon={<PlayCircle className="w-4 h-4" />}
                onClick={() => handleLoadDemo(scenario.id || scenario.name)}
              >
                Load Scenario Dataset
              </Button>
            </Card>
          ))}
        </div>
      </div>

      {/* New Investigation Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Initialize New Forensic Investigation"
      >
        <form onSubmit={handleCreate} className="space-y-4">
          <Input
            label="Investigation Name"
            placeholder="e.g., CASE-2026-004-APT29-EXFIL"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            autoFocus
          />

          <Select
            label="Threat Category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            options={INVESTIGATION_CATEGORIES.map((cat) => ({
              value: cat,
              label: cat,
            }))}
          />

          <div className="w-full space-y-1.5">
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300">
              Case Brief / Description
            </label>
            <textarea
              rows={3}
              className="w-full bg-[#0d1117] border border-[#1e293b] text-slate-200 placeholder-slate-500 rounded-md p-2.5 text-sm focus:outline-none focus:border-sky-500 font-sans"
              placeholder="Specify initial infection vector, compromised assets, hostnames..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div className="flex justify-end gap-3 pt-3 border-t border-[#1e293b]">
            <Button
              type="button"
              variant="secondary"
              onClick={() => setIsModalOpen(false)}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={submitting}>
              Create Investigation
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        title="Confirm Investigation Deletion"
      >
        <div className="space-y-4">
          <p className="text-sm text-slate-300">
            Are you sure you want to delete investigation{' '}
            <strong className="text-white font-mono">
              {deleteTarget?.name}
            </strong>
            ? All associated evidence baselines, normalized event logs, and correlation alerts
            will be permanently removed.
          </p>

          <div className="p-3 rounded bg-red-950/30 border border-red-800/40 text-xs text-red-300 font-mono">
            WARNING: This action cannot be undone. Cryptographic baselines will be purged.
          </div>

          <div className="flex justify-end gap-3 pt-3 border-t border-[#1e293b]">
            <Button
              type="button"
              variant="secondary"
              onClick={() => setDeleteTarget(null)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="danger"
              loading={isDeleting}
              onClick={handleDelete}
            >
              Delete Case Permanently
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};

export default Investigations;

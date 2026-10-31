import React, { useState } from 'react';
import {
  Settings as SettingsIcon,
  Shield,
  Save,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Info,
  ExternalLink,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { Card, CardHeader } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';
import { STORAGE_KEYS, DEFAULT_API_BASE } from '../utils/constants';
import { systemApi } from '../services/api';

export const Settings: React.FC = () => {
  const [backendUrl, setBackendUrl] = useState(() => {
    return localStorage.getItem(STORAGE_KEYS.BACKEND_URL) || DEFAULT_API_BASE;
  });
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'success' | 'failed' | null>(null);

  const handleSaveBackendUrl = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = backendUrl.trim().replace(/\/+$/, '');
    localStorage.setItem(STORAGE_KEYS.BACKEND_URL, trimmed);
    toast.success('Backend API configuration updated');
  };

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setConnectionStatus(null);
    try {
      await systemApi.checkHealth();
      setConnectionStatus('success');
      toast.success('Connection to VIGILANCE backend succeeded!');
    } catch {
      setConnectionStatus('failed');
      toast.error('Unable to reach backend API at specified endpoint');
    } finally {
      setTestingConnection(false);
    }
  };

  const handleResetDefaults = () => {
    setBackendUrl(DEFAULT_API_BASE);
    localStorage.setItem(STORAGE_KEYS.BACKEND_URL, DEFAULT_API_BASE);
    toast.success('Reset to default backend URL: ' + DEFAULT_API_BASE);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="pb-2 border-b border-[#1e293b]">
        <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-sky-400" />
          SYSTEM CONFIGURATION & PLATFORM AUDIT
        </h1>
        <p className="text-xs text-slate-400 mt-0.5 font-mono">
          CORE SERVICES, BACKEND TELEMETRY INTEGRATIONS, AND FORENSIC DISCLAIMERS
        </p>
      </div>

      {/* Backend API Configuration */}
      <Card>
        <CardHeader
          title="Backend Service Connection"
          subtitle="Define the root URL of the Vigilance API server handling parsing and cryptographic verification"
        />

        <form onSubmit={handleSaveBackendUrl} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
            <div className="sm:col-span-2">
              <Input
                label="API Base URL"
                value={backendUrl}
                onChange={(e) => setBackendUrl(e.target.value)}
                placeholder="http://localhost:8000/api"
                helperText="Default: http://localhost:8000/api"
                required
              />
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="secondary"
                loading={testingConnection}
                icon={<RefreshCw className="w-4 h-4" />}
                onClick={handleTestConnection}
                className="flex-1"
              >
                Test Ping
              </Button>
              <Button
                type="submit"
                variant="primary"
                icon={<Save className="w-4 h-4" />}
                className="flex-1"
              >
                Save
              </Button>
            </div>
          </div>

          {connectionStatus === 'success' && (
            <div className="p-3 rounded-md bg-emerald-950/40 border border-emerald-800 text-xs font-mono text-emerald-400 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>Core backend responded with HTTP 200 OK. All services operational.</span>
            </div>
          )}

          {connectionStatus === 'failed' && (
            <div className="p-3 rounded-md bg-red-950/40 border border-red-800 text-xs font-mono text-red-400 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>Failed to establish contact with backend. Verify the host is reachable and CORS is enabled.</span>
            </div>
          )}

          <div className="pt-2 flex justify-start">
            <button
              type="button"
              onClick={handleResetDefaults}
              className="text-xs font-mono text-slate-500 hover:text-slate-300 underline cursor-pointer"
            >
              Reset to Factory Default Endpoint
            </button>
          </div>
        </form>
      </Card>

      {/* Platform Architecture & About */}
      <Card>
        <CardHeader
          title="About VIGILANCE Digital Forensics Platform"
          subtitle="High-assurance digital forensics, incident response, and time-series audit framework"
        />

        <div className="space-y-4 text-xs font-mono text-slate-300 leading-relaxed">
          <div className="flex items-center gap-3 p-3 bg-[#0d1117] rounded border border-[#1e293b]">
            <Shield className="w-8 h-8 text-sky-400 shrink-0" />
            <div>
              <div className="font-bold text-slate-100 text-sm">VIGILANCE PLATFORM v1.0.0-RELEASE</div>
              <div className="text-slate-500 text-[11px] mt-0.5">
                AIORI Forensics & Incident Response Hackathon Edition
              </div>
            </div>
          </div>

          <p className="text-slate-400 font-sans">
            VIGILANCE is designed to eliminate time-consuming manual forensic workflows. By computing SHA-256 cryptographic baselines at the precise moment of artifact ingestion, normalizing heterogeneous multi-source timezones to UTC, and evaluating correlation rules against raw evidence, VIGILANCE guarantees rigorous chain-of-custody while accelerating incident triage from hours to seconds.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            <div className="p-3 bg-[#0d1117] rounded border border-[#1e293b]">
              <span className="text-slate-500 block uppercase mb-1">Architecture</span>
              <span className="text-slate-200">React 19, TypeScript, Vite, Tailwind v4</span>
            </div>
            <div className="p-3 bg-[#0d1117] rounded border border-[#1e293b]">
              <span className="text-slate-500 block uppercase mb-1">Hashing Standard</span>
              <span className="text-slate-200">SHA-256 (FIPS 180-4 standard)</span>
            </div>
          </div>

          <div className="pt-2 flex items-center gap-3">
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#1a2235] text-slate-200 hover:bg-[#243049] border border-[#1e293b] text-xs font-mono"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
              </svg>
              Source Repository
              <ExternalLink className="w-3 h-3 text-slate-500" />
            </a>
          </div>
        </div>
      </Card>

      {/* Forensic Disclaimer */}
      <Card className="border-yellow-800/40 bg-yellow-950/10">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-yellow-400 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs">
            <h4 className="font-bold text-yellow-300 font-mono uppercase">
              Forensic Integrity & Chain-of-Custody Notice
            </h4>
            <p className="text-slate-300 leading-relaxed font-sans">
              All cryptographic baselines generated by VIGILANCE confirm bit-level parity between the stored artifact and its state at ingestion. Recalculation confirms no subsequent tampering has occurred within the platform. However, baseline calculation cannot attest to authenticity or integrity of the host operating system or network pipeline prior to initial capture.
            </p>
          </div>
        </div>
      </Card>
    </div>
  );
};

export default Settings;

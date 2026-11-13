import React, { useState, useEffect } from 'react';
import { Activity, RefreshCw } from 'lucide-react';
import { useInvestigations } from '../../hooks/useInvestigations';
import { systemApi } from '../../services/api';

interface TopBarProps {
  collapsed: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({ collapsed }) => {
  const { investigations, activeInvestigationId, selectActiveInvestigation, loading } = useInvestigations();
  const [backendConnected, setBackendConnected] = useState<boolean | null>(null);
  const [checkingHealth, setCheckingHealth] = useState(false);

  const checkStatus = async () => {
    setCheckingHealth(true);
    try {
      await systemApi.checkHealth();
      setBackendConnected(true);
    } catch {
      setBackendConnected(false);
    } finally {
      setCheckingHealth(false);
    }
  };

  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const selectedInvestigationId =
    investigations.some((inv) => inv.id === activeInvestigationId)
      ? activeInvestigationId
      : investigations[0]?.id || '';

  return (
    <header
      className={`fixed top-0 right-0 h-16 bg-[#0d1117]/90 backdrop-blur-md border-b border-[#1e293b] z-20 flex items-center justify-between px-6 transition-all duration-200 ${
        collapsed ? 'left-16' : 'left-60'
      }`}
    >
      {/* Left side brand / context info */}
      <div className="flex items-center gap-3">
        <span className="font-mono text-sm tracking-widest text-slate-300 font-semibold hidden sm:inline">
          VIGILANCE PLATFORM
        </span>
        <span className="text-slate-600 hidden sm:inline">/</span>
        <span className="text-xs font-mono text-sky-400 uppercase tracking-wider">
          FORENSIC CONTEXT
        </span>
      </div>

      {/* Center: Active Investigation Selector */}
      <div className="flex items-center gap-2 max-w-md w-full justify-center px-4">
        <div className="flex items-center gap-2 w-full max-w-xs">
          <label htmlFor="topbar-investigation-select" className="text-xs font-mono text-slate-400 shrink-0 hidden md:inline">
            ACTIVE CASE:
          </label>
          <select
            id="topbar-investigation-select"
            value={selectedInvestigationId}
            onChange={(e) => selectActiveInvestigation(e.target.value)}
            disabled={loading || investigations.length === 0}
            className="w-full bg-[#111827] border border-[#1e293b] text-slate-200 text-xs rounded-md px-2.5 py-1.5 focus:outline-none focus:border-sky-500 font-mono transition-colors cursor-pointer truncate"
          >
            {investigations.length === 0 ? (
              <option value="">{loading ? 'Loading cases...' : 'No Active Investigations'}</option>
            ) : (
              investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  [{inv.category.toUpperCase()}] {inv.name}
                </option>
              ))
            )}
          </select>
        </div>
      </div>

      {/* Right: System Status Indicator */}
      <div className="flex items-center gap-4">
        <div
          onClick={checkStatus}
          title={
            backendConnected === true
              ? 'Backend API Connected (Click to re-verify)'
              : backendConnected === false
              ? 'Backend API Disconnected (Click to re-verify)'
              : 'Verifying Backend Connection...'
          }
          className="flex items-center gap-2 px-2.5 py-1 rounded bg-[#111827] border border-[#1e293b] cursor-pointer hover:border-slate-700 transition-colors"
        >
          <div className="relative flex items-center justify-center">
            {backendConnected === true ? (
              <>
                <span className="absolute w-2 h-2 rounded-full bg-emerald-400 animate-ping opacity-75"></span>
                <span className="relative w-2 h-2 rounded-full bg-emerald-500"></span>
              </>
            ) : backendConnected === false ? (
              <>
                <span className="relative w-2 h-2 rounded-full bg-red-500"></span>
              </>
            ) : (
              <RefreshCw className={`w-3 h-3 text-yellow-400 ${checkingHealth ? 'animate-spin' : ''}`} />
            )}
          </div>

          <span className="text-[11px] font-mono uppercase tracking-wider hidden lg:inline">
            {backendConnected === true ? (
              <span className="text-emerald-400 font-medium">CORE ONLINE</span>
            ) : backendConnected === false ? (
              <span className="text-red-400 font-medium">DISCONNECTED</span>
            ) : (
              <span className="text-yellow-400 font-medium">PROBING...</span>
            )}
          </span>
          <Activity className="w-3.5 h-3.5 text-slate-500" />
        </div>
      </div>
    </header>
  );
};

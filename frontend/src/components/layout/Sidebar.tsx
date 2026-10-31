import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  FolderOpen,
  Database,
  Upload,
  Clock,
  ShieldCheck,
  AlertTriangle,
  FileText,
  BarChart3,
  Settings,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

interface SidebarProps {
  collapsed: boolean;
  onToggleCollapse: () => void;
}

const navItems = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/investigations', label: 'Investigations', icon: FolderOpen },
  { to: '/evidence', label: 'Evidence', icon: Database },
  { to: '/ingestion', label: 'Log Ingestion', icon: Upload },
  { to: '/timeline', label: 'Timeline', icon: Clock },
  { to: '/integrity', label: 'Integrity', icon: ShieldCheck },
  { to: '/analysis', label: 'Analysis', icon: AlertTriangle },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/triage', label: 'Triage', icon: BarChart3 },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggleCollapse }) => {
  return (
    <aside
      className={`fixed top-0 left-0 h-screen z-30 flex flex-col justify-between bg-[#0d1117] border-r border-[#1e293b] transition-all duration-200 select-none ${
        collapsed ? 'w-16' : 'w-60'
      }`}
    >
      {/* Brand Header */}
      <div>
        <div className="h-16 flex items-center justify-between px-4 border-b border-[#1e293b]">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="p-2 rounded bg-sky-950/70 text-sky-400 border border-sky-800/40 shrink-0 shadow-sm shadow-sky-900/20">
              <Shield className="w-5 h-5 text-sky-400" />
            </div>
            {!collapsed && (
              <div className="truncate">
                <span className="font-bold text-base tracking-widest text-slate-100 font-mono">
                  VIGILANCE
                </span>
                <span className="block text-[10px] uppercase font-mono tracking-wider text-sky-400">
                  Forensics Suite
                </span>
              </div>
            )}
          </div>
          <button
            onClick={onToggleCollapse}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-[#1a2235] transition-colors"
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="p-2 space-y-1 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all group ${
                    isActive
                      ? 'bg-sky-950/80 text-sky-400 border border-sky-800/50 shadow-sm shadow-sky-950/40'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-[#161f30]'
                  }`
                }
              >
                <Icon className="w-4 h-4 shrink-0 transition-transform group-hover:scale-105" />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Footer System Status / Version */}
      <div className="p-3 border-t border-[#1e293b] text-xs font-mono text-slate-500 bg-[#0a0e1a]/40">
        {!collapsed ? (
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400">STATUS: READY</span>
            <span className="text-[11px] text-sky-500">v1.0-RC</span>
          </div>
        ) : (
          <div className="text-center text-[10px] text-sky-500 font-bold">V1</div>
        )}
      </div>
    </aside>
  );
};

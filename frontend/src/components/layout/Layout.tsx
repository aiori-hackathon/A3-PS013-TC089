import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

export const Layout: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="min-h-screen bg-[#0a0e1a] text-slate-200 flex">
      {/* Toast notifications */}
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#111827',
            color: '#e2e8f0',
            border: '1px solid #1e293b',
            fontFamily: 'monospace',
            fontSize: '13px',
          },
          success: {
            iconTheme: {
              primary: '#10b981',
              secondary: '#111827',
            },
          },
          error: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#111827',
            },
          },
        }}
      />

      {/* Sidebar */}
      <Sidebar
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed(!collapsed)}
      />

      {/* TopBar */}
      <TopBar collapsed={collapsed} />

      {/* Main Content Area */}
      <main
        className={`flex-1 transition-all duration-200 min-h-screen pt-16 flex flex-col ${
          collapsed ? 'ml-16' : 'ml-60'
        }`}
      >
        <div className="flex-1 p-6 max-w-7xl w-full mx-auto">
          <Outlet />
        </div>
      </main>
    </div>
  );
};

export default Layout;

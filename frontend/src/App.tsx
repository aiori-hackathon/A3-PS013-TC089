import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/layout/Layout';
import Dashboard from './pages/Dashboard';
import Investigations from './pages/Investigations';
import InvestigationDetail from './pages/InvestigationDetail';
import EvidenceManagement from './pages/EvidenceManagement';
import LogIngestion from './pages/LogIngestion';
import Timeline from './pages/Timeline';
import IntegrityVerification from './pages/IntegrityVerification';
import IncidentAnalysis from './pages/IncidentAnalysis';
import Reports from './pages/Reports';
import TriageComparison from './pages/TriageComparison';
import Settings from './pages/Settings';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="investigations" element={<Investigations />} />
          <Route path="investigations/:id" element={<InvestigationDetail />} />
          <Route path="evidence" element={<EvidenceManagement />} />
          <Route path="ingestion" element={<LogIngestion />} />
          <Route path="timeline" element={<Timeline />} />
          <Route path="integrity" element={<IntegrityVerification />} />
          <Route path="analysis" element={<IncidentAnalysis />} />
          <Route path="reports" element={<Reports />} />
          <Route path="triage" element={<TriageComparison />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

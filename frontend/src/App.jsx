import React from 'react';
import { AppProvider, useApp } from './context/AppContext';
import TopBar from './components/TopBar';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Events from './pages/Events';
import Assets from './pages/Assets';
import Incidents from './pages/Incidents';
import IncidentWorkspace from './pages/IncidentWorkspace';
import ThreatIntel from './pages/ThreatIntel';
import Mitre from './pages/Mitre';
import Response from './pages/Response';
import Audit from './pages/Audit';
import Twin from './pages/Twin';
import AttackReplayPage from './pages/AttackReplayPage';
import Settings from './pages/Settings';

function AppContent() {
  const { currentTab } = useApp();

  const renderCurrentView = () => {
    switch (currentTab) {
      case 'dashboard': return <Dashboard />;
      case 'alerts': return <Alerts />;
      case 'events': return <Events />;
      case 'assets': return <Assets />;
      case 'incidents': return <Incidents />;
      case 'investigation': return <IncidentWorkspace />;
      case 'intel': return <ThreatIntel />;
      case 'mitre': return <Mitre />;
      case 'response': return <Response />;
      case 'audit': return <Audit />;
      case 'twin': return <Twin />;
      case 'replay': return <AttackReplayPage />;
      case 'settings': return <Settings />;
      default: return <Dashboard />;
    }
  };

  return (
    <div className="ts-layout">
      <TopBar />
      <div className="ts-main">
        <Sidebar />
        <main className="ts-viewport">{renderCurrentView()}</main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <AppContent />
    </AppProvider>
  );
}

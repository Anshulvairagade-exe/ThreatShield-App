import React from 'react';
import { useApp } from '../context/AppContext';
import { useApi } from '../hooks/useApi.js';
import { apiGet, isBackendConfigured } from '../services/api/client.js';
import { ConnectionState, LoadingState, PageHeader } from '../components/ui.jsx';
import ContractsPage from './ContractsPage.jsx';

export default function Settings() {
  const { setCurrentTab } = useApp();
  const [showContracts, setShowContracts] = React.useState(false);
  const health = useApi(() => apiGet('/api/v1/health'), []);

  return (
    <div>
      <PageHeader title="Settings" sub="Environment, data sources and API reference" />
      <div className="ts-card ts-card-pad" style={{ marginBottom: 12, maxWidth: 640 }}>
        <div className="ts-section-title">Backend connection</div>
        {!isBackendConfigured() && (
          <p className="ts-small ts-muted">VITE_API_BASE_URL is unset — the UI renders empty states instead of estimates.</p>
        )}
        {health.loading && <LoadingState label="Checking backend…" />}
        {health.error && <ConnectionState error={health.error} retry={health.refresh} />}
        {health.data && (
          <dl className="ts-kv">
            <dt>Status</dt><dd>{health.data.status}</dd>
            <dt>Version</dt><dd>{health.data.version}</dd>
            <dt>Database</dt><dd>{health.data.database}</dd>
            <dt>Search</dt><dd>{health.data.opensearch}</dd>
            <dt>Zero-Day model</dt><dd>{health.data.zeroday_model}</dd>
          </dl>
        )}
      </div>
      <div className="ts-card ts-card-pad" style={{ marginBottom: 12, maxWidth: 640 }}>
        <div className="ts-section-title">Data policy</div>
        <p className="ts-small ts-muted">
          Production views display backend truth only. When the backend is unreachable they show
          empty states — never fabricated alerts, scores or coverage. Demo data exists solely in
          the Attack Replay simulation lab and is labelled as such.
        </p>
      </div>
      <div className="ts-card ts-card-pad" style={{ maxWidth: 640 }}>
        <div className="ts-section-title">Team API contracts</div>
        <p className="ts-small ts-muted" style={{ marginBottom: 10 }}>
          Developer reference for backend endpoint contracts (kept out of the SOC navigation).
        </p>
        {!showContracts
          ? <button className="ts-btn" onClick={() => setShowContracts(true)}>Show API contracts</button>
          : <><button className="ts-btn" onClick={() => setShowContracts(false)}>Hide API contracts</button><ContractsPage /></>}
      </div>
    </div>
  );
}

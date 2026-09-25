import React from 'react';
import { useApp } from '../context/AppContext';
import { useApi } from '../hooks/useApi.js';
import { listIncidents } from '../services/api/incidents.js';
import { ConnectionState, EmptyState, fmtTime, LoadingState, PageHeader, RiskScore,
  SeverityBadge, StatusBadge } from '../components/ui.jsx';
import DataTable from '../components/DataTable.jsx';

export default function Incidents() {
  const { setCurrentTab, setSelectedIncidentId } = useApp();
  const req = useApi(() => listIncidents({ limit: 200 }), []);

  const open = (id) => { setSelectedIncidentId(id); setCurrentTab('investigation'); };

  return (
    <div>
      <PageHeader title="Incidents" sub="Correlated cases · click a row to investigate" />
      {req.loading && <LoadingState label="Loading incidents…" />}
      {req.error && <ConnectionState error={req.error} retry={req.refresh} context="the incident store" />}
      {req.data && (
        req.data.incidents.length === 0
          ? <div className="ts-card"><EmptyState title="No incidents" body="No correlated cases exist yet. Incidents open automatically when detections correlate." /></div>
          : <DataTable
              columns={[
                { key: 'severity', label: 'Severity', render: (r) => <SeverityBadge severity={r.severity} />, sortValue: (r) => r.severity },
                { key: 'title', label: 'Incident', render: (r) => <span className="ts-row-title">{r.title}</span> },
                { key: 'risk_score', label: 'Risk', render: (r) => <RiskScore value={r.risk_score} />, sortValue: (r) => r.risk_score },
                { key: 'status', label: 'Status', render: (r) => <StatusBadge status={r.status} /> },
                { key: 'created_at', label: 'Opened', render: (r) => <span className="ts-small ts-muted">{fmtTime(r.created_at)}</span>, sortValue: (r) => r.created_at },
              ]}
              rows={req.data.incidents} rowKey={(r) => r.id} onRowClick={(r) => open(r.id)}
            />
      )}
    </div>
  );
}

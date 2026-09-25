import React from 'react';
import { useApi } from '../hooks/useApi.js';
import { apiGet } from '../services/api/client.js';
import { ConnectionState, Drawer, EmptyState, fmtTime, LoadingState, PageHeader,
  RiskScore, SeverityBadge, StatusBadge } from '../components/ui.jsx';
import DataTable from '../components/DataTable.jsx';

function AssetDrawer({ hostname, onClose }) {
  const asset = useApi(() => apiGet(`/api/v1/assets/${encodeURIComponent(hostname)}`), [hostname]);
  const alerts = useApi(() => apiGet('/api/v1/alerts?limit=500'), []);
  const incidents = useApi(() => apiGet('/api/v1/incidents?limit=200'), []);
  const events = useApi(() => apiGet(`/api/v1/events/search?limit=200&asset=${encodeURIComponent(hostname)}`), [hostname]);

  return (
    <Drawer title={hostname} onClose={onClose} wide>
      {asset.loading && <LoadingState />}
      {asset.error && <ConnectionState error={asset.error} retry={asset.refresh} context="the asset store" />}
      {asset.data && (() => { const a = asset.data; return (
        <div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <StatusBadge status={a.status} />
            <span className="ts-small ts-muted">Risk <RiskScore value={a.risk_score} /></span>
          </div>
          <dl className="ts-kv">
            <dt>IP</dt><dd className="font-mono">{a.ip || '—'}</dd>
            <dt>OS</dt><dd>{a.os || '—'}</dd>
            <dt>Type</dt><dd>{a.type || '—'}</dd>
            <dt>Subnet</dt><dd>{a.subnet || '—'}</dd>
            <dt>User</dt><dd>{a.user || '—'}</dd>
            <dt>Criticality</dt><dd>{a.criticality}</dd>
            <dt>Last seen</dt><dd>{fmtTime(a.last_seen)}</dd>
          </dl>
          <h2 className="ts-h2">Alerts on this asset</h2>
          {alerts.data
            ? (alerts.data.alerts.filter((x) => (x.hostname === hostname)).length === 0
              ? <p className="ts-small ts-muted">None.</p>
              : alerts.data.alerts.filter((x) => x.hostname === hostname).slice(0, 10).map((x) => (
                <div key={x.id} className="ts-small" style={{ marginBottom: 4 }}>
                  <SeverityBadge severity={x.severity} /> {x.rule_id}
                </div>)))
            : <p className="ts-small ts-muted">Unavailable.</p>}
          <h2 className="ts-h2">Recent events ({events.data ? events.data.results.length : '…'})</h2>
          {(events.data ? events.data.results : []).slice(0, 10).map((e) => (
            <div key={e.event_id} className="ts-small ts-muted" style={{ marginBottom: 4 }}>
              <span className="font-mono">{fmtTime(e.timestamp)}</span> · {e.event_type} · {e.source}
            </div>
          ))}
          <h2 className="ts-h2">Incidents</h2>
          {(incidents.data ? incidents.data.incidents : [])
            .filter((i) => (i.title || '').includes(hostname)).slice(0, 5).map((i) => (
              <div key={i.id} className="ts-small" style={{ marginBottom: 4 }}>{i.title} · <RiskScore value={i.risk_score} /></div>
            ))}
        </div>
      ); })()}
    </Drawer>
  );
}

export default function Assets() {
  const req = useApi(() => apiGet('/api/v1/assets'), []);
  const alerts = useApi(() => apiGet('/api/v1/alerts?limit=500'), []);
  const [open, setOpen] = React.useState(null);

  const alertCount = React.useCallback((hostname) => {
    if (!alerts.data) return '…';
    return alerts.data.alerts.filter((a) => a.hostname === hostname).length;
  }, [alerts.data]);

  return (
    <div>
      <PageHeader title="Assets" sub="Monitored endpoints and servers" />
      {req.loading && <LoadingState label="Loading assets…" />}
      {req.error && <ConnectionState error={req.error} retry={req.refresh} context="the asset store" />}
      {req.data && (
        req.data.assets.length === 0
          ? <div className="ts-card"><EmptyState title="No assets" body="Enroll Wazuh agents or run the simulator to populate inventory." /></div>
          : <DataTable
              columns={[
                { key: 'hostname', label: 'Hostname', render: (r) => <span className="ts-row-title font-mono">{r.hostname}</span> },
                { key: 'ip', label: 'IP', render: (r) => <span className="font-mono">{r.ip || '—'}</span> },
                { key: 'os', label: 'OS', render: (r) => <span className="ts-small">{r.os || '—'}</span> },
                { key: 'status', label: 'Status', render: (r) => <StatusBadge status={r.status} /> },
                { key: 'risk_score', label: 'Risk', render: (r) => <RiskScore value={r.risk_score} />, sortValue: (r) => r.risk_score },
                { key: 'alerts', label: 'Alerts', render: (r) => alertCount(r.hostname), sortable: false },
                { key: 'last_seen', label: 'Last seen', render: (r) => <span className="ts-small ts-muted">{fmtTime(r.last_seen)}</span>, sortValue: (r) => r.last_seen },
              ]}
              rows={req.data.assets} rowKey={(r) => r.hostname} onRowClick={(r) => setOpen(r.hostname)}
            />
      )}
      {open && <AssetDrawer hostname={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

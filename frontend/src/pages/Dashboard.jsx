import React from 'react';
import { useApp } from '../context/AppContext';
import { useApi } from '../hooks/useApi.js';
import { apiGet } from '../services/api/client.js';
import { inRange, MetricCard, PageHeader, SeverityBadge, RiskScore, TimeRangeSelect,
  LoadingState, ConnectionState, fmtTime } from '../components/ui.jsx';
import DataTable from '../components/DataTable.jsx';

function ActivityChart({ alerts }) {
  const buckets = React.useMemo(() => {
    const arr = new Array(24).fill(0);
    alerts.forEach((a) => {
      const t = new Date(a.created_at || a.timestamp || Date.now()).getTime();
      if (Number.isNaN(t)) return;
      const h = Math.floor((Date.now() - t) / 3600000);
      if (h >= 0 && h < 24) arr[23 - h] += 1;
    });
    return arr;
  }, [alerts]);
  const max = Math.max(1, ...buckets);
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 3, height: 120 }} role="img" aria-label="Alert activity, last 24 hours">
      {buckets.map((v, i) => (
        <div key={i} title={`${v} alerts`} style={{ flex: 1, height: `${Math.max(4, (v / max) * 100)}%`,
          background: v > 0 ? 'var(--accent)' : 'var(--bg-surface-2)', borderRadius: 2, opacity: v > 0 ? 0.85 : 1 }} />
      ))}
    </div>
  );
}

function SeverityMix({ alerts }) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const counts = {};
  alerts.forEach((a) => { const s = (a.severity || 'LOW').toUpperCase(); counts[s] = (counts[s] || 0) + 1; });
  const total = Math.max(1, alerts.length);
  const color = { CRITICAL: 'var(--sev-critical)', HIGH: 'var(--sev-high)', MEDIUM: 'var(--sev-medium)', LOW: 'var(--sev-low)' };
  return (
    <div>
      {order.map((s) => (
        <div className="ts-bar-row" key={s}>
          <span className="ts-bar-label">{s}</span>
          <div className="ts-bar-track"><div className="ts-bar-fill" style={{ width: `${((counts[s] || 0) / total) * 100}%`, background: color[s] }} /></div>
          <span className="ts-bar-val">{counts[s] || 0}</span>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const { setCurrentTab, setSelectedIncidentId } = useApp();
  const [range, setRange] = React.useState('24h');
  const dash = useApi(() => apiGet('/api/v1/dashboard'), []);
  const alerts = useApi(() => apiGet('/api/v1/alerts?limit=500'), []);
  const incidents = useApi(() => apiGet('/api/v1/incidents?limit=50'), []);

  if (dash.loading || alerts.loading || incidents.loading) return <LoadingState label="Loading overview…" />;
  if (dash.error) return <ConnectionState error={dash.error} retry={dash.refresh} />;
  if (alerts.error) return <ConnectionState error={alerts.error} retry={alerts.refresh} />;
  if (incidents.error) return <ConnectionState error={incidents.error} retry={incidents.refresh} />;

  const k = dash.data.kpis;
  const rangedAlerts = (alerts.data.alerts || []).filter((a) => inRange(a.created_at, range));
  const openIncidents = incidents.data.incidents || [];
  const crit = openIncidents.filter((i) => i.severity === 'CRITICAL').length;

  const byDetector = {};
  rangedAlerts.forEach((a) => {
    const key = a.detector_type === 'IOC' ? 'Threat Intelligence' : a.detector_type === 'RULE' ? 'Behavioral Detection' : a.detector_type === 'ZERODAY' ? 'Zero-Day ML' : a.detector_type;
    byDetector[key] = (byDetector[key] || 0) + 1;
  });
  const sources = ['Wazuh', 'Zeek', 'Threat Intelligence', 'Behavioral Detection', 'Zero-Day ML'];

  return (
    <div>
      <PageHeader title="Security Operations Overview" sub="ThreatShield · what requires attention right now"
        actions={<TimeRangeSelect value={range} onChange={setRange} />} />

      <div className="ts-kpi-grid">
        <MetricCard label="Alerts" value={rangedAlerts.length} sub={range === '24h' ? 'Last 24 hours' : `Last ${range}`} />
        <MetricCard label="Critical alerts" value={rangedAlerts.filter((a) => a.severity === 'CRITICAL').length} sub="Needs immediate triage" />
        <MetricCard label="Active incidents" value={openIncidents.length} sub={`${crit} critical`} />
        <MetricCard label="Risky assets" value={k.risky_assets ?? k.compromised_assets} sub={`${k.compromised_assets} compromised · ${k.monitored_assets} monitored`} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 12, marginBottom: 12 }}>
        <div className="ts-card ts-card-pad">
          <div className="ts-section-title">Alert activity</div>
          <ActivityChart alerts={rangedAlerts} />
        </div>
        <div className="ts-card ts-card-pad">
          <div className="ts-section-title">Severity distribution</div>
          <SeverityMix alerts={rangedAlerts} />
        </div>
      </div>

      <div className="ts-card ts-card-pad" style={{ marginBottom: 12 }}>
        <div className="ts-section-title">Active incidents</div>
        <DataTable
          columns={[
            { key: 'severity', label: 'Severity', render: (r) => <SeverityBadge severity={r.severity} />, sortValue: (r) => r.severity },
            { key: 'title', label: 'Incident', render: (r) => <span className="ts-row-title">{r.title}</span> },
            { key: 'risk_score', label: 'Risk', render: (r) => <RiskScore value={r.risk_score} />, sortValue: (r) => r.risk_score },
            { key: 'status', label: 'Status', render: (r) => <span className="ts-badge neutral">{r.status}</span> },
            { key: 'created_at', label: 'Time', render: (r) => <span className="ts-small ts-muted">{fmtTime(r.created_at)}</span>, sortValue: (r) => r.created_at },
          ]}
          rows={openIncidents.slice(0, 10)} rowKey={(r) => r.id}
          onRowClick={(r) => { setSelectedIncidentId(r.id); setCurrentTab('investigation'); }}
          emptyTitle="No active incidents" emptyBody="The pipeline has not opened any incidents in range."
        />
      </div>

      <div className="ts-card ts-card-pad">
        <div className="ts-section-title">Detection sources</div>
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
          {sources.map((s) => (
            <div key={s}><span className="ts-muted ts-small">{s}</span>
              <div style={{ fontSize: 18, fontWeight: 700 }}>{byDetector[s] || 0}</div></div>
          ))}
        </div>
      </div>
    </div>
  );
}

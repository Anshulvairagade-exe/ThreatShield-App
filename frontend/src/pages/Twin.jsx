import React from 'react';
import { useApi } from '../hooks/useApi.js';
import { apiGet } from '../services/api/client.js';
import { ConnectionState, Drawer, EmptyState, fmtTime, LoadingState, PageHeader, RiskScore, StatusBadge } from '../components/ui.jsx';

const STATE_COLOR = { healthy: '#46A758', suspicious: '#FFC53D', compromised: '#E5484D', isolated: '#8E9AAF', offline: '#8E9AAF' };
const stateColor = (s) => STATE_COLOR[s] || '#8E9AAF';

export default function Twin() {
  const req = useApi(() => apiGet('/api/v1/twin/topology'), []);
  const [selected, setSelected] = React.useState(null);

  const W = 900; const H = 420;
  const nodes = req.data ? req.data.nodes : [];
  const edges = req.data ? req.data.edges : [];
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));

  return (
    <div>
      <PageHeader title="Digital Twin" sub="Enterprise topology from live asset state" />
      {req.loading && <LoadingState label="Loading topology…" />}
      {req.error && <ConnectionState error={req.error} retry={req.refresh} context="the asset store" />}
      {req.data && nodes.length === 0 && (
        <div className="ts-card"><EmptyState title="No topology" body="No assets report state yet. Enroll agents or run the simulator." /></div>
      )}
      {req.data && nodes.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
          <div className="ts-card ts-card-pad">
            <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height: 'auto' }} role="img" aria-label="Enterprise topology">
              {edges.map((e) => {
                const a = byId[e.source]; const b = byId[e.target];
                if (!a || !b) return null;
                const col = e.severity === 'CRITICAL' ? '#E5484D' : e.severity === 'HIGH' ? '#F76B15' : '#3A4654';
                return <line key={e.id} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={col} strokeWidth={e.status === 'active' ? 2 : 1.2} />;
              })}
              {nodes.map((n) => (
                <g key={n.id} onClick={() => setSelected(n)} style={{ cursor: 'pointer' }} role="button" aria-label={`Asset ${n.hostname}`}>
                  <circle cx={n.x} cy={n.y} r={20} fill="var(--bg-surface-2)" stroke={stateColor(n.status)} strokeWidth={2.5} />
                  <circle cx={n.x} cy={n.y} r={5} fill={stateColor(n.status)} />
                  <text x={n.x} y={n.y + 38} textAnchor="middle" fill="var(--text-primary)" fontSize={11} fontWeight={600}>{n.hostname}</text>
                  <text x={n.x} y={n.y + 51} textAnchor="middle" fill="var(--text-muted)" fontSize={10} fontFamily="var(--font-mono)">{n.ip}</text>
                </g>
              ))}
            </svg>
            <div style={{ display: 'flex', gap: 14, marginTop: 8, fontSize: 11.5 }} className="ts-muted">
              {[['healthy', 'Healthy'], ['suspicious', 'Suspicious'], ['compromised', 'Compromised'], ['offline', 'Offline / unknown']].map(([k, l]) => (
                <span key={k}><span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: STATE_COLOR[k], marginRight: 5 }} />{l}</span>
              ))}
            </div>
          </div>
          <div className="ts-card ts-card-pad">
            <div className="ts-section-title">Assets</div>
            {nodes.map((n) => (
              <button key={n.id} onClick={() => setSelected(n)}
                style={{ display: 'flex', width: '100%', justifyContent: 'space-between', alignItems: 'center',
                  background: 'none', border: 'none', borderBottom: '1px solid var(--border-subtle)',
                  padding: '8px 0', cursor: 'pointer', color: 'var(--text-primary)', fontSize: 12.5, textAlign: 'left' }}>
                <span><strong className="font-mono">{n.hostname}</strong><br /><span className="ts-small ts-muted">{n.os || n.type}</span></span>
                <StatusBadge status={n.status} />
              </button>
            ))}
          </div>
        </div>
      )}
      {selected && (
        <Drawer title={selected.hostname} onClose={() => setSelected(null)}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            <StatusBadge status={selected.status} />
            <span className="ts-small ts-muted">Risk <RiskScore value={selected.risk_score} /></span>
          </div>
          <dl className="ts-kv">
            <dt>IP</dt><dd className="font-mono">{selected.ip || '—'}</dd>
            <dt>OS</dt><dd>{selected.os || '—'}</dd>
            <dt>Type</dt><dd>{selected.type || '—'}</dd>
            <dt>Subnet</dt><dd>{selected.subnet || '—'}</dd>
            <dt>User</dt><dd>{selected.user || '—'}</dd>
            <dt>Criticality</dt><dd>{selected.criticality}</dd>
            <dt>Last seen</dt><dd>{fmtTime(selected.last_seen)}</dd>
          </dl>
        </Drawer>
      )}
    </div>
  );
}

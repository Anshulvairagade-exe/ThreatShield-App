import React from 'react';
import { useApp } from '../context/AppContext';

// Compact twin status view for the simulation lab (mock-driven replay state).
const COLOR = { healthy: '#46A758', suspicious: '#FFC53D', compromised: '#E5484D', isolated: '#8E9AAF', active_threat: '#E5484D' };

export default function TwinPreview() {
  const { twinNodes, twinEdges } = useApp();
  return (
    <div className="ts-card ts-card-pad">
      <div className="ts-section-title">Twin state (simulation)</div>
      {twinNodes.map((n) => (
        <div key={n.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0',
          borderBottom: '1px solid var(--border-subtle)', fontSize: 12.5 }}>
          <span style={{ width: 9, height: 9, borderRadius: '50%', background: COLOR[n.status] || '#8E9AAF' }} />
          <strong className="font-mono">{n.name || n.id}</strong>
          <span className="ts-muted font-mono">{n.ip}</span>
          <span className="ts-muted" style={{ marginLeft: 'auto' }}>risk {n.riskScore} · {n.status}</span>
        </div>
      ))}
      <div className="ts-small ts-muted" style={{ marginTop: 8 }}>
        Links: {twinEdges.map((e) => `${e.source}→${e.target} (${e.status})`).join(' · ') || '—'}
      </div>
    </div>
  );
}

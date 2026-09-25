import React from 'react';
import { useApi } from '../hooks/useApi.js';
import { apiGet } from '../services/api/client.js';
import { ConnectionState, Drawer, EmptyState, LoadingState, PageHeader } from '../components/ui.jsx';

function TechniqueDrawer({ techniqueId, onClose }) {
  const detail = useApi(() => apiGet(`/api/v1/mitre/${encodeURIComponent(techniqueId)}`), [techniqueId]);
  return (
    <Drawer title={techniqueId} onClose={onClose}>
      {detail.loading && <LoadingState />}
      {detail.error && <ConnectionState error={detail.error} retry={detail.refresh} context="the MITRE store" />}
      {detail.data && (() => { const t = detail.data; return (
        <div>
          <div style={{ fontSize: 14, fontWeight: 650, marginBottom: 2 }}>{t.technique_name}</div>
          <div className="ts-small ts-muted" style={{ marginBottom: 12 }}>{t.tactic}</div>
          {t.description && <p className="ts-small ts-muted" style={{ marginBottom: 12 }}>{t.description}</p>}
          <dl className="ts-kv">
            <dt>Observed</dt><dd>{t.observed_count} detections</dd>
            <dt>Incidents</dt><dd>{t.incidents.length === 0 ? '—' : t.incidents.map((i) => i.slice(0, 8)).join(', ')}</dd>
            <dt>Rules</dt><dd>{t.rules.length === 0 ? '—' : t.rules.map((r) => r.rule_id).join(', ')}</dd>
          </dl>
        </div>
      ); })()}
    </Drawer>
  );
}

export default function Mitre() {
  const req = useApi(() => apiGet('/api/v1/mitre'), []);
  const [open, setOpen] = React.useState(null);

  return (
    <div>
      <PageHeader title="MITRE ATT&CK" sub={req.data ? `${req.data.overall_coverage_pct}% technique coverage across 12 tactics` : 'Coverage from live detections'} />
      {req.loading && <LoadingState label="Loading matrix…" />}
      {req.error && <ConnectionState error={req.error} retry={req.refresh} context="the MITRE store" />}
      {req.data && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
          {req.data.tactics.map((t) => (
            <div key={t.tactic} className="ts-card ts-card-pad">
              <div style={{ fontSize: 12.5, fontWeight: 650, marginBottom: 2 }}>{t.tactic}</div>
              <div className="ts-small ts-muted" style={{ marginBottom: 8 }}>{t.coverage_pct}% covered</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {t.techniques.map((tech) => (
                  <button key={tech.technique_id} onClick={() => setOpen(tech.technique_id)}
                    title={`${tech.name} · ${tech.observed_count} observations`}
                    style={{
                      fontFamily: 'var(--font-mono)', fontSize: 11, padding: '3px 8px', cursor: 'pointer',
                      borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-card)',
                      background: tech.observed_count > 0 ? 'var(--sev-critical-bg)' : 'var(--bg-surface-2)',
                      color: tech.observed_count > 0 ? 'var(--sev-critical)' : 'var(--text-secondary)',
                    }}>
                    {tech.technique_id}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
      {open && <TechniqueDrawer techniqueId={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

import React from 'react';
import { useApp } from '../context/AppContext';
import { useApi } from '../hooks/useApi.js';
import { apiGet, apiPatch, apiPost } from '../services/api/client.js';
import { assignIncident, getInvestigation, setIncidentStatus } from '../services/api/incidents.js';
import { ConnectionState, Drawer, EmptyState, ErrorState, fmtTime, LoadingState, Modal,
  PageHeader, RiskScore, SeverityBadge, StatusBadge, Tabs } from '../components/ui.jsx';

function AttackGraph({ relatedEvents }) {
  // Linear attack progression derived from the incident timeline.
  const nodes = (relatedEvents || []).map((e, i) => ({
    id: e.event_id || i,
    label: e.hostname || 'unknown host',
    sub: `${e.event_type}${e.detections && e.detections.length ? ` · ${e.detections.length} signal${e.detections.length > 1 ? 's' : ''}` : ''}`,
  }));
  if (nodes.length === 0) return <EmptyState title="No attack path" body="No related events to graph." />;
  return (
    <div role="img" aria-label="Attack progression graph">
      {nodes.map((n, i) => (
        <div key={n.id}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '8px 12px',
            border: '1px solid var(--border-card)', borderRadius: 'var(--radius-md)', background: 'var(--bg-secondary)' }}>
            <span className="font-mono ts-small ts-muted">{String(i + 1).padStart(2, '0')}</span>
            <div><div style={{ fontWeight: 600, fontSize: 12.5 }}>{n.label}</div>
              <div className="ts-small ts-muted">{n.sub}</div></div>
          </div>
          {i < nodes.length - 1 && <div aria-hidden="true" style={{ textAlign: 'center', color: 'var(--text-muted)', lineHeight: 1.2 }}>↓</div>}
        </div>
      ))}
    </div>
  );
}

function OverviewTab({ inv }) {
  const layers = {};
  (inv.detections || []).forEach((d) => { layers[d.detector_type] = (layers[d.detector_type] || 0) + 1; });
  const zd = (inv.detections || []).find((d) => d.detector_type === 'ZERODAY');
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      <div className="ts-card ts-card-pad">
        <div className="ts-section-title">Detection summary</div>
        <dl className="ts-kv">
          <dt>Summary</dt><dd>{inv.summary || '—'}</dd>
          <dt>Signals</dt><dd>{Object.entries(layers).map(([k, v]) => `${k} ×${v}`).join(' · ') || '—'}</dd>
          <dt>Risk</dt><dd>{inv.risk_explanation || '—'}</dd>
          <dt>Status</dt><dd><StatusBadge status={inv.status} /></dd>
          <dt>Analyst</dt><dd>{inv.assigned_analyst || 'Unassigned'}</dd>
        </dl>
      </div>
      <div className="ts-card ts-card-pad">
        <div className="ts-section-title">Zero-Day / Anomaly detection</div>
        {!zd && <p className="ts-small ts-muted">No anomaly signal on this incident.</p>}
        {zd && (
          <dl className="ts-kv">
            <dt>Anomaly score</dt><dd className="font-mono">{zd.score}</dd>
            <dt>Decision</dt><dd>{zd.evidence.decision || '—'}</dd>
            {(zd.reasons || []).slice(0, 5).map((r, i) => (
              <React.Fragment key={i}><dt>{i === 0 ? 'Why flagged' : ''}</dt><dd>{r}</dd></React.Fragment>
            ))}
          </dl>
        )}
      </div>
      <div className="ts-card ts-card-pad">
        <div className="ts-section-title">Affected assets ({inv.affected_hosts.length})</div>
        {inv.affected_hosts.map((a) => (
          <div key={a.id} style={{ fontSize: 12.5, marginBottom: 4 }}>
            <strong>{a.hostname}</strong> <span className="ts-muted font-mono">{a.ip} · {a.criticality}</span>
          </div>
        ))}
      </div>
      <div className="ts-card ts-card-pad">
        <div className="ts-section-title">Threat intel matches ({inv.iocs.length})</div>
        {inv.iocs.length === 0 && <p className="ts-small ts-muted">No IOC matches.</p>}
        {inv.iocs.map((o) => (
          <div key={o.id} style={{ fontSize: 12.5, marginBottom: 4 }}>
            <span className="font-mono">{o.ioc}</span>
            <span className="ts-muted"> · rep {o.reputation ?? '—'} · conf {o.confidence ?? '—'}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ResponseTab({ inv, refresh }) {
  const [confirm, setConfirm] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const run = async (kind, target) => {
    setBusy(true);
    try {
      await apiPost(`/api/v1/incidents/${encodeURIComponent(inv.id)}/actions/${kind}`,
        { target, actor: 'analyst', mode: 'SIMULATION' });
      setConfirm(null);
      refresh();
    } finally { setBusy(false); }
  };
  const approve = async (id) => {
    await apiPost(`/api/v1/incidents/${encodeURIComponent(inv.id)}/actions/${id}/approve`, { actor: 'analyst' });
    refresh();
  };
  const primary = inv.primary_asset?.hostname || inv.affected_hosts[0]?.hostname || '';
  const firstIoc = inv.iocs[0]?.ioc || '';
  return (
    <div>
      <div className="ts-card ts-card-pad" style={{ marginBottom: 12 }}>
        <div className="ts-section-title">Recommended actions (simulation mode)</div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button className="ts-btn" disabled={!primary || busy}
            onClick={() => setConfirm({ kind: 'isolate', target: primary, title: 'Isolate endpoint', body: `Isolate ${primary}? The host will be marked isolated in SIMULATION mode.` })}>Isolate endpoint</button>
          <button className="ts-btn" disabled={!firstIoc || busy}
            onClick={() => setConfirm({ kind: 'block', target: firstIoc, title: 'Block IOC', body: `Push a perimeter block for ${firstIoc}? SIMULATION mode only.` })}>Block IOC</button>
        </div>
      </div>
      <div className="ts-section-title">Action history</div>
      {(inv.response_actions || []).length === 0 && <p className="ts-small ts-muted">No response actions yet.</p>}
      {(inv.response_actions || []).map((a) => (
        <div key={a.id} className="ts-card ts-card-pad" style={{ marginBottom: 8, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <StatusBadge status={a.status} />
          <strong style={{ fontSize: 12.5 }}>{a.type}</strong>
          <span className="ts-small ts-muted font-mono">{a.target}</span>
          <span className="ts-small ts-muted">{a.mode} · {a.actor}</span>
          {a.status === 'REQUESTED' && (
            <button className="ts-btn small primary" style={{ marginLeft: 'auto' }} onClick={() => approve(a.id)}>Approve</button>
          )}
        </div>
      ))}
      {confirm && (
        <Modal title={confirm.title} body={confirm.body} confirmLabel="Confirm action"
          onCancel={() => setConfirm(null)} onConfirm={() => run(confirm.kind, confirm.target)} />
      )}
    </div>
  );
}

export default function IncidentWorkspace() {
  const { selectedIncidentId, setCurrentTab } = useApp();
  const [tab, setTab] = React.useState('overview');
  const [statusMsg, setStatusMsg] = React.useState('');
  const req = useApi(() => getInvestigation(selectedIncidentId), [selectedIncidentId]);
  const [eventDetail, setEventDetail] = React.useState(null);

  const changeStatus = async (status) => {
    try {
      await setIncidentStatus(selectedIncidentId, status);
      setStatusMsg(`Status → ${status}`);
      req.refresh();
    } catch (e) { setStatusMsg(e.message); }
  };
  const assign = async () => {
    const name = window.prompt('Assign analyst:', 'analyst');
    if (!name) return;
    await assignIncident(selectedIncidentId, name);
    req.refresh();
  };

  if (!selectedIncidentId) {
    return <EmptyState title="No incident selected" body="Open one from Incidents or Alerts." action={<button className="ts-btn" onClick={() => setCurrentTab('incidents')}>Go to Incidents</button>} />;
  }
  if (req.loading) return <LoadingState label="Loading investigation…" />;
  if (req.error) return <ConnectionState error={req.error} retry={req.refresh} context="the investigation store" />;
  const inv = req.data;

  return (
    <div>
      <PageHeader
        title={`${shortTitle(inv)}`}
        sub={`${inv.id.slice(0, 8)} · opened ${fmtTime(inv.created_at)}`}
        actions={<>
          <button className="ts-btn small" onClick={assign}>Assign</button>
          <select className="ts-select" value={inv.status} onChange={(e) => changeStatus(e.target.value)} aria-label="Incident status">
            {['NEW', 'TRIAGED', 'INVESTIGATING', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'CLOSED'].map((s) => <option key={s}>{s}</option>)}
          </select>
        </>}
      />
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14 }}>
        <SeverityBadge severity={inv.severity} />
        <span className="ts-small ts-muted">Risk <RiskScore value={inv.risk_score} /></span>
        <StatusBadge status={inv.status} />
        {statusMsg && <span className="ts-small ts-muted">{statusMsg}</span>}
      </div>

      <Tabs tabs={[
        { id: 'overview', label: 'Overview' }, { id: 'timeline', label: 'Timeline' },
        { id: 'entities', label: 'Entities' }, { id: 'mitre', label: 'MITRE' },
        { id: 'evidence', label: 'Evidence' }, { id: 'response', label: 'Response' },
      ]} active={tab} onChange={setTab} />

      {tab === 'overview' && <OverviewTab inv={inv} />}

      {tab === 'timeline' && (
        <div className="ts-card ts-card-pad">
          <ul className="ts-timeline">
            {inv.timeline.map((t, i) => (
              <li key={i} className={(t.severity || '').toLowerCase()}>
                <div className="ts-tl-time">{fmtTime(t.time)}</div>
                <div className="ts-tl-title">{t.event}</div>
                <div className="ts-tl-sub">{t.source}{t.technique ? ` · ${t.technique}` : ''}</div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {tab === 'entities' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div className="ts-card ts-card-pad">
            <div className="ts-section-title">Hosts & users</div>
            {inv.affected_hosts.map((a) => <div key={a.id} className="ts-small" style={{ marginBottom: 4 }}><strong>{a.hostname}</strong> <span className="ts-muted">{a.ip}</span></div>)}
            {(inv.users || []).map((u) => <div key={u.id} className="ts-small" style={{ marginBottom: 4 }}>👤 {u.name}</div>)}
          </div>
          <div className="ts-card ts-card-pad">
            <div className="ts-section-title">Attack graph</div>
            <AttackGraph relatedEvents={inv.related_events} />
          </div>
        </div>
      )}

      {tab === 'mitre' && (
        <div className="ts-card ts-card-pad">
          {(inv.mitre_techniques || []).map((t) => (
            <div key={t.technique_id} style={{ marginBottom: 8, fontSize: 12.5 }}>
              <span className="font-mono" style={{ color: 'var(--text-code)' }}>{t.technique_id}</span>
              {' '}<strong>{t.technique_name}</strong> <span className="ts-muted">· {t.tactic}</span>
            </div>
          ))}
          {(inv.mitre_techniques || []).length === 0 && <p className="ts-small ts-muted">No techniques mapped.</p>}
        </div>
      )}

      {tab === 'evidence' && (
        <div className="ts-card ts-card-pad">
          <div className="ts-section-title">Detection evidence</div>
          {(inv.detections || []).map((d) => (
            <div key={d.detection_id} style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 12.5 }}><strong>{d.rule_id}</strong> <span className="ts-muted">· {d.detector_type} · <RiskScore value={Math.round((d.score || 0) * 100)} /></span></div>
              {(d.reasons || []).map((r, i) => <div key={i} className="ts-small ts-muted">— {r}</div>)}
              {d.detector_type === 'ZERODAY' && d.evidence && (
                <button className="ts-btn small" style={{ marginTop: 6 }}
                  onClick={() => setEventDetail({ title: 'Zero-Day anomaly detail', body: d.evidence })}>View anomaly detail</button>
              )}
            </div>
          ))}
        </div>
      )}

      {tab === 'response' && <ResponseTab inv={inv} refresh={req.refresh} />}

      {eventDetail && (
        <Drawer title={eventDetail.title} onClose={() => setEventDetail(null)}>
          <pre className="ts-small" style={{ whiteSpace: 'pre-wrap' }}>{JSON.stringify(eventDetail.body, null, 2)}</pre>
        </Drawer>
      )}
    </div>
  );
}

function shortTitle(inv) {
  return inv.title || `Incident ${inv.id.slice(0, 8)}`;
}

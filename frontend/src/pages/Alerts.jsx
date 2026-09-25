import React from 'react';
import { useApp } from '../context/AppContext';
import { useApi } from '../hooks/useApi.js';
import { getAlert, listAlerts } from '../services/api/alerts.js';
import { lookupIocLive } from '../services/api/threatIntel.js';
import { apiPatch } from '../services/api/client.js';
import { Drawer, EmptyState, ErrorState, fmtTime, inRange, LoadingState, ConnectionState,
  PageHeader, RiskScore, SeverityBadge, StatusBadge, TimeRangeSelect } from '../components/ui.jsx';
import DataTable, { Pager } from '../components/DataTable.jsx';

const PAGE_SIZE = 25;

function SignalRow({ label, value, score }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '7px 0', borderBottom: '1px solid var(--border-subtle)', fontSize: 12.5 }}>
      <span>{label}</span>
      <span className="ts-muted">{value}{score != null ? ` · ${score}` : ''}</span>
    </div>
  );
}

function AlertDrawer({ alertId, onClose, onChanged }) {
  const detail = useApi(() => getAlert(alertId), [alertId]);
  const [ioc, setIoc] = React.useState(null);
  const { setCurrentTab, setSelectedIncidentId } = useApp();

  React.useEffect(() => {
    setIoc(null);
    if (detail.data && detail.data.detection.detector_type === 'IOC') {
      const v = detail.data.detection.evidence.ioc;
      if (v) lookupIocLive(v).then(setIoc).catch(() => {});
    }
  }, [detail.data]);

  const setStatus = async (status) => {
    await apiPatch(`/api/v1/alerts/${encodeURIComponent(alertId)}`, { status, actor: 'analyst' });
    onChanged();
    detail.refresh();
  };

  return (
    <Drawer title={detail.data ? `${detail.data.detection.rule_id}` : 'Alert'} onClose={onClose} wide>
      {detail.loading && <LoadingState />}
      {detail.error && <ErrorState message={detail.error} retry={detail.refresh} />}
      {detail.data && (() => { const d = detail.data; const det = d.detection; return (
        <div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}>
            <SeverityBadge severity={det.severity} />
            <StatusBadge status={d.status} />
            <span className="ts-muted ts-small">Risk <RiskScore value={Math.round((det.score || 0) * 100)} /></span>
          </div>

          <h2 className="ts-h2">Detection signals</h2>
          <div style={{ marginBottom: 6 }}>
            <SignalRow label="Detector" value={`${det.detector_type} · ${det.rule_id}`} />
            {(det.reasons || []).map((r, i) => <SignalRow key={i} label={`Signal ${i + 1}`} value={r} />)}
            {det.detector_type === 'ZERODAY' && (
              <SignalRow label="Zero-Day / Anomaly score" value={det.evidence.model_risk_score ?? det.score} />
            )}
          </div>

          {ioc && ioc.found && (
            <>
              <h2 className="ts-h2">Threat intelligence</h2>
              <dl className="ts-kv">
                <dt>IOC</dt><dd className="font-mono">{ioc.ioc}</dd>
                <dt>Reputation</dt><dd>{ioc.reputation ?? '—'}</dd>
                <dt>Confidence</dt><dd>{ioc.confidence ?? '—'}</dd>
                <dt>Sources</dt><dd>{(ioc.sources || []).join(', ') || '—'}</dd>
                <dt>First seen</dt><dd>{fmtTime(ioc.first_seen)}</dd>
                <dt>Last seen</dt><dd>{fmtTime(ioc.last_seen)}</dd>
              </dl>
            </>
          )}

          {d.event && (
            <>
              <h2 className="ts-h2">Related event</h2>
              <dl className="ts-kv">
                <dt>Time</dt><dd>{fmtTime(d.event.timestamp)}</dd>
                <dt>Host</dt><dd>{d.event.hostname || '—'}</dd>
                <dt>Type / Source</dt><dd>{d.event.event_type} · {d.event.source}</dd>
                <dt>User</dt><dd>{d.event.user || '—'}</dd>
                <dt>Network</dt><dd className="font-mono">{[d.event.src_ip, d.event.dest_ip].filter(Boolean).join(' → ') || '—'}</dd>
                {d.event.domain && <><dt>Domain</dt><dd className="font-mono">{d.event.domain}</dd></>}
              </dl>
            </>
          )}

          {d.mitre.length > 0 && (
            <>
              <h2 className="ts-h2">MITRE ATT&amp;CK</h2>
              {d.mitre.map((t) => (
                <div key={t.technique_id} style={{ fontSize: 12.5, marginBottom: 4 }}>
                  <span className="font-mono" style={{ color: 'var(--text-code)' }}>{t.technique_id}</span>
                  <span className="ts-muted"> · {t.name} ({t.tactic})</span>
                </div>
              ))}
            </>
          )}

          <h2 className="ts-h2">Recommended actions</h2>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {d.incident_ids.length > 0 && (
              <button className="ts-btn small primary" onClick={() => { setSelectedIncidentId(d.incident_ids[0]); setCurrentTab('investigation'); }}>
                Investigate incident
              </button>
            )}
            {d.status === 'OPEN' && (
              <button className="ts-btn small" onClick={() => setStatus('ACKED')}>Acknowledge</button>
            )}
            {d.status !== 'CLOSED' && (
              <button className="ts-btn small" onClick={() => setStatus('CLOSED')}>Close alert</button>
            )}
          </div>
        </div>
      ); })()}
    </Drawer>
  );
}

export default function Alerts() {
  const [search, setSearch] = React.useState('');
  const [sev, setSev] = React.useState('');
  const [source, setSource] = React.useState('');
  const [status, setStatus] = React.useState('');
  const [range, setRange] = React.useState('24h');
  const [page, setPage] = React.useState(0);
  const [openId, setOpenId] = React.useState(null);
  const req = useApi(() => listAlerts({ limit: 500 }), []);

  const rows = React.useMemo(() => {
    let list = req.data ? req.data.alerts : [];
    const q = search.trim().toLowerCase();
    return list.filter((a) => {
      if (sev && a.severity !== sev) return false;
      if (status && a.status !== status) return false;
      if (source && a.detector_type !== source) return false;
      if (!inRange(a.created_at, range)) return false;
      if (q && !`${a.rule_id} ${a.event_id} ${a.detector_type}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [req.data, search, sev, source, status, range]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <div>
      <PageHeader title="Alerts" sub="Triage queue · newest first" actions={<TimeRangeSelect value={range} onChange={setRange} />} />
      {req.loading && <LoadingState label="Loading alerts…" />}
      {req.error && <ConnectionState error={req.error} retry={req.refresh} context="the alert stream" />}
      {req.data && (
        <>
          <div className="ts-filterbar" role="search">
            <input className="ts-input" placeholder="Search rule, event, detector…" aria-label="Search alerts"
              value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} />
            <select className="ts-select" value={sev} onChange={(e) => { setSev(e.target.value); setPage(0); }} aria-label="Severity filter">
              <option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
            </select>
            <select className="ts-select" value={source} onChange={(e) => { setSource(e.target.value); setPage(0); }} aria-label="Source filter">
              <option value="">All sources</option><option value="IOC">Threat Intel</option><option value="RULE">Behavioral</option><option value="ZERODAY">Zero-Day ML</option>
            </select>
            <select className="ts-select" value={status} onChange={(e) => { setStatus(e.target.value); setPage(0); }} aria-label="Status filter">
              <option value="">All statuses</option><option>OPEN</option><option>ACKED</option><option>CLOSED</option>
            </select>
          </div>
          <DataTable
            columns={[
              { key: 'created_at', label: 'Time', render: (r) => <span className="ts-small ts-muted">{fmtTime(r.created_at)}</span>, sortValue: (r) => r.created_at },
              { key: 'severity', label: 'Severity', render: (r) => <SeverityBadge severity={r.severity} />, sortValue: (r) => r.severity },
              { key: 'rule_id', label: 'Alert', render: (r) => <span className="ts-row-title">{r.rule_id}</span> },
              { key: 'hostname', label: 'Asset', render: (r) => <span className="ts-small font-mono">{r.hostname || '—'}</span> },
              { key: 'detector_type', label: 'Detection', render: (r) => <span className="ts-small">{r.detector_type}</span> },
              { key: 'score', label: 'Risk', render: (r) => <RiskScore value={Math.round((r.score || 0) * 100)} />, sortValue: (r) => r.score },
              { key: 'status', label: 'Status', render: (r) => <StatusBadge status={r.status} /> },
            ]}
            rows={pageRows} rowKey={(r) => r.id} onRowClick={(r) => setOpenId(r.id)}
            emptyTitle="No alerts match" emptyBody="Adjust filters or widen the time range."
          />
          <Pager page={page} pages={pages} total={rows.length} onPage={setPage} />
        </>
      )}
      {openId && <AlertDrawer alertId={openId} onClose={() => setOpenId(null)} onChanged={req.refresh} />}
    </div>
  );
}

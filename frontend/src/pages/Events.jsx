import React from 'react';
import { useApi } from '../hooks/useApi.js';
import { apiGet } from '../services/api/client.js';
import { ConnectionState, Drawer, EmptyState, fmtTime, inRange, LoadingState,
  PageHeader, TimeRangeSelect } from '../components/ui.jsx';
import DataTable, { Pager } from '../components/DataTable.jsx';

const PAGE_SIZE = 25;

function EventDrawer({ eventId, onClose }) {
  const detail = useApi(() => apiGet(`/api/v1/events/${encodeURIComponent(eventId)}`), [eventId]);
  const doc = detail.data || {};
  const full = doc.full || doc;
  return (
    <Drawer title={`Event ${eventId.slice(0, 8)}`} onClose={onClose}>
      {detail.loading && <LoadingState />}
      {detail.error && <ConnectionState error={detail.error} retry={detail.refresh} context="the event store" />}
      {detail.data && (
        <>
          <dl className="ts-kv">
            <dt>Timestamp</dt><dd>{fmtTime(doc.timestamp || full.timestamp)}</dd>
            <dt>Host</dt><dd>{doc.hostname || full?.asset?.hostname || '—'}</dd>
            <dt>Type / Source</dt><dd>{doc.event_type} · {doc.source}</dd>
            <dt>User</dt><dd>{doc.user || '—'}</dd>
            <dt>Source IP</dt><dd className="font-mono">{doc.src_ip || '—'}</dd>
            <dt>Dest IP</dt><dd className="font-mono">{doc.dest_ip || '—'}</dd>
            <dt>Domain</dt><dd className="font-mono">{doc.domain || '—'}</dd>
          </dl>
          <h2 className="ts-h2">Raw event</h2>
          <pre className="ts-small" style={{ whiteSpace: 'pre-wrap', maxHeight: 320, overflow: 'auto' }}>
            {JSON.stringify(full.raw || full, null, 2)}
          </pre>
        </>
      )}
    </Drawer>
  );
}

export default function Events() {
  const [q, setQ] = React.useState('');
  const [host, setHost] = React.useState('');
  const [etype, setEtype] = React.useState('');
  const [source, setSource] = React.useState('');
  const [range, setRange] = React.useState('24h');
  const [page, setPage] = React.useState(0);
  const [openId, setOpenId] = React.useState(null);
  const req = useApi(() => apiGet('/api/v1/events/search?limit=500'), []);

  const rows = React.useMemo(() => {
    let list = req.data ? req.data.results : [];
    const query = q.trim().toLowerCase();
    return list.filter((e) => {
      if (host && (e.hostname || '') !== host) return false;
      if (etype && e.event_type !== etype) return false;
      if (source && e.source !== source) return false;
      if (!inRange(e.timestamp, range)) return false;
      if (query && !`${e.event_id} ${e.hostname} ${e.user} ${e.src_ip} ${e.dest_ip} ${e.domain}`.toLowerCase().includes(query)) return false;
      return true;
    });
  }, [req.data, q, host, etype, source, range]);

  const hosts = React.useMemo(() => [...new Set((req.data ? req.data.results : []).map((e) => e.hostname).filter(Boolean))].sort(), [req.data]);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));

  return (
    <div>
      <PageHeader title="Events" sub="Telemetry explorer · click a row for structured fields"
        actions={<TimeRangeSelect value={range} onChange={setRange} />} />
      {req.loading && <LoadingState label="Loading events…" />}
      {req.error && <ConnectionState error={req.error} retry={req.refresh} context="the event store" />}
      {req.data && (
        <>
          <div className="ts-filterbar" role="search">
            <input className="ts-input" placeholder="Search host, user, IP, domain…" aria-label="Search events"
              value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} />
            <select className="ts-select" value={host} onChange={(e) => { setHost(e.target.value); setPage(0); }} aria-label="Host filter">
              <option value="">All hosts</option>{hosts.map((h) => <option key={h}>{h}</option>)}
            </select>
            <select className="ts-select" value={etype} onChange={(e) => { setEtype(e.target.value); setPage(0); }} aria-label="Event type filter">
              <option value="">All types</option>
              {['AUTH', 'PROCESS', 'NETWORK', 'DNS', 'FILE', 'WEB', 'FIREWALL', 'ENDPOINT'].map((t) => <option key={t}>{t}</option>)}
            </select>
            <select className="ts-select" value={source} onChange={(e) => { setSource(e.target.value); setPage(0); }} aria-label="Source filter">
              <option value="">All sources</option><option value="simulator">Simulator</option><option value="wazuh">Wazuh</option><option value="zeek">Zeek</option>
            </select>
          </div>
          <DataTable
            columns={[
              { key: 'timestamp', label: 'Timestamp', render: (r) => <span className="ts-small font-mono">{fmtTime(r.timestamp)}</span>, sortValue: (r) => r.timestamp },
              { key: 'hostname', label: 'Host', render: (r) => <strong>{r.hostname || '—'}</strong> },
              { key: 'event_type', label: 'Event', render: (r) => <span className="ts-small">{r.event_type}</span> },
              { key: 'source', label: 'Source', render: (r) => <span className="ts-small">{r.source}</span> },
              { key: 'user', label: 'User', render: (r) => <span className="ts-small">{r.user || '—'}</span> },
              { key: 'ip', label: 'IP', render: (r) => <span className="ts-small font-mono">{r.dest_ip || r.src_ip || '—'}</span> },
            ]}
            rows={rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)} rowKey={(r) => r.event_id}
            onRowClick={(r) => setOpenId(r.event_id)}
            emptyTitle="No events" emptyBody="No telemetry matches the current filters."
          />
          <Pager page={page} pages={pages} total={rows.length} onPage={setPage} />
        </>
      )}
      {openId && <EventDrawer eventId={openId} onClose={() => setOpenId(null)} />}
    </div>
  );
}

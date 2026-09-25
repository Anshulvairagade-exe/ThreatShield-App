import React from 'react';
import { useApi } from '../hooks/useApi.js';
import { apiGet } from '../services/api/client.js';
import { ConnectionState, EmptyState, fmtTime, LoadingState, PageHeader } from '../components/ui.jsx';
import DataTable, { Pager } from '../components/DataTable.jsx';

const PAGE_SIZE = 25;

export default function Audit() {
  const [q, setQ] = React.useState('');
  const [page, setPage] = React.useState(0);
  const req = useApi(() => apiGet('/api/v1/audit?limit=500'), []);

  const rows = React.useMemo(() => {
    let list = req.data ? req.data.logs : [];
    const query = q.trim().toLowerCase();
    if (query) list = list.filter((l) => `${l.actor} ${l.action} ${l.target} ${l.result}`.toLowerCase().includes(query));
    return list;
  }, [req.data, q]);

  return (
    <div>
      <PageHeader title="Audit Log" sub="Every significant operation, who did it, and what happened" />
      {req.loading && <LoadingState label="Loading audit log…" />}
      {req.error && <ConnectionState error={req.error} retry={req.refresh} context="the audit store" />}
      {req.data && (
        <>
          <div className="ts-filterbar" role="search">
            <input className="ts-input" placeholder="Search actor, action, target…" aria-label="Search audit log"
              value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} />
          </div>
          {rows.length === 0
            ? <div className="ts-card"><EmptyState title="No audit entries" body="Actions on incidents, alerts and responses are recorded here." /></div>
            : <>
              <DataTable
                columns={[
                  { key: 'timestamp', label: 'Timestamp', render: (r) => <span className="ts-small font-mono">{fmtTime(r.timestamp)}</span>, sortValue: (r) => r.timestamp },
                  { key: 'actor', label: 'User', render: (r) => r.actor || '—' },
                  { key: 'action', label: 'Action', render: (r) => <span className="ts-row-title font-mono">{r.action}</span> },
                  { key: 'target', label: 'Target', render: (r) => <span className="ts-small font-mono">{r.target || '—'}</span> },
                  { key: 'result', label: 'Result', render: (r) => r.result || '—' },
                  { key: 'incident_id', label: 'Incident', render: (r) => <span className="ts-small font-mono">{r.incident_id ? r.incident_id.slice(0, 8) : '—'}</span> },
                ]}
                rows={rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)} rowKey={(r) => r.id}
              />
              <Pager page={page} pages={Math.max(1, Math.ceil(rows.length / PAGE_SIZE))} total={rows.length} onPage={setPage} />
            </>}
        </>
      )}
    </div>
  );
}

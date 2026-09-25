import React from 'react';
import { useApi } from '../hooks/useApi.js';
import { apiGet, apiPost } from '../services/api/client.js';
import { ConnectionState, EmptyState, fmtTime, LoadingState, Modal, PageHeader, StatusBadge } from '../components/ui.jsx';

async function actionsFor(incidentIds) {
  const out = [];
  for (const id of incidentIds) {
    try {
      const r = await apiGet(`/api/v1/incidents/${encodeURIComponent(id)}/actions`);
      (r.actions || []).forEach((a) => out.push({ ...a, incident_title: id }));
    } catch { /* skip */ }
  }
  return out.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
}

export default function Response() {
  const incidents = useApi(() => apiGet('/api/v1/incidents?limit=200'), []);
  const [actions, setActions] = React.useState(null);
  const [loading, setLoading] = React.useState(true);
  const [confirm, setConfirm] = React.useState(null);

  const load = React.useCallback(async () => {
    if (!incidents.data) return;
    setLoading(true);
    setActions(await actionsFor(incidents.data.incidents.map((i) => i.id)));
    setLoading(false);
  }, [incidents.data]);

  React.useEffect(() => { load(); }, [load]);

  const review = async (action, decision) => {
    await apiPost(`/api/v1/incidents/${encodeURIComponent(action.incident_id)}/actions/${action.id}/${decision === 'approve' ? 'approve' : 'reject'}`, { actor: 'analyst' });
    setConfirm(null);
    load();
  };

  return (
    <div>
      <PageHeader title="Response" sub="Controlled actions · approval enforced · simulation mode default" />
      {incidents.loading && <LoadingState label="Loading incidents…" />}
      {incidents.error && <ConnectionState error={incidents.error} retry={incidents.refresh} context="the incident store" />}
      {incidents.data && loading && <LoadingState label="Loading actions…" />}
      {incidents.data && !loading && (actions || []).length === 0 && (
        <div className="ts-card"><EmptyState title="No response actions" body="Request isolate / block / disable actions from an incident investigation." /></div>
      )}
      {actions && actions.length > 0 && (
        <div className="ts-table-wrap">
          <table className="ts-table">
            <thead><tr><th>Time</th><th>Incident</th><th>Action</th><th>Target</th><th>Approval</th><th>Status</th><th>Analyst</th><th></th></tr></thead>
            <tbody>
              {actions.map((a) => (
                <tr key={a.id}>
                  <td className="ts-small ts-muted">{fmtTime(a.created_at)}</td>
                  <td className="ts-small font-mono">{a.incident_id.slice(0, 8)}</td>
                  <td><strong>{a.type}</strong> <span className="ts-small ts-muted">· {a.mode}</span></td>
                  <td className="ts-small font-mono">{a.target}</td>
                  <td>{a.status === 'REQUESTED' ? <span className="ts-badge neutral">Awaiting approval</span> : <span className="ts-small ts-muted">Decided</span>}</td>
                  <td><StatusBadge status={a.status} /></td>
                  <td className="ts-small">{a.actor || '—'}</td>
                  <td>
                    {a.status === 'REQUESTED' && (
                      <span style={{ display: 'flex', gap: 6 }}>
                        <button className="ts-btn small primary" onClick={() => review(a, 'approve')}>Approve</button>
                        <button className="ts-btn small" onClick={() => setConfirm(a)}>Reject</button>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {confirm && (
        <Modal title="Reject action" body={`Reject ${confirm.type} on ${confirm.target}?`} confirmLabel="Reject"
          onCancel={() => setConfirm(null)} onConfirm={() => review(confirm, 'reject')} />
      )}
    </div>
  );
}

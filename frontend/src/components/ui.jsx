import React from 'react';

const SEV_CLASS = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

export function sevClass(severity) {
  return SEV_CLASS[(severity || '').toUpperCase()] || 'neutral';
}

export function SeverityBadge({ severity }) {
  return <span className={`ts-badge ${sevClass(severity)}`}>{severity || 'Unknown'}</span>;
}

export function StatusBadge({ status }) {
  const s = (status || '').toUpperCase();
  const cls = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(s) ? sevClass(s)
    : ['CLOSED', 'SUCCESS', 'ACKED', 'ACTIVE'].includes(s) ? 'healthy'
    : 'neutral';
  return <span className={`ts-badge ${cls}`}>{status || '—'}</span>;
}

export function RiskScore({ value }) {
  const v = Number(value) || 0;
  const cls = v >= 81 ? 'critical' : v >= 61 ? 'high' : v >= 31 ? 'medium' : 'low';
  return <span className={`ts-risk ${cls}`}>{v}</span>;
}

export function MetricCard({ label, value, sub }) {
  return (
    <div className="ts-card ts-kpi">
      <div className="ts-kpi-label">{label}</div>
      <div className="ts-kpi-value">{value}</div>
      {sub && <div className="ts-kpi-sub">{sub}</div>}
    </div>
  );
}

export function PageHeader({ title, sub, actions }) {
  return (
    <div className="ts-page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
      <div>
        <h1 className="ts-page-title">{title}</h1>
        {sub && <p className="ts-page-sub">{sub}</p>}
      </div>
      {actions && <div style={{ display: 'flex', gap: 8 }}>{actions}</div>}
    </div>
  );
}

export function LoadingState({ label = 'Loading…' }) {
  return <div className="ts-state" role="status" aria-live="polite"><h3>{label}</h3></div>;
}

export function EmptyState({ title = 'No data', body, action }) {
  return (
    <div className="ts-state">
      <h3>{title}</h3>
      {body && <p>{body}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ message = 'Request failed', retry }) {
  return (
    <div className="ts-state" role="alert">
      <h3>Something went wrong</h3>
      <p>{message}</p>
      {retry && <button className="ts-btn" onClick={retry}>Retry</button>}
    </div>
  );
}

export function ConnectionState({ error, retry, context = 'the backend' }) {
  return (
    <div className="ts-state">
      <h3>Backend unavailable</h3>
      <p>Could not reach {context} ({error || 'connection refused'}). Showing no data rather than estimates.</p>
      {retry && <button className="ts-btn" onClick={retry}>Retry connection</button>}
    </div>
  );
}

export function Tabs({ tabs, active, onChange }) {
  return (
    <div className="ts-tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={active === t.id}
          className={`ts-tab${active === t.id ? ' active' : ''}`} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Drawer({ title, onClose, children, wide }) {
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <>
      <div className="ts-overlay" onClick={onClose} />
      <aside className="ts-drawer" role="dialog" aria-modal="true" aria-label={title}
        style={wide ? { width: 'min(720px, 96vw)' } : undefined}>
        <div className="ts-drawer-head">
          <div className="ts-drawer-title">{title}</div>
          <button className="ts-icon-btn" onClick={onClose} aria-label="Close panel">✕</button>
        </div>
        <div className="ts-drawer-body">{children}</div>
      </aside>
    </>
  );
}

export function Modal({ title, body, confirmLabel = 'Confirm', onConfirm, onCancel, danger }) {
  return (
    <>
      <div className="ts-overlay" onClick={onCancel} />
      <div className="ts-modal" role="dialog" aria-modal="true" aria-label={title}>
        <h3>{title}</h3>
        <p>{body}</p>
        <div className="ts-modal-actions">
          <button className="ts-btn" onClick={onCancel}>Cancel</button>
          <button className={`ts-btn ${danger ? 'danger' : 'primary'}`} onClick={onConfirm} autoFocus>
            {confirmLabel}
          </button>
        </div>
      </div>
    </>
  );
}

export function TimeRangeSelect({ value, onChange }) {
  return (
    <select className="ts-select" value={value} onChange={(e) => onChange(e.target.value)} aria-label="Time range">
      <option value="24h">Last 24 hours</option>
      <option value="7d">Last 7 days</option>
      <option value="30d">Last 30 days</option>
    </select>
  );
}

/** Filter Date objects/ISO strings to the selected range. Pass null range to skip. */
export function inRange(ts, range) {
  if (!range || !ts) return true;
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return true;
  const hours = range === '24h' ? 24 : range === '7d' ? 24 * 7 : 24 * 30;
  return Date.now() - t <= hours * 3600 * 1000;
}

export function shortId(id) {
  return id && id.length > 12 ? `${id.slice(0, 8)}…` : (id || '—');
}

export function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
}

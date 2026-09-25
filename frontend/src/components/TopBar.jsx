import React from 'react';
import { useApp } from '../context/AppContext';
import { apiGet, isBackendConfigured } from '../services/api/client.js';
import { triggerRefresh, useEventStream } from '../hooks/useApi.js';

function useHealth() {
  const [health, setHealth] = React.useState(null);
  React.useEffect(() => {
    if (!isBackendConfigured()) return;
    let cancelled = false;
    apiGet('/api/v1/health').then((h) => { if (!cancelled) setHealth(h); }).catch(() => {});
    return () => { cancelled = true; };
  }, []);
  return health;
}

export default function TopBar() {
  const { setCurrentTab, setSelectedIncidentId } = useApp();
  const health = useHealth();
  const live = useEventStream();
  const [query, setQuery] = React.useState('');
  const [results, setResults] = React.useState(null);
  const [searching, setSearching] = React.useState(false);

  const runSearch = async (e) => {
    e.preventDefault();
    const q = query.trim().toLowerCase();
    if (!q || !isBackendConfigured()) { setResults(null); return; }
    setSearching(true);
    try {
      const [incs, alerts, assets] = await Promise.all([
        apiGet('/api/v1/incidents').catch(() => ({ incidents: [] })),
        apiGet('/api/v1/alerts').catch(() => ({ alerts: [] })),
        apiGet('/api/v1/assets').catch(() => ({ assets: [] })),
      ]);
      setResults({
        incidents: (incs.incidents || []).filter((i) =>
          (i.title || '').toLowerCase().includes(q) || (i.id || '').toLowerCase().includes(q)).slice(0, 5),
        alerts: (alerts.alerts || []).filter((a) =>
          (a.rule_id || '').toLowerCase().includes(q)).slice(0, 5),
        assets: (assets.assets || []).filter((a) =>
          (a.hostname || '').toLowerCase().includes(q) || (a.ip || '').includes(q)).slice(0, 5),
      });
    } finally {
      setSearching(false);
    }
  };

  const openIncident = (id) => { setSelectedIncidentId(id); setCurrentTab('investigation'); setResults(null); setQuery(''); };

  return (
    <header className="ts-topbar">
      <div className="ts-topbar-left">
        <span className="ts-env">
          <span className={`ts-conn ${health ? 'ok' : 'down'}`}>
            <span className="dot" />{health ? 'Connected' : 'Offline'}
          </span>
        </span>
        {live && <span className="ts-live"><span className="ts-live-dot" />LIVE</span>}
      </div>
      <form className="ts-search" onSubmit={runSearch} role="search">
        <input className="ts-input" placeholder="Search incidents, alerts, assets…" aria-label="Global search"
          value={query} onChange={(e) => setQuery(e.target.value)} onBlur={() => setTimeout(() => setResults(null), 150)} />
        {results && (
          <div className="ts-search-results">
            {results.incidents.length === 0 && results.alerts.length === 0 && results.assets.length === 0 && (
              <div className="ts-search-empty">No matches</div>
            )}
            {results.incidents.map((i) => (
              <button type="button" key={i.id} onClick={() => openIncident(i.id)}>
                <span className="ts-search-kind">Incident</span> {i.title} <span className="ts-muted">{i.severity}</span>
              </button>
            ))}
            {results.alerts.map((a) => (
              <button type="button" key={a.id} onClick={() => { setCurrentTab('alerts'); setResults(null); }}>
                <span className="ts-search-kind">Alert</span> {a.rule_id} <span className="ts-muted">{a.severity}</span>
              </button>
            ))}
            {results.assets.map((a) => (
              <button type="button" key={a.hostname} onClick={() => { setCurrentTab('assets'); setResults(null); }}>
                <span className="ts-search-kind">Asset</span> {a.hostname} <span className="ts-muted">{a.ip}</span>
              </button>
            ))}
          </div>
        )}
      </form>
      <div className="ts-topbar-right">
        <button className="ts-btn small" onClick={triggerRefresh} aria-label="Refresh current view">
          {searching ? '…' : 'Refresh'}
        </button>
        <span className="ts-user" title="Signed-in analyst">analyst ▾</span>
      </div>
      <style>{`
        .ts-topbar { height: var(--topbar-height); flex-shrink: 0; display: flex; align-items: center; gap: 16px;
          padding: 0 20px; background: var(--bg-secondary); border-bottom: 1px solid var(--border-card); }
        .ts-topbar-left { display: flex; align-items: center; gap: 12px; min-width: 180px; }
        .ts-live { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; font-weight: 700;
          color: var(--sev-healthy); letter-spacing: 0.05em; }
        .ts-search { position: relative; flex: 1; max-width: 520px; }
        .ts-search .ts-input { width: 100%; }
        .ts-search-results { position: absolute; top: 110%; left: 0; right: 0; z-index: 50; background: var(--bg-surface);
          border: 1px solid var(--border-card); border-radius: var(--radius-md); box-shadow: 0 8px 24px rgba(0,0,0,.5);
          max-height: 320px; overflow-y: auto; padding: 4px; }
        .ts-search-results button { display: block; width: 100%; text-align: left; background: none; border: none;
          color: var(--text-primary); font-size: 12.5px; padding: 7px 10px; border-radius: var(--radius-sm); cursor: pointer; }
        .ts-search-results button:hover { background: var(--bg-surface-hover); }
        .ts-search-kind { font-size: 10.5px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-right: 6px; }
        .ts-search-empty { padding: 10px; font-size: 12.5px; color: var(--text-secondary); }
        .ts-topbar-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
        .ts-user { font-size: 12.5px; color: var(--text-secondary); cursor: default; }
      `}</style>
    </header>
  );
}

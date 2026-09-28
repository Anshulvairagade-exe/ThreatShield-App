import React from 'react';
import { useApi } from '../hooks/useApi.js';
import { apiGet } from '../services/api/client.js';
import { liveLookup, lookupIocLive } from '../services/api/threatIntel.js';
import { getInvestigation } from '../services/api/incidents.js';
import { ConnectionState, EmptyState, fmtTime, LoadingState, PageHeader, SeverityBadge } from '../components/ui.jsx';
import DataTable from '../components/DataTable.jsx';

function detectType(v) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip';
  if (/^[a-f\d]{64}$/i.test(v)) return 'hash_sha256';
  if (/^[a-f\d]{40}$/i.test(v)) return 'hash_sha1';
  if (/^[a-f\d]{32}$/i.test(v)) return 'hash_md5';
  if (/^https?:\/\//i.test(v)) return 'url';
  return 'domain';
}

export default function ThreatIntel() {
  const [q, setQ] = React.useState('');
  const [result, setResult] = React.useState(null);
  const [searching, setSearching] = React.useState(false);
  const [searchError, setSearchError] = React.useState(null);
  const [searched, setSearched] = React.useState(false);
  const alerts = useApi(() => apiGet('/api/v1/alerts?limit=500'), []);
  const incidents = useApi(() => apiGet('/api/v1/incidents?limit=200'), []);
  const [linked, setLinked] = React.useState({ alerts: [], incidents: [] });
  const [live, setLive] = React.useState(null);
  const [liveLoading, setLiveLoading] = React.useState(false);

  const search = async (e) => {
    e.preventDefault();
    const v = q.trim();
    if (!v) return;
    setSearching(true); setSearchError(null); setSearched(true);
    setLive(null);
    try {
      const r = await lookupIocLive(v, detectType(v));
      setResult(r);
      if (!r.found) {
        // Repo miss → ask the integrated APIs live. Display-only.
        setLiveLoading(true);
        try { setLive(await liveLookup(v, detectType(v))); }
        catch { setLive(null); }
        finally { setLiveLoading(false); }
      }
      const hitAlerts = (alerts.data ? alerts.data.alerts : []).filter((a) =>
        (a.reasons || []).some((x) => String(x).includes(v)));
      const incs = incidents.data ? incidents.data.incidents : [];
      const hitIncidents = [];
      for (const i of incs) {
        try {
          const inv = await getInvestigation(i.id);
          if ((inv.iocs || []).some((o) => o.ioc === v)) hitIncidents.push(i);
        } catch { /* skip */ }
      }
      setLinked({ alerts: hitAlerts, incidents: hitIncidents });
    } catch (err) {
      setSearchError(err.message);
      setResult(null);
    } finally {
      setSearching(false);
    }
  };

  return (
    <div>
      <PageHeader title="Threat Intelligence" sub="IOC investigation backed by the live repository" />
      <form onSubmit={search} className="ts-filterbar" role="search">
        <input className="ts-input" style={{ minWidth: 320 }} placeholder="IP, domain, URL or hash…"
          aria-label="IOC value" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="ts-btn primary" type="submit" disabled={searching}>{searching ? 'Searching…' : 'Search'}</button>
      </form>

      {searchError && <ConnectionState error={searchError} retry={search} context="the threat-intel repository" />}
      {!searched && !searchError && (
        <div className="ts-card"><EmptyState title="Search an indicator" body="Results show reputation, confidence, sources and linked cases." /></div>
      )}
      {result && !result.found && (
        <div className="ts-card ts-card-pad" style={{ marginBottom: 12 }}>
          <div className="ts-section-title">Repository verdict: not reported</div>
          <p className="ts-small ts-muted" style={{ marginBottom: 0 }}>
            {result.ioc} was never pulled in by any feed — treated as clean unless live sources disagree.
          </p>
        </div>
      )}
      {result && !result.found && (liveLoading || live) && (
        <div className="ts-card ts-card-pad" style={{ marginBottom: 12 }}>
          <div className="ts-section-title">Live verdict · queried now across integrated APIs (not stored)</div>
          {liveLoading && <p className="ts-small ts-muted">Asking AbuseIPDB / AbuseCH / OTX / VirusTotal…</p>}
          {live && (
            <>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
                <SeverityBadge severity={live.verdict === 'malicious' ? 'CRITICAL' : live.verdict === 'clean' ? 'LOW' : 'MEDIUM'} />
                <strong style={{ fontSize: 13 }}>{live.verdict === 'malicious' ? 'Flagged malicious' : live.verdict === 'clean' ? 'No source flags it' : 'Could not check any source'}</strong>
              </div>
              <dl className="ts-kv">
                <dt>Checked</dt><dd>{live.checked.length ? live.checked.join(', ') : '— (missing API keys?)'}</dd>
                {live.flagged_by.length > 0 && <><dt>Flagged by</dt><dd>{live.flagged_by.join(', ')}</dd></>}
                {Object.entries(live.details || {}).map(([src, d]) => (
                  <React.Fragment key={src}><dt>{src}</dt><dd className="ts-small font-mono">{JSON.stringify(d)}</dd></React.Fragment>
                ))}
              </dl>
            </>
          )}
        </div>
      )}
      {result && result.found && (
        <>
          <div className="ts-card ts-card-pad" style={{ marginBottom: 12 }}>
            <div className="ts-section-title font-mono">{result.ioc} <span className="ts-muted">· {result.type}</span></div>
            <dl className="ts-kv">
              <dt>Reputation</dt><dd>{result.reputation ?? '—'}</dd>
              <dt>Confidence</dt><dd>{result.confidence ?? '—'}</dd>
              <dt>Sources</dt><dd>{(result.sources || []).join(', ') || '—'}</dd>
              <dt>Tags</dt><dd>{(result.tags || []).join(', ') || '—'}</dd>
              <dt>MITRE</dt><dd className="font-mono">{(result.mitre || []).join(', ') || '—'}</dd>
              <dt>Status</dt><dd>{result.status || '—'}</dd>
              <dt>First seen</dt><dd>{fmtTime(result.first_seen)}</dd>
              <dt>Last seen</dt><dd>{fmtTime(result.last_seen)}</dd>
            </dl>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div className="ts-card ts-card-pad">
              <div className="ts-section-title">Related alerts ({linked.alerts.length})</div>
              {linked.alerts.length === 0 && <p className="ts-small ts-muted">None.</p>}
              {linked.alerts.slice(0, 10).map((a) => (
                <div key={a.id} className="ts-small" style={{ marginBottom: 4 }}>
                  <SeverityBadge severity={a.severity} /> {a.rule_id}
                </div>
              ))}
            </div>
            <div className="ts-card ts-card-pad">
              <div className="ts-section-title">Related incidents ({linked.incidents.length})</div>
              {linked.incidents.length === 0 && <p className="ts-small ts-muted">None.</p>}
              {linked.incidents.map((i) => (
                <div key={i.id} className="ts-small" style={{ marginBottom: 4 }}><strong>{i.title}</strong> <span className="ts-muted">{i.severity}</span></div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

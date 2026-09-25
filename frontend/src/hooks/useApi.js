import React from 'react';
import { isBackendConfigured } from '../services/api/client.js';

/**
 * useApi(fetchFn, deps) — backend truth with honest states.
 * Returns {data, loading, error, refresh}. When the backend is not
 * configured, error is set immediately so pages render EmptyState.
 * Listens for global 'ts:refresh' (TopBar refresh button / WS events).
 */
export function useApi(fetchFn, deps = []) {
  const [data, setData] = React.useState(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(null);
  const [token, setToken] = React.useState(0);
  const fnRef = React.useRef(fetchFn);
  fnRef.current = fetchFn;

  const refresh = React.useCallback(() => setToken((t) => t + 1), []);

  React.useEffect(() => {
    const onRefresh = () => setToken((t) => t + 1);
    window.addEventListener('ts:refresh', onRefresh);
    return () => window.removeEventListener('ts:refresh', onRefresh);
  }, []);

  React.useEffect(() => {
    let cancelled = false;
    if (!isBackendConfigured()) {
      setLoading(false);
      setError('backend not configured (VITE_API_BASE_URL unset)');
      return;
    }
    setLoading(true);
    setError(null);
    fnRef.current()
      .then((d) => { if (!cancelled) { setData(d); setLoading(false); } })
      .catch((e) => { if (!cancelled) { setError(e.message || 'request failed'); setLoading(false); } });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, ...deps]);

  return { data, loading, error, refresh };
}

export function triggerRefresh() {
  window.dispatchEvent(new CustomEvent('ts:refresh'));
}

/** WebSocket live stream. Returns 'live' | 'off'. Dispatches ts:refresh on messages. */
export function useEventStream() {
  const [live, setLive] = React.useState(false);
  React.useEffect(() => {
    const base = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');
    if (!base) return;
    const url = `${base.replace(/^http/, 'ws')}/api/v1/ws/events`;
    let ws = null; let closed = false;
    try {
      ws = new WebSocket(url);
    } catch { return; }
    ws.onopen = () => { if (!closed) setLive(true); };
    ws.onmessage = () => { if (!closed) triggerRefresh(); };
    ws.onclose = () => { if (!closed) setLive(false); };
    ws.onerror = () => { try { ws.close(); } catch { /* noop */ } };
    return () => { closed = true; try { ws.close(); } catch { /* noop */ } };
  }, []);
  return live;
}

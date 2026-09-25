// Shared fetch client for the ThreatShield backend.
// Base URL comes from VITE_API_BASE_URL (http://localhost:8000 local dev).
// Every helper throws on failure so callers can fall back to mock data
// while the backend is still incomplete.
const BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

export const isBackendConfigured = () => BASE_URL.length > 0;

async function request(path, { method = 'GET', body = null, timeoutMs = 8000 } = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${BASE_URL}${path}`, {
      method,
      signal: controller.signal,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!response.ok) {
      throw new Error(`Backend returned ${response.status} for ${path}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeoutId);
  }
}

export const apiGet = (path, opts) => request(path, { ...opts, method: 'GET' });
export const apiPost = (path, body, opts) => request(path, { ...opts, method: 'POST', body });
export const apiPatch = (path, body, opts) => request(path, { ...opts, method: 'PATCH', body });

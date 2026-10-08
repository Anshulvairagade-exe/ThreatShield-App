// Shared fetch client for the ThreatShield backend.
// Base URL comes from VITE_API_BASE_URL (http://localhost:8000 local dev).
// When unset (Vercel/Netlify portfolio deploy) the UI runs on built-in
// demo data from mockBackend.js — backend code is untouched.
import { mockApiResponse } from '../mockData/mockBackend.js';

const BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

export const isBackendConfigured = () => BASE_URL.length > 0;
export const isDemoMode = () => BASE_URL.length === 0;

async function request(path, { method = 'GET', body = null, timeoutMs = 8000 } = {}) {
  // Frontend-only demo: answer locally, no network.
  if (isDemoMode()) {
    await new Promise((r) => setTimeout(r, 250));
    return mockApiResponse(path, { method, body });
  }
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

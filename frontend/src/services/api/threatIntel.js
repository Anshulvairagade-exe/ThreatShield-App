import { apiGet, apiPost } from './client.js';

// New versioned backend first, legacy :8001 proxy second (handled by caller).
export const lookupIocLive = (value, type = null) => {
  const query = type ? `?type=${encodeURIComponent(type)}` : '';
  return apiGet(`/api/v1/ti/ioc/${encodeURIComponent(value)}${query}`);
};
export const tiStats = () => apiGet('/api/v1/ti/stats');
export const tiRefresh = () => apiPost('/api/v1/ti/refresh', {});

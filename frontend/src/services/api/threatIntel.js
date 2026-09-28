import { apiGet, apiPost } from './client.js';

// Query-param form: path form 404s on values containing slashes
// (servers decode %2F before routing).
export const lookupIocLive = (value, type = null) => {
  const params = new URLSearchParams({ value });
  if (type) params.set('type', type);
  return apiGet(`/api/v1/ti/lookup?${params}`);
};
export const tiStats = () => apiGet('/api/v1/ti/stats');
export const tiRefresh = () => apiPost('/api/v1/ti/refresh', {});
export const liveLookup = (value, type = null) => {
  const params = new URLSearchParams({ value });
  if (type) params.set('type', type);
  return apiGet(`/api/v1/ti/live-lookup?${params}`);
};

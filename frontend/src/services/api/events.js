import { apiGet, apiPost } from './client.js';

export const ingestEvent = (source, raw) =>
  apiPost('/api/v1/pipeline/ingest', { source, raw });
export const searchEvents = (params = {}) => {
  const query = new URLSearchParams(params).toString();
  return apiGet(`/api/v1/events/search${query ? `?${query}` : ''}`);
};
export const getEvent = (id) => apiGet(`/api/v1/events/${encodeURIComponent(id)}`);
export const getDashboard = () => apiGet('/api/v1/dashboard');

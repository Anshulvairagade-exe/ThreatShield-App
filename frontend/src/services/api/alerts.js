import { apiGet, apiPatch } from './client.js';

export const listAlerts = (params = {}) => {
  const query = new URLSearchParams(params).toString();
  return apiGet(`/api/v1/alerts${query ? `?${query}` : ''}`);
};
export const getAlert = (id) => apiGet(`/api/v1/alerts/${encodeURIComponent(id)}`);
export const ackAlert = (id, actor = 'analyst') =>
  apiPatch(`/api/v1/alerts/${encodeURIComponent(id)}`, { status: 'ACKED', actor });
export const listDetections = (params = {}) => {
  const query = new URLSearchParams(params).toString();
  return apiGet(`/api/v1/detections${query ? `?${query}` : ''}`);
};
export const listRules = () => apiGet('/api/v1/rules');

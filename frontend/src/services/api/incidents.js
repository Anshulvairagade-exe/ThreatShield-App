import { apiGet, apiPatch, apiPost } from './client.js';

export const listIncidents = (params = {}) => {
  const query = new URLSearchParams(params).toString();
  return apiGet(`/api/v1/incidents${query ? `?${query}` : ''}`);
};
export const getIncident = (id) => apiGet(`/api/v1/incidents/${encodeURIComponent(id)}`);
export const getInvestigation = (id) => apiGet(`/api/v1/incidents/${encodeURIComponent(id)}/investigation`);
export const getIncidentTimeline = (id) => apiGet(`/api/v1/incidents/${encodeURIComponent(id)}/timeline`);
export const getIncidentEvents = (id) => apiGet(`/api/v1/incidents/${encodeURIComponent(id)}/events`);
export const setIncidentStatus = (id, status, actor = 'analyst') =>
  apiPatch(`/api/v1/incidents/${encodeURIComponent(id)}/status`, { status, actor });
export const assignIncident = (id, analyst, actor = 'analyst') =>
  apiPatch(`/api/v1/incidents/${encodeURIComponent(id)}/assign`, { analyst, actor });
export const isolateHost = (id, target, actor = 'analyst') =>
  apiPost(`/api/v1/incidents/${encodeURIComponent(id)}/actions/isolate`, { target, actor, mode: 'SIMULATION' });
export const blockIoc = (id, target, actor = 'analyst') =>
  apiPost(`/api/v1/incidents/${encodeURIComponent(id)}/actions/block`, { target, actor, mode: 'SIMULATION' });

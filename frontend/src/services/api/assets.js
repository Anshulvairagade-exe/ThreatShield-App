import { apiGet } from './client.js';

export const listAssets = () => apiGet('/api/v1/assets');
export const getAsset = (hostname) => apiGet(`/api/v1/assets/${encodeURIComponent(hostname)}`);
export const getTopology = () => apiGet('/api/v1/twin/topology');

import { apiGet } from './client.js';

export const getMitreMatrix = () => apiGet('/api/v1/mitre');
export const getTechnique = (id) => apiGet(`/api/v1/mitre/${encodeURIComponent(id)}`);

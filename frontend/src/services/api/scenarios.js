import { apiGet, apiPost } from './client.js';

// Scenario engine lands in Phase 11 (backend replay + WebSocket).
// These helpers already point at the final contract; they throw until
// the backend implements it, so Attack Replay keeps its mock behavior.
export const listScenarios = () => apiGet('/api/v1/scenarios');
export const startScenario = (id) => apiPost(`/api/v1/scenarios/${encodeURIComponent(id)}/start`, {});

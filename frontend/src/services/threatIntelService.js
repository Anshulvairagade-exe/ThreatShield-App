function detectIocType(value) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return 'ip';
  if (/^[a-f\d]{32}$/i.test(value)) return 'hash_md5';
  if (/^[a-f\d]{40}$/i.test(value)) return 'hash_sha1';
  if (/^[a-f\d]{64}$/i.test(value)) return 'hash_sha256';
  if (/^https?:\/\//i.test(value)) return 'url';
  return 'domain';
}

import { isBackendConfigured } from './api/client.js';
import { lookupIocLive } from './api/threatIntel.js';

export async function lookupIoc(iocValue, type = null) {
  const cleanVal = iocValue.trim();
  const detectedType = type || detectIocType(cleanVal);

  // Prefer the versioned backend (Phase 10+); fall back to the legacy :8001 proxy.
  if (isBackendConfigured()) {
    try {
      return {
        ...(await lookupIocLive(cleanVal, detectedType)),
        ioc: cleanVal,
        type: detectedType,
        isLiveSource: true
      };
    } catch {
      // fall through to legacy lookup below
    }
  }

  const query = new URLSearchParams({ type: detectedType });
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(`/api/ti/ioc/${encodeURIComponent(cleanVal)}?${query}`, {
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`Threat intelligence API returned ${response.status}`);
    }

    return {
      ...(await response.json()),
      ioc: cleanVal,
      type: detectedType,
      isLiveSource: true
    };
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('Threat intelligence API timed out. Is Member 2\'s API running on port 8001?');
    }
    throw new Error('Unable to reach the threat intelligence API. Start Member 2\'s API on port 8001.');
  } finally {
    clearTimeout(timeoutId);
  }
}

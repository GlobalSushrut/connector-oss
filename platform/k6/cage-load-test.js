/**
 * TraceTramp cage + Connector cage-proof load test (plan Phase 2).
 *
 *   k6 run platform/k6/cage-load-test.js
 *
 * Env:
 *   CONNECTOR_TEST_URL   (default http://127.0.0.1:9091)
 *   CONNECTOR_DEV_TOKEN  (default dev-token)
 *   CAGE_LOAD_SHA        (hex cage address, 40+ chars)
 *   K6_VUS               (default 25)
 *   K6_DURATION          (default 45s)
 */
import http from 'k6/http';
import { check, sleep } from 'k6';

const BASE = (__ENV.CONNECTOR_TEST_URL || 'http://127.0.0.1:9091').replace(/\/$/, '');
const TOKEN = __ENV.CONNECTOR_DEV_TOKEN || 'dev-token';
const SHA =
  __ENV.CAGE_LOAD_SHA ||
  'deadbeef0123456789abcdef0123456789abcdef01';
const AUTH = { Authorization: `Bearer ${TOKEN}` };

export const options = {
  vus: Number(__ENV.K6_VUS || 25),
  duration: __ENV.K6_DURATION || '45s',
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<500', 'p(99)<2000'],
  },
};

export default function () {
  const proof = http.get(`${BASE}/api/v1/plugins/cage-proof`, { headers: AUTH, tags: { name: 'cage-proof' } });
  check(proof, {
    'cage-proof 200': (r) => r.status === 200,
    'cage-proof ok': (r) => {
      try {
        return JSON.parse(r.body).ok === true;
      } catch {
        return false;
      }
    },
  });

  const health = http.get(`${BASE}/plugin/tracetramp/cage/${SHA}/health`, {
    headers: AUTH,
    tags: { name: 'cage-health' },
  });
  check(health, {
    'cage health 2xx': (r) => r.status >= 200 && r.status < 300,
  });

  const bad = http.get(`${BASE}/plugin/tracetramp/cage/not-valid!/health`, {
    headers: AUTH,
    tags: { name: 'cage-invalid' },
  });
  check(bad, {
    'invalid cage 4xx': (r) => r.status >= 400 && r.status < 500,
  });

  sleep(0.05);
}

export function handleSummary(data) {
  const p99 = data.metrics.http_req_duration?.values?.['p(99)'] ?? 0;
  const failed = data.metrics.http_req_failed?.values?.rate ?? 0;
  console.log(`cage-load summary: p99_ms=${p99} failed_rate=${failed}`);
  return {};
}

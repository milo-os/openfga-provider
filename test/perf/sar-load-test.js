/**
 * sar-load-test.js — k6 performance test for the SubjectAccessReview webhook.
 *
 * All environment-specific values are passed via environment variables so
 * this script can target any deployment without modification.
 *
 * Usage (local Kind cluster, managed by Taskfile):
 *   task test:perf
 *
 * Usage (direct, targeting any environment):
 *   k6 run \
 *     -e WEBHOOK_URL=https://webhook.example.com/apis/authorization.k8s.io/v1/subjectaccessreviews \
 *     -e AUTH_TOKEN=<token> \
 *     -e TLS_SKIP_VERIFY=false \
 *     -e PERF_USER_UID=<uid-of-perf-test-user-in-target-env> \
 *     test/perf/sar-load-test.js
 *
 * To forward metrics via OpenTelemetry (e.g., to Victoria Metrics):
 *   k6 run \
 *     -o experimental-opentelemetry \
 *     -e PERF_USER_UID=<uid> \
 *     test/perf/sar-load-test.js
 *
 *   Configure the OTLP endpoint via K6_OTEL_EXPORTER_OTLP_ENDPOINT.
 *   For Kind with Victoria Metrics: defaults to http://localhost:8428 (via port-forward).
 *   Victoria Metrics accepts OTLP at /opentelemetry/api/v1/push on port 8428.
 */

import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

// Guard against missing PERF_USER_UID before any test iteration runs.
// An empty UID causes 100% of SAR requests to fail with "user UID is required".
if (!__ENV.PERF_USER_UID) {
  throw new Error(
    'PERF_USER_UID is required. Run "task test:perf:setup" first to create fixtures ' +
    'and obtain the User UID, then pass it via -e PERF_USER_UID=<uid>.'
  );
}

// ---------------------------------------------------------------------------
// Environment variable inputs with defaults
// ---------------------------------------------------------------------------
const WEBHOOK_URL = __ENV.WEBHOOK_URL ||
  'https://localhost:8090/apis/authorization.k8s.io/v1/subjectaccessreviews';
const AUTH_TOKEN = __ENV.AUTH_TOKEN || '';
const TLS_SKIP_VERIFY = (__ENV.TLS_SKIP_VERIFY || 'true') === 'true';
const PERF_VUS = parseInt(__ENV.PERF_VUS || '10', 10);
const PERF_DURATION = __ENV.PERF_DURATION || '30s';
const PERF_RAMP_UP = __ENV.PERF_RAMP_UP || '5s';
const PERF_USER_UID = __ENV.PERF_USER_UID;
const PERF_ORG_NAME = __ENV.PERF_ORG_NAME || 'perf-test-org';
const ENVIRONMENT = __ENV.ENVIRONMENT || 'kind-local';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const sarCheckFailures = new Counter('sar_check_failures');

// ---------------------------------------------------------------------------
// Test options
// ---------------------------------------------------------------------------
export const options = {
  // Tag all metrics with the environment name so JSON output can be filtered
  // when comparing results across environments.
  tags: {
    environment: ENVIRONMENT,
  },

  stages: [
    // Ramp-up: gradually increase load to avoid cold-start noise skewing
    // the sustained-load measurements.
    { duration: PERF_RAMP_UP, target: PERF_VUS },
    // Sustained load: the measurement window from which p50/p95/p99 are drawn.
    { duration: PERF_DURATION, target: PERF_VUS },
  ],

  // TLS configuration: skip verification for local Kind (self-signed cert from
  // cert-manager). insecureSkipTLSVerify must be in options.tlsAuth or the top-level
  // options object for k6 v0.43+; the per-request params field was removed.
  insecureSkipTLSVerify: TLS_SKIP_VERIFY,

  // Uncomment and tune after establishing baselines:
  // thresholds: {
  //   http_req_duration: ['p(95)<200', 'p(99)<500'],
  //   sar_check_failures: ['count<5'],
  // },
};

// ---------------------------------------------------------------------------
// Request payload — SAR for the allowed path:
//   user perf-test-user performing organizations.get on perf-test-org
// ---------------------------------------------------------------------------
const sarPayload = JSON.stringify({
  apiVersion: 'authorization.k8s.io/v1',
  kind: 'SubjectAccessReview',
  spec: {
    user: 'perf-test-user',
    uid: PERF_USER_UID,
    groups: ['system:authenticated'],
    extra: {
      // The webhook reads this key to scope authorization to the organization.
      // Confirmed from e2e curl commands in test/iam/policy-bindings/chainsaw-test.yaml.
      'resourcemanager.miloapis.com/organization-id': [PERF_ORG_NAME],
    },
    resourceAttributes: {
      group: 'resourcemanager.miloapis.com',
      resource: 'organizations',
      version: 'v1alpha1',
      verb: 'get',
      name: PERF_ORG_NAME,
    },
  },
});

// Build request headers once outside the iteration function for efficiency.
const requestHeaders = {
  'Content-Type': 'application/json',
};
if (AUTH_TOKEN) {
  requestHeaders['Authorization'] = `Bearer ${AUTH_TOKEN}`;
}

// HTTP params shared across all requests.
// TLS skip-verify is configured globally in options.insecureSkipTLSVerify above
// (per-request insecureSkipTLSVerify was removed in k6 v0.43+).
const requestParams = {
  headers: requestHeaders,
};

// ---------------------------------------------------------------------------
// Default function — executed once per virtual user iteration
// ---------------------------------------------------------------------------
export default function () {
  const response = http.post(WEBHOOK_URL, sarPayload, requestParams);

  // Parse the response body once; guard against non-JSON responses.
  let body = null;
  try {
    body = response.json();
  } catch (_) {
    // body remains null; the checks below will fail and increment the counter.
  }

  const passed = check(response, {
    // The webhook writes JSON directly to the ResponseWriter without calling
    // WriteHeader, so Go defaults to 200 for all valid SAR responses (both
    // allowed and denied). HTTP 4xx/5xx indicates a parsing or infra error.
    'HTTP status is 200': (r) => r.status === 200,
    'response body is valid JSON': () => body !== null,
    'response kind is SubjectAccessReview': () =>
      body !== null && body.kind === 'SubjectAccessReview',
    'request was allowed': () =>
      body !== null &&
      body.status !== undefined &&
      body.status.allowed === true,
  });

  if (!passed) {
    sarCheckFailures.add(1);
  }
}

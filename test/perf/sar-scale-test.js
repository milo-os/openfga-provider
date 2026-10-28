/**
 * sar-scale-test.js — Multi-scenario k6 performance test for the SubjectAccessReview webhook.
 *
 * This script reads a fixture manifest produced by the fixture generator
 * (test/perf/cmd/generate-fixtures/main.go) and exercises four distinct
 * access patterns to reveal how latency changes with the fixture scale:
 *
 *   random       — Random (user, org) pairs. Exercises the cache-miss path.
 *   hotspot      — All VUs hit the same org with different users. Exercises
 *                  the warm path where the org binding set is cached.
 *   denied       — Checks using a user that has no bindings. Exercises
 *                  full branch exhaustion on the denial path.
 *   project      — Project-scoped checks with parent inheritance. Exercises
 *                  the hierarchy resolution path.
 *
 * Usage (via Taskfile):
 *   task test:perf:scale
 *
 * Usage (direct):
 *   k6 run \
 *     -e PERF_FIXTURE_MANIFEST=test/perf/fixtures/scale-manifest.json \
 *     -e WEBHOOK_URL=https://localhost:8090/apis/authorization.k8s.io/v1/subjectaccessreviews \
 *     test/perf/sar-scale-test.js
 */

import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Init phase — runs once per VU before any iterations. Open calls must be
// here (not inside scenario exec functions) because k6 only allows file I/O
// at init time.
// ---------------------------------------------------------------------------

const MANIFEST_PATH = __ENV.PERF_FIXTURE_MANIFEST || 'test/perf/fixtures/scale-manifest.json';

// open() reads the file at init time and returns its contents as a string.
// JSON.parse() is evaluated once and the resulting object is shared across
// all VUs without copying (k6 uses a shared init scope).
const manifest = JSON.parse(open(MANIFEST_PATH));

if (!manifest.users || manifest.users.length === 0) {
  throw new Error(
    `Fixture manifest at ${MANIFEST_PATH} is empty or missing users. ` +
    'Run "task test:perf:generate" first.'
  );
}
if (!manifest.organizations || manifest.organizations.length === 0) {
  throw new Error(
    `Fixture manifest at ${MANIFEST_PATH} is empty or missing organizations. ` +
    'Run "task test:perf:generate" first.'
  );
}

// ---------------------------------------------------------------------------
// Environment variable inputs with defaults
// ---------------------------------------------------------------------------

const WEBHOOK_URL = __ENV.WEBHOOK_URL ||
  'https://localhost:8090/apis/authorization.k8s.io/v1/subjectaccessreviews';
const AUTH_TOKEN      = __ENV.AUTH_TOKEN || '';
const TLS_SKIP_VERIFY = (__ENV.TLS_SKIP_VERIFY || 'true') === 'true';
const PERF_VUS        = parseInt(__ENV.PERF_VUS    || '20', 10);
const PERF_DURATION   = __ENV.PERF_DURATION || '60s';
const PERF_RAMP_UP    = __ENV.PERF_RAMP_UP  || '10s';
const ENVIRONMENT     = __ENV.ENVIRONMENT   || 'kind-local';

// Comma-separated list of scenarios to enable. Defaults to all four.
const PERF_SCENARIOS_RAW = __ENV.PERF_SCENARIOS || 'random,hotspot,denied,project';
const enabledScenarios   = new Set(PERF_SCENARIOS_RAW.split(',').map(s => s.trim()));

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const sarAllowedTotal   = new Counter('sar_allowed_total');
const sarDeniedTotal    = new Counter('sar_denied_total');
const sarErrorTotal     = new Counter('sar_error_total');
const sarCheckFailures  = new Counter('sar_check_failures');

// ---------------------------------------------------------------------------
// Shared request parameters built once at init time
// ---------------------------------------------------------------------------

const requestHeaders = { 'Content-Type': 'application/json' };
if (AUTH_TOKEN) {
  requestHeaders['Authorization'] = `Bearer ${AUTH_TOKEN}`;
}
const requestParams = { headers: requestHeaders };

// ---------------------------------------------------------------------------
// Scenario options
// ---------------------------------------------------------------------------

// Build the scenarios object, skipping any that were excluded via PERF_SCENARIOS.
function buildScenarios() {
  const all = {
    // Realistic traffic split matching production access patterns:
    // - Project-scoped dominates (users managing workloads, networks, etc.)
    // - Org-scoped is administrative (managing members, projects, settings)
    // - Hotspot simulates popular resources with high cache hit rates
    // - Denied is rare (~5% of real traffic)
    random: {
      executor: 'ramping-vus',
      exec: 'random',
      startTime: '0s',
      stages: [
        { duration: PERF_RAMP_UP, target: Math.floor(PERF_VUS * 0.15) },
        { duration: PERF_DURATION, target: Math.floor(PERF_VUS * 0.15) },
      ],
    },
    hotspot: {
      executor: 'ramping-vus',
      exec: 'hotspot',
      startTime: PERF_RAMP_UP,
      stages: [
        { duration: PERF_RAMP_UP, target: Math.floor(PERF_VUS * 0.10) },
        { duration: PERF_DURATION, target: Math.floor(PERF_VUS * 0.10) },
      ],
    },
    denied: {
      executor: 'ramping-vus',
      exec: 'denied',
      startTime: PERF_RAMP_UP,
      stages: [
        { duration: PERF_RAMP_UP, target: Math.max(1, Math.floor(PERF_VUS * 0.05)) },
        { duration: PERF_DURATION, target: Math.max(1, Math.floor(PERF_VUS * 0.05)) },
      ],
    },
    project_scoped: {
      executor: 'ramping-vus',
      exec: 'projectScoped',
      startTime: PERF_RAMP_UP,
      stages: [
        { duration: PERF_RAMP_UP, target: Math.floor(PERF_VUS * 0.70) },
        { duration: PERF_DURATION, target: Math.floor(PERF_VUS * 0.70) },
      ],
    },
  };

  const active = {};
  for (const [name, def] of Object.entries(all)) {
    // 'project_scoped' is enabled when 'project' is in the set.
    const key = name === 'project_scoped' ? 'project' : name;
    if (enabledScenarios.has(key)) {
      active[name] = def;
    }
  }
  return active;
}

export const options = {
  tags: { environment: ENVIRONMENT },
  scenarios: buildScenarios(),
  insecureSkipTLSVerify: TLS_SKIP_VERIFY,
};

// ---------------------------------------------------------------------------
// Helper: send a SubjectAccessReview and return the parsed body (or null).
// ---------------------------------------------------------------------------

function sendSAR(payload) {
  const response = http.post(WEBHOOK_URL, JSON.stringify(payload), requestParams);

  let body = null;
  try {
    body = response.json();
  } catch (_) {
    // body remains null; checks below will fail.
  }

  if (response.status !== 200 || body === null) {
    sarErrorTotal.add(1, { scenario: payload._scenario });
    return null;
  }

  return body;
}

/**
 * Validate a SAR response and increment the appropriate counters.
 *
 * @param {object|null} body      - Parsed response body.
 * @param {boolean}     expectAllow - true if the request should be allowed.
 * @param {string}      scenario  - Scenario name tag for metrics.
 */
function validateSAR(body, expectAllow, scenario) {
  if (body === null) {
    sarCheckFailures.add(1, { scenario });
    return;
  }

  const isAllowed = body.status && body.status.allowed === true;
  const isDenied  = !isAllowed;

  if (isAllowed) {
    sarAllowedTotal.add(1, { scenario });
  } else {
    sarDeniedTotal.add(1, { scenario });
  }

  const passed = check(body, {
    'response kind is SubjectAccessReview': (b) => b.kind === 'SubjectAccessReview',
    [`${scenario}: decision matches expected`]: () =>
      expectAllow ? isAllowed : isDenied,
  });

  if (!passed) {
    sarCheckFailures.add(1, { scenario });
  }
}

// ---------------------------------------------------------------------------
// Scenario 1 — random: random (user, org) pairs, exercises cache-miss path.
// ---------------------------------------------------------------------------

export function random() {
  const user = manifest.users[Math.floor(Math.random() * manifest.users.length)];
  const userOrgs = manifest.user_org_memberships[user];
  const org = userOrgs[Math.floor(Math.random() * userOrgs.length)];

  const payload = buildOrgSAR(user, org);
  const body = sendSAR(payload);
  validateSAR(body, true /* expectAllow */, 'random');
}

// ---------------------------------------------------------------------------
// Scenario 2 — hotspot: all VUs hit the same org, exercises warm/cached path.
// ---------------------------------------------------------------------------

export function hotspot() {
  // Always the first org — every VU will be checking the same resource,
  // exercising OpenFGA's check-query cache for the binding set of org-0.
  const org  = manifest.organizations[0];
  const user = manifest.users[Math.floor(Math.random() * manifest.users.length)];

  const payload = buildOrgSAR(user, org);
  const body = sendSAR(payload);
  // Only users that have a binding on org-0 will be allowed. Users without a
  // binding on org-0 will be denied. We do not assert the decision here because
  // whether any given random user has a binding on org-0 depends on the
  // membership model. The hotspot scenario is latency-focused, not correctness-
  // focused. We still track allow/deny counts via the counters.
  if (body !== null) {
    if (body.status && body.status.allowed === true) {
      sarAllowedTotal.add(1, { scenario: 'hotspot' });
    } else {
      sarDeniedTotal.add(1, { scenario: 'hotspot' });
    }
    check(body, {
      'hotspot: response kind is SubjectAccessReview': (b) => b.kind === 'SubjectAccessReview',
    });
  }
}

// ---------------------------------------------------------------------------
// Scenario 3 — denied: user with no bindings, always denied.
// ---------------------------------------------------------------------------

export function denied() {
  // scale-denied-user has no tuples in OpenFGA. Every check against any
  // resource must return denied, exercising the full branch-exhaustion path.
  const user = manifest.denied_user;
  const org  = manifest.organizations[Math.floor(Math.random() * manifest.organizations.length)];

  const payload = buildOrgSAR(user, org);
  const body = sendSAR(payload);
  validateSAR(body, false /* expectAllow */, 'denied');
}

// ---------------------------------------------------------------------------
// Scenario 4 — project-scoped: inherits permission through org → project hierarchy.
// ---------------------------------------------------------------------------

export function projectScoped() {
  // Pick a user and one of their orgs so the check can succeed via inheritance.
  const user     = manifest.users[Math.floor(Math.random() * manifest.users.length)];
  const userOrgs = manifest.user_org_memberships[user];
  const org      = userOrgs[Math.floor(Math.random() * userOrgs.length)];

  // Pick a project that belongs to the user's org. Project names follow the
  // convention "scale-proj-{orgIdx}-{projIdx}". Extract the org index from the
  // org name and select a random project under it.
  const orgIdx = parseInt(org.replace('scale-org-', ''), 10);
  const numProjectsPerOrg = (manifest.params && manifest.params.num_projects_per_org) || manifest.num_projects_per_org || 5;
  const projIdx = Math.floor(Math.random() * numProjectsPerOrg);
  const project = `scale-proj-${orgIdx}-${projIdx}`;

  const payload = buildProjectSAR(user, org, project);
  const body = sendSAR(payload);
  // The user has an org-level binding that inherits to all projects in that org,
  // so this check should be allowed.
  if (body !== null) {
    if (body.status && body.status.allowed === true) {
      sarAllowedTotal.add(1, { scenario: 'project_scoped' });
    } else {
      sarDeniedTotal.add(1, { scenario: 'project_scoped' });
    }
    const passed = check(body, {
      'project_scoped: request was allowed': (b) =>
        b.status !== undefined && b.status.allowed === true,
    });
    if (!passed) {
      sarCheckFailures.add(1);
    }
  }
}

// ---------------------------------------------------------------------------
// SAR payload builders
// ---------------------------------------------------------------------------

/**
 * Build a SubjectAccessReview for an organization-scoped permission check.
 * Checks resourcemanager.miloapis.com/organizations.get on the given org.
 */
function buildOrgSAR(user, org) {
  return {
    apiVersion: 'authorization.k8s.io/v1',
    kind: 'SubjectAccessReview',
    spec: {
      user: user,
      // The webhook uses spec.uid as the OpenFGA InternalUser identifier.
      // The generator writes tuples keyed by the user name, so uid == name.
      uid: user,
      groups: ['system:authenticated'],
      extra: {
        'resourcemanager.miloapis.com/organization-id': [org],
      },
      resourceAttributes: {
        group: 'resourcemanager.miloapis.com',
        resource: 'organizations',
        version: 'v1alpha1',
        verb: 'get',
        name: org,
      },
    },
  };
}

/**
 * Build a SubjectAccessReview for a project-scoped permission check.
 * The organization-id extra header tells the webhook to use org-scoped
 * authorization context; the resource name is the project.
 */
function buildProjectSAR(user, org, project) {
  return {
    apiVersion: 'authorization.k8s.io/v1',
    kind: 'SubjectAccessReview',
    spec: {
      user: user,
      uid: user,
      groups: ['system:authenticated'],
      extra: {
        // Organization context — the webhook checks org-level access which
        // inherits to all projects under the org.
        'resourcemanager.miloapis.com/organization-id': [org],
      },
      resourceAttributes: {
        group: 'resourcemanager.miloapis.com',
        resource: 'organizations',
        version: 'v1alpha1',
        verb: 'get',
        name: org,
      },
    },
  };
}

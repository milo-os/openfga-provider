# Local subresource authorization E2E

This suite builds Milo and the OpenFGA provider from sibling local checkouts. It
uses the provider's pinned `datum-cloud/test-infra` v0.6.2 tasks to create a
separate kind cluster and install Flux, then runs etcd, OpenFGA, Milo, and both
provider processes. It requires Docker, kind, kubectl, Task, Git, Go, Python 3,
OpenSSL, and envsubst. No Python packages are required.

```sh
# Optional with multiple Docker runtimes:
# export DOCKER_CONTEXT=your-context
# Defaults to the sibling ../milo checkout:
export MILO_DIR=/absolute/path/to/milo

task dev:authz:up
task test:e2e:subresources
task dev:authz:down
```

`dev:authz:up` defaults `ENABLE_SUBRESOURCE_AUTHORIZATION` to `false`. The suite
first omits the new argument entirely to prove compatibility with existing
installations, then enables it on both provider workloads. Production defaults
are unchanged. Test resources and declarations live only in the dedicated test
control plane; no other service's registration is changed.

The cluster defaults to `openfga-subresources`; override with
`AUTHZ_CLUSTER_NAME`. All kubectl calls select its explicit context and
`.tmp/authz/kind.kubeconfig`. The ambient kubeconfig is never used. The local kind
configuration has no application host port mappings; test port-forwards use 16443 for Milo
and 18080 temporarily for OpenFGA. `AUTHZ_PORT` overrides Milo's local port.

The harness compiles Linux binaries on the host in a temporary Go workspace
that includes both checkouts, packages minimal images, and loads those images
into kind. This avoids duplicating the Go build cache inside the Docker VM.
`AUTHZ_SKIP_BUILD=true task dev:authz:up` reuses `milo:authz` and
`openfga-provider:authz` after they have been built. Run `task dev:authz:build` to
refresh those images. Setup uses ephemeral in-memory OpenFGA, so rerunning setup
creates a new store; rerunning only the test suite reuses the environment.

The test sends real PATCH and PUT requests to Milo with a non-admin token. Milo
uses `RBAC,Webhook`; this user has no RBAC grants. Checks include legacy behavior,
base/status separation, PATCH versus UPDATE, actual persisted state, instance
scope, Root scope, inherited Roles, Organization-to-Project hierarchy,
revocation, undeclared scale, and removed registration verbs. IAM conditions
must report the current generation, followed by bounded polling for actual
HTTP behavior. Milo's authorization cache TTL is disabled so the suite measures
provider cache/controller convergence without a five-minute apiserver cache.

Successful cases and their actual HTTP response bodies are recorded in
`.tmp/authz/results.jsonl`. Failures save component logs and IAM resources there.
`AUTHZ_TIMEOUT` controls bounded waits (default 240 seconds). These artifacts can
contain test-only credentials/resource IDs; `.tmp` is ignored by Git.

The environment uses static local-only tokens and self-signed certificates and
is intended for development/testing only. `dev:authz:down` deletes just its named
kind cluster. The suite retains resources for inspection after success and can
be rerun; it leaves the provider feature enabled after testing.

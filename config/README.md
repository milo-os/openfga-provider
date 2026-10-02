# Configuration Structure

This directory contains a layered configuration structure that separates concerns between platform infrastructure, application dependencies, and application components.

## Directory Structure

```
config/
├── dependencies/                  # Application-specific infrastructure
│   ├── openfga/                   # Authorization service (app-specific)
│   └── kustomization.yaml         # App dependencies composition
├── base/                          # Core application components
│   ├── services/                  # Application services
│   ├── rbac/                      # Security resources
│   └── kustomization.yaml         # Application composition
├── environments/                  # Environment-specific overlays
│   ├── local-development/         # Local dev environment
│   ├── testing/                   # CI/E2E testing
│   └── production-example/        # Production example (for reference)
├── components/                    # Optional Kustomize components
    ├── tls-certs/                 # TLS certificate configuration
    ├── prometheus-monitoring/     # Metrics and monitoring
    └── network-policies/          # Network security policies

```

## Deployment Layers

### 1. Platform Bootstrap — centralized **datum-cloud/test-infra**

**Purpose**   
Spin-up a fully-featured testing cluster in minutes, identical for every repo.

| Component | Delivered by `test-infra` | Notes |
|-----------|---------------------------|-------|
| Kubernetes (Kind) | `task test-infra:cluster-up` | Single-node Kind cluster on the CI runner |
| Flux CD (v2) | built-in | Installs its own CRDs & controllers |
| cert-manager v1 + CSI driver | Flux HelmReleases | CRDs + controllers, CSI DaemonSet |
| Kyverno | Flux-managed | Admission, background, cleanup, reports controllers |

**Managed by:** the *test-infra* maintainers – **zero** per-application YAML.  
**Frequency:** created & destroyed per-job (ephemeral).

#### How to use it in this repo

```bash
# bootstrap cluster, Flux, cert-manager (+ CSI), Kyverno
task test-infra:cluster-up    # pulls test-infra and sets up the cluster
```

# (optional) load your own image(s)
docker pull ghcr.io/…/my-app:<tag>
kind load docker-image ghcr.io/…/my-app:<tag> --name $(CLUSTER_NAME)

### 2. Dependencies Layer (`dependencies/`)
**Purpose**: External services required by this specific application
**Managed by**: Application teams
**Frequency**: Per application deployment, updated occasionally

Services include:
- OpenFGA (authorization service)
- Application-specific databases (if added)

**Deployment**: `task dev:deploy:dependencies`

### 3. Application Layer (`base/` + `environments/`)
**Purpose**: The core application and environment-specific configurations
**Managed by**: Application teams
**Frequency**: Updated frequently during development

**Deployment**: `task dev:deploy` (includes infrastructure) or `task dev:deploy:fast` (app only)

## Components (Optional Features)

### TLS Certificates (`components/tls-certs/`)

Enables HTTPS for metrics and webhook endpoints using cert-manager. **The component is issuer-agnostic** - certificate issuers are configured per environment.

**Usage:**
```yaml
components:
  - ../../components/tls-certs

# Configure certificate issuers per environment
replacements:
  - source:
      kind: ClusterIssuer
      name: your-environment-issuer
      fieldPath: metadata.name
    targets:
      - select:
          kind: Certificate
          name: webhook-server-cert
        fieldPaths:
          - spec.issuerRef.name
      - select:
          kind: Certificate
          name: metrics-server-cert
        fieldPaths:
          - spec.issuerRef.name
```

**Environment Examples:**

| Environment | Issuer Type | Use Case |
|-------------|-------------|----------|
| Development | Self-signed CA | Local development, fast setup |
| Testing | Self-signed CA | CI/CD, E2E testing |
| Staging | Let's Encrypt Staging | Pre-production validation |
| Production | Let's Encrypt Production | Public endpoints |
| Enterprise | Corporate CA | Internal PKI compliance |

**Features:**
- ✅ HTTPS metrics endpoint (port 8443)
- ✅ TLS webhook certificates
- ✅ Automatic cert-manager integration
- ✅ Environment-specific issuer configuration
- ✅ ServiceMonitor TLS configuration

### Prometheus Monitoring (`components/prometheus-monitoring/`)

Enables Prometheus ServiceMonitor for metrics collection.

**Features:**
- ✅ ServiceMonitor for controller metrics
- ✅ HTTPS support (when used with tls-certs component)
- ✅ Proper RBAC for metrics access

### Network Policies (`components/network-policies/`)

Provides network security isolation and access control.

**Features:**
- ✅ Default deny-all policy
- ✅ Selective metrics access (namespaces with `metrics: enabled`)
- ✅ Webhook traffic controls
- ✅ HTTPS metrics port (8443) support

## Environment Configuration Patterns

### Development (`environments/local-development/`)
- Self-signed certificates for simplicity
- Prometheus monitoring enabled
- Latest image tags
- Single replica deployments

### Testing (`environments/testing/`)
- Self-signed certificates (different CA from dev)
- All security components enabled
- Test image tags
- Network policies for security validation

### Production Example (`environments/production-example/`)
**Note**: This is a reference example. Real production configs are managed by infrastructure teams.

- Let's Encrypt certificates
- High availability (3 replicas)
- Resource limits and requests
- All security components enabled
- Production image tags

## Deployment Options

### Quick Start (All-in-One)
```bash
task test-infra:cluster-up  # Bootstrap cluster and platform infrastructure
task dev:deploy             # Dependencies + Application
```

### Layered Deployment
```bash
task test-infra:cluster-up     # 1. Deploy cluster and platform infrastructure
task dev:deploy:dependencies   # 2. Deploy app dependencies
task dev:deploy:fast           # 3. Deploy application only
```

### Custom Component Selection

Enable/disable components per environment by adding/removing from the `components:` section:

```yaml
components:
  # Core monitoring
  - ../../components/prometheus-monitoring

  # Enable TLS (optional)
  - ../../components/tls-certs

  # Enable network security (optional)
  - ../../components/network-policies
```

## TLS Certificate Management

### Flexible Issuer Configuration

The TLS component separates **certificate creation** from **issuer management**:

1. **Certificate Resources**: Defined in the component (reusable)
2. **Issuer Selection**: Configured per environment using Kustomize replacements
3. **Application Configuration**: Automatically patched for HTTPS

This allows the same certificate component to work with:
- Self-signed certificates (development/testing)
- Let's Encrypt (staging/production)
- Corporate CAs (enterprise environments)
- Any cert-manager compatible issuer

### Certificate Lifecycle

1. **Platform Layer**: Deploys cert-manager cluster-wide
2. **Environment Layer**: Creates appropriate certificate issuers
3. **TLS Component**: Creates certificate resources and configures application
4. **cert-manager**: Issues and manages certificate lifecycle automatically

## Validation

Validate all configurations:
```bash
task validate  # or appropriate validation task
```

This ensures all layers and environments build correctly without deployment.

### Subresource authorization (opt in)

Subresource authorization is **off by default**. Enable it on both the controller
manager and authorization webhook by setting their deployment environment variable
`ENABLE_SUBRESOURCE_AUTHORIZATION` to `"true"`. The base manifests pass this value
to `--enable-subresource-authorization`; when running binaries directly, pass that
flag to both `manager` and `authz-webhook`.

When enabled, declare subresource verbs separately in a `ProtectedResource`:

```yaml
spec:
  permissions: [get, patch, update]
  subresources:
    - name: status
      permissions: [get, patch, update]
```

A role grants `example.com/widgets/status.patch` independently of
`example.com/widgets.patch` and `example.com/widgets/status.update`. Unknown
subresources and undeclared verbs deny access. Permissions bind to the owning
resource and inherit through the existing parent and Root hierarchy. Both model
creation and binding reconciliation use these same registered permissions.

Deploy the additive Milo API schema first. Prepare subresource registrations and
role grants before opting in; existing base grants will no longer authorize
subresource requests once the webhook flag is enabled. Enable the manager first,
wait for model and binding reconciliation, then enable the webhook. Keep the
settings aligned after rollout. Controllers rebuild the model on restart even
when registration generations have not changed. With the flag disabled, the
webhook retains legacy behavior and ignores the SAR subresource; the control
plane excludes subresource permissions from its generated model and tuples.

For rollback, disable the webhook first, then the manager, and wait for both
rollouts and authorization caches to converge. This restores the original
base-permission behavior. This capability does not automatically change service
registrations or service roles.

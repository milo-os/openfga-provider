# Milo OpenFGA Auth Provider

Authorization infrastructure for Milo's business operating system backed by
OpenFGA - enabling fine-grained, relationship-based access control across
business entities like customers, products, agreements, and organizational
resources.

## Overview

This project provides the authorization backbone for the [Milo business
operating system](https://github.com/datum-cloud/milo), which uses Kubernetes
APIServer patterns to manage business entities for product-led B2B companies.
The auth provider bridges Milo's business APIs with OpenFGA's relationship-based
authorization engine to answer complex business questions like:

- *"Can this sales rep view pricing for customers in this project?"*
- *"Can this account manager modify agreements for this organization?"*
- *"Which product features can this customer access based on their
  entitlements?"*

### Key Capabilities

1. **Resource Authorization** - Protects Milo's resources using
   relationship-based policies
2. **Organizational Hierarchies** - Supports complex business structures with
   permission inheritance across organizations and projects
3. **Dynamic Permission Models** - Automatically builds authorization models as
   new resource types are registered in Milo
4. **Real-time Access Control** - Provides webhook-based authorization that
   integrates seamlessly with Milo's Kubernetes-based APIs

## How It Works

1. **Resource Registration**: `ProtectedResource` CRDs define what resources
   should be protected and what permissions are available (view, edit, delete,
   manage)
2. **Authorization Model Sync**: The system automatically builds OpenFGA type
   definitions based on registered resources
3. **Role Management**: `Role` CRDs define roles (Sales Rep, Account Manager)
   with collections of permissions
4. **Access Binding**: `PolicyBinding` CRDs create relationships between
   subjects, roles, and target resources
5. **Runtime Authorization**: Webhook servers evaluate access requests by
   querying OpenFGA relationship graphs
6. **Inheritance Support**: Resources inherit permissions through organizational
   hierarchies (Organization → Project → Customer)

Review the [Architecture](./docs/architecture.md) documentation for more
information.

## Essential Commands

```bash
task dev:setup          # Complete environment setup
task dev:deploy         # Deploy/redeploy application
task dev:status         # Check environment status
task dev:logs           # View application logs
task test               # Run tests
```

## Documentation

- **[Architecture Guide](docs/architecture.md)** - System design, components,
  and data flow
- **[OpenFGA Integration](docs/openfga-integration.md)** - OpenFGA authorization
  model and implementation details

## Project Structure

```
├── config/               # Kubernetes manifests and Kustomize overlays
├── docs/                 # Detailed documentation
├── internal/             # Application logic
│   ├── controller/       # Kubernetes controllers
│   ├── webhook/          # Authorization webhook server
│   └── openfga/          # OpenFGA integration layer
├── cmd/                  # CLI entrypoints (manager, webhook)
└── test/                 # E2E tests
```

## Quick Contributing

1. `task dev:setup` - Set up environment
2. Make your changes
3. `task test && task test:e2e` - Verify changes
4. Submit PR

For detailed guidelines, see [Contributing Guide](docs/contributing.md).

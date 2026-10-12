# AuthzPermissionNotRegistered

**Alert:** `AuthzPermissionNotRegistered`
**Severity:** Warning
**Fires after:** at least 3 refusals for one API group within 15 minutes, held
for 5 minutes

## What this means

The authorization webhook turns each request into a permission, such as
`o11y.miloapis.com/logs/api.get`, and checks it against the authorization model.
When the model holds no such permission, the webhook refuses the request with
`permission '<permission>' not registered`. No role grant can fix that from the
caller's side: every caller gets a 403.

The webhook counts each of these once in `authz_decisions_total` with
`reason="permission_not_registered"`. `decision` is `denied` when subresource
authorization is on and `error` when it is off. The alert ignores `decision`, so
it fires in both modes.

Three API groups refuse a request or two an hour as a matter of course and are
excluded: `coordination.k8s.io`, `notification.miloapis.com` and
`rbac.authorization.k8s.io`. Milo registers no permissions for the two
Kubernetes groups, and the trickle in its own notification group is steady. A
rise in one of those does not fire this alert.

## How to investigate

The commands below assume the default namespace from `config/base`,
`auth-provider-openfga-system`. Substitute the namespace you deploy into.

1. **Find the exact permission.** The webhook logs each refusal as
   `permission not found` with the permission and the request attributes.

   ```sh
   kubectl -n auth-provider-openfga-system logs \
     deploy/auth-provider-openfga-authz-webhook -c authz-webhook --since=30m \
     | grep 'permission not found'
   ```

   `kubectl logs deploy/...` reads one pod. Read each pod if the first shows
   nothing.

2. **See how widespread it is.**

   ```promql
   sum by (resource_group, decision, scope) (
     increase(authz_decisions_total{reason="permission_not_registered"}[1h])
   )
   ```

3. **Decide whether the permission should exist.** A permission for a resource
   or subresource that a service serves must be declared by that service. A
   newly served subresource, or subresource authorization being switched on,
   are the usual causes.

## How to resolve

- **The owning service never declared the permission.** Declare it in that
  service's `ProtectedResource` registration and roll it out, then confirm the
  counter stops rising.
- **A rollout switched on subresource authorization before the permissions
  existed.** Set `--enable-subresource-authorization=false` on the webhook,
  then declare the permissions before switching it on again.
- **The permission should not exist**, for example a client probing an
  unsupported subresource. Find the caller in the logs and fix the client.

## Related

- [authz-decision-reason-missing.md](authz-decision-reason-missing.md), the
  guard that fires when this alert cannot

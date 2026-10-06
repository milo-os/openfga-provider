# AuthzDecisionReasonMissing

**Alert:** `AuthzDecisionReasonMissing`
**Severity:** Warning
**Fires after:** about 35 minutes (30m absence window plus 5m `for`)

## What this means

No `authz_decisions_total` series with a `reason` label has arrived from the
authorization webhook for 30 minutes.
[AuthzPermissionNotRegistered](authz-permission-not-registered.md) selects on
`reason="permission_not_registered"`, so while this fires an authorization
outage caused by an unregistered permission goes unalerted.

The webhook records a `reason` on every decision it counts, so request traffic
keeps these series present. Two things remove them: the webhook is no longer
scraped, or the running provider predates the label, which arrived in v0.7.13.

## How to investigate

The commands below assume the default namespace and names from `config/base`.
Substitute your own if you deploy with a different namespace or name prefix.

1. **Is the webhook scraped?**

   ```promql
   up{job="auth-provider-openfga-authz-webhook"}
   ```

2. **Does it still record decisions, and with which labels?**

   ```promql
   count by (reason) (authz_decisions_total)
   ```

3. **Which provider version is running?**

   ```sh
   kubectl -n auth-provider-openfga-system get deploy \
     auth-provider-openfga-authz-webhook \
     -o jsonpath='{.spec.template.spec.containers[*].image}'
   ```

## How to resolve

- **`up` is missing or zero.** Fix the scrape or the webhook pods first. The
  webhook sits in the request path of every authorization decision.
- **Series exist with no `reason`.** The provider was rolled back below
  v0.7.13, or the label was renamed. Roll the provider forward, or update both
  rules to the new label in the same change.

## Related

- [authz-permission-not-registered.md](authz-permission-not-registered.md), the
  alert this one keeps honest

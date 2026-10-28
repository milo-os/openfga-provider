package openfga

import (
	"context"
	"fmt"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
)

// RoleReconciler manages the OpenFGA representation of Roles.
//
// Under the direct-permission model, permissions are written as individual
// tuples at PolicyBinding reconciliation time (see PolicyReconciler). A Role no
// longer has its own OpenFGA object; its permissions are "inlined" into each
// binding tuple.
//
// When the LegacyRoleBindingModel feature gate is enabled, ReconcileRole
// writes wildcard InternalUser:* permission tuples on an InternalRole object so
// that the old RoleBinding intersection model can resolve them.
type RoleReconciler struct {
	StoreID      string
	OpenFGA      openfgav1.OpenFGAServiceClient
	ControlPlane client.Client
}

// ReconcileRole writes InternalRole permission tuples when the
// LegacyRoleBindingModel feature gate is enabled. When only the
// DirectPermissionTuples gate is enabled this is a no-op because permissions
// are inlined into PolicyBinding tuples at bind time.
func (r *RoleReconciler) ReconcileRole(ctx context.Context, role *iamdatumapiscomv1alpha1.Role) error {
	if !utilfeature.DefaultFeatureGate.Enabled(features.LegacyRoleBindingModel) {
		// Direct-permission model: no InternalRole tuples needed.
		return nil
	}

	return r.reconcileLegacyRole(ctx, role)
}

// reconcileLegacyRole writes wildcard InternalUser:* permission tuples on an
// InternalRole object for the legacy RoleBinding intersection model.
func (r *RoleReconciler) reconcileLegacyRole(ctx context.Context, role *iamdatumapiscomv1alpha1.Role) error {
	// Use Role UID for the object identifier
	roleObjectIdentifier := TypeInternalRole + ":" + string(role.UID)

	existingTupleKeys, err := getTupleKeys(ctx, r.StoreID, r.OpenFGA, &openfgav1.ReadRequestTupleKey{
		Object: roleObjectIdentifier,
	})
	if err != nil {
		return fmt.Errorf("failed to get existing tuples: %w", err)
	}

	allPermissions, err := r.getAllPermissions(ctx, role, nil)
	if err != nil {
		return fmt.Errorf("failed to collect permissions: %w", err)
	}

	expectedTuples := make([]*openfgav1.TupleKey, 0, len(allPermissions))
	for _, permission := range allPermissions {
		expectedTuples = append(
			expectedTuples,
			&openfgav1.TupleKey{
				User:     TypeInternalUser + ":*",
				Relation: hashPermission(permission),
				Object:   roleObjectIdentifier,
			},
		)
	}

	added, removed := diffTuples(existingTupleKeys, expectedTuples)

	if len(added) == 0 && len(removed) == 0 {
		return nil
	}

	req := &openfgav1.WriteRequest{
		StoreId: r.StoreID,
	}

	if len(removed) > 0 {
		req.Deletes = &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(removed),
		}
	}

	if len(added) > 0 {
		req.Writes = &openfgav1.WriteRequestWrites{
			TupleKeys: added,
		}
	}

	_, err = r.OpenFGA.Write(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to reconcile legacy role tuples: %w", err)
	}

	return nil
}

// getAllPermissions recursively collects all permissions for a role, including
// permissions inherited via InheritedRoles, with cycle detection.
func (r *RoleReconciler) getAllPermissions(ctx context.Context, role *iamdatumapiscomv1alpha1.Role, visited map[string]struct{}) ([]string, error) {
	if visited == nil {
		visited = make(map[string]struct{})
	}

	roleIdentifier := role.Namespace + "/" + role.Name
	if _, ok := visited[roleIdentifier]; ok {
		return nil, nil // prevent cycles
	}
	visited[roleIdentifier] = struct{}{}

	permissionSet := make(map[string]struct{})
	for _, p := range role.Spec.IncludedPermissions {
		permissionSet[p] = struct{}{}
	}

	for _, inheritedRoleRef := range role.Spec.InheritedRoles {
		namespace := role.Namespace
		if inheritedRoleRef.Namespace != "" {
			namespace = inheritedRoleRef.Namespace
		}

		inheritedRole := &iamdatumapiscomv1alpha1.Role{}
		if err := r.ControlPlane.Get(ctx, client.ObjectKey{
			Namespace: namespace,
			Name:      inheritedRoleRef.Name,
		}, inheritedRole); err != nil {
			return nil, fmt.Errorf("failed to get inherited role %s/%s: %w", namespace, inheritedRoleRef.Name, err)
		}

		inheritedPerms, err := r.getAllPermissions(ctx, inheritedRole, visited)
		if err != nil {
			return nil, err
		}

		for _, p := range inheritedPerms {
			permissionSet[p] = struct{}{}
		}
	}

	permissions := make([]string, 0, len(permissionSet))
	for p := range permissionSet {
		permissions = append(permissions, p)
	}

	return permissions, nil
}

// DeleteRole removes any legacy InternalRole permission tuples that may have
// been written by a previous version of this reconciler. In a fresh deployment
// with the direct-permission model there will be nothing to delete.
func (r *RoleReconciler) DeleteRole(ctx context.Context, role iamdatumapiscomv1alpha1.Role) error {
	// Use Role UID for the legacy object identifier
	roleObjectIdentifier := TypeInternalRole + ":" + string(role.UID)

	existingTupleKeys, err := getTupleKeys(ctx, r.StoreID, r.OpenFGA, &openfgav1.ReadRequestTupleKey{
		Object: roleObjectIdentifier,
	})
	if err != nil {
		return fmt.Errorf("failed to get existing tuples: %w", err)
	}

	if len(existingTupleKeys) == 0 {
		return nil
	}

	_, err = r.OpenFGA.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.StoreID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(existingTupleKeys),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	return nil
}

package openfga

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RoleReconciler manages the OpenFGA representation of Roles.
//
// Permissions are written as individual tuples at PolicyBinding reconciliation
// time (see PolicyReconciler). ReconcileRole is a no-op since Role permissions
// are inlined into each binding tuple.
type RoleReconciler struct {
	StoreID      string
	OpenFGA      openfgav1.OpenFGAServiceClient
	ControlPlane client.Client
	// ModelIDProvider pins writes to a known authorization model so OpenFGA
	// does not resolve the store's latest model on every call. Optional.
	ModelIDProvider ModelIDProvider
}

// ReconcileRole is a no-op. Permissions are inlined into PolicyBinding tuples
// at bind time.
func (r *RoleReconciler) ReconcileRole(ctx context.Context, role *iamdatumapiscomv1alpha1.Role) error {
	return nil
}

// DeleteRole removes any InternalRole permission tuples associated with the
// given Role. This is called during finalization when a Role is deleted.
func (r *RoleReconciler) DeleteRole(ctx context.Context, role iamdatumapiscomv1alpha1.Role) error {
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
		StoreId:              r.StoreID,
		AuthorizationModelId: ModelIDFrom(r.ModelIDProvider),
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(existingTupleKeys),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	return nil
}

package openfga

import (
	"context"
	"fmt"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

// RoleReconciler manages the OpenFGA representation of Roles.
//
// Under the direct-permission model, permissions are written as individual
// tuples at PolicyBinding reconciliation time (see PolicyReconciler). A Role no
// longer has its own OpenFGA object; its permissions are "inlined" into each
// binding tuple.
//
// ReconcileRole is therefore a no-op for OpenFGA writes. The struct is retained
// so that the controller layer can still call DeleteRole during finalization to
// clean up any legacy InternalRole tuples that may exist from a previous model
// version.
type RoleReconciler struct {
	StoreID      string
	OpenFGA      openfgav1.OpenFGAServiceClient
	ControlPlane client.Client
}

// ReconcileRole is a no-op under the direct-permission model. Previously this
// wrote wildcard InternalUser:* permission tuples on an InternalRole object so
// that the RoleBinding intersection could resolve them. Those tuples are no
// longer needed because permissions are inlined into PolicyBinding tuples.
//
// Keeping this method allows the controller layer to remain unchanged.
func (r *RoleReconciler) ReconcileRole(_ context.Context, _ *iamdatumapiscomv1alpha1.Role) error {
	return nil
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

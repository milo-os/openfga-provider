package controller

import (
	"context"
	"fmt"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	systemGroupFinalizerKey = "iam.miloapis.com/system-group-membership"

	// systemAuthenticatedGroup is the internal group name (post-escape) for
	// system:authenticated. All User resources receive this membership so that
	// authorization checks against InternalUserGroup:system_authenticated resolve
	// correctly via OpenFGA's stored-tuple cache path.
	systemAuthenticatedGroup = "system_authenticated"
)

// SystemGroupReconciler watches User resources and ensures each user has the
// system:authenticated group membership tuple written to OpenFGA. This moves
// tuple writes out of the authorization webhook hot path so that the stored
// tuples are eligible for OpenFGA's check query cache.
type SystemGroupReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users/finalizers,verbs=update

// Reconcile ensures the system:authenticated group membership tuple exists in
// OpenFGA for the reconciled User. On deletion it removes the tuple.
func (r *SystemGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	user := &iamv1alpha1.User{}
	if err := r.Get(ctx, req.NamespacedName, user); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get User: %w", err)
	}

	if user.GetDeletionTimestamp() != nil {
		return r.handleDeletion(ctx, user)
	}

	// Ensure the finalizer is present so we can clean up on deletion.
	if !controllerutil.ContainsFinalizer(user, systemGroupFinalizerKey) {
		controllerutil.AddFinalizer(user, systemGroupFinalizerKey)
		if err := r.Update(ctx, user); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer to User %s: %w", user.Name, err)
		}
		// Re-queue so we proceed with the write after the update is persisted.
		return ctrl.Result{Requeue: true}, nil
	}

	if err := r.writeSystemGroupTuple(ctx, user); err != nil {
		log.Error(err, "failed to write system group membership tuple", "user", user.Name)
		return ctrl.Result{}, err
	}

	log.Info("reconciled system group memberships", "user", user.Name)
	return ctrl.Result{}, nil
}

// handleDeletion removes the system group membership tuple and strips the
// finalizer so the User object can be garbage-collected.
func (r *SystemGroupReconciler) handleDeletion(ctx context.Context, user *iamv1alpha1.User) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(user, systemGroupFinalizerKey) {
		return ctrl.Result{}, nil
	}

	if err := r.deleteSystemGroupTuple(ctx, user); err != nil {
		log.Error(err, "failed to delete system group membership tuple during finalization", "user", user.Name)
		return ctrl.Result{}, err
	}

	controllerutil.RemoveFinalizer(user, systemGroupFinalizerKey)
	if err := r.Update(ctx, user); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to remove finalizer from User %s: %w", user.Name, err)
	}

	log.Info("removed system group memberships on User deletion", "user", user.Name)
	return ctrl.Result{}, nil
}

// writeSystemGroupTuple writes the system:authenticated membership tuple for
// the given user. OpenFGA gRPC code 2017 ("already exists") is treated as
// idempotent success.
func (r *SystemGroupReconciler) writeSystemGroupTuple(ctx context.Context, user *iamv1alpha1.User) error {
	log := logf.FromContext(ctx)

	tupleKey := r.systemGroupTupleKey(user)

	_, err := r.FGAClient.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.FGAStoreID,
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys: []*openfgav1.TupleKey{tupleKey},
		},
	})
	if err != nil {
		if isAlreadyExistsErr(err) {
			log.V(1).Info("system group membership tuple already exists in OpenFGA", "user", user.Name)
			return nil
		}
		return fmt.Errorf("failed to write system group membership tuple for user %s: %w", user.Name, err)
	}

	log.V(1).Info("wrote system group membership tuple", "user", user.Name)
	return nil
}

// deleteSystemGroupTuple deletes the system:authenticated membership tuple for
// the given user. A "not found" response from OpenFGA is treated as success.
func (r *SystemGroupReconciler) deleteSystemGroupTuple(ctx context.Context, user *iamv1alpha1.User) error {
	log := logf.FromContext(ctx)

	tupleKey := r.systemGroupTupleKey(user)

	_, err := r.FGAClient.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.FGAStoreID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: []*openfgav1.TupleKeyWithoutCondition{
				{
					User:     tupleKey.User,
					Relation: tupleKey.Relation,
					Object:   tupleKey.Object,
				},
			},
		},
	})
	if err != nil {
		if isTupleNotFoundErr(err) {
			log.V(1).Info("system group membership tuple already absent from OpenFGA", "user", user.Name)
			return nil
		}
		return fmt.Errorf("failed to delete system group membership tuple for user %s: %w", user.Name, err)
	}

	return nil
}

// systemGroupTupleKey builds the OpenFGA tuple key that represents membership
// of user in the system:authenticated InternalUserGroup. The user's Name (not
// UID) is used as the subject identifier, matching the convention used by
// SystemGroupMaterializer which keyed tuples on the user UID extracted from the
// SubjectAccessReview. Here we use user.Name which is the Kubernetes resource
// name — the same value stored as UID in the SAR (the IAM provider sets the
// SAR user.uid to the User resource name).
func (r *SystemGroupReconciler) systemGroupTupleKey(user *iamv1alpha1.User) *openfgav1.TupleKey {
	return &openfgav1.TupleKey{
		User:     fmt.Sprintf("iam.miloapis.com/InternalUser:%s", user.Name),
		Relation: "member",
		Object:   fmt.Sprintf("iam.miloapis.com/InternalUserGroup:%s", systemAuthenticatedGroup),
	}
}

// isAlreadyExistsErr reports whether the gRPC error indicates that the tuple
// already exists in OpenFGA (code 2017).
func isAlreadyExistsErr(err error) bool {
	if st, ok := status.FromError(err); ok {
		// OpenFGA uses gRPC application error code 2017 for "already exists".
		return st.Code() == 2017
	}
	// Fallback: check the error message for robustness across SDK versions.
	return strings.Contains(err.Error(), "already exists")
}

// isTupleNotFoundErr reports whether the gRPC error indicates that the tuple
// was not found in OpenFGA (code 2018).
func isTupleNotFoundErr(err error) bool {
	if st, ok := status.FromError(err); ok {
		// OpenFGA uses gRPC application error code 2018 for tuple not found.
		return st.Code() == 2018
	}
	return strings.Contains(err.Error(), "not found")
}

// SetupWithManager registers the SystemGroupReconciler with the controller manager.
func (r *SystemGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&iamv1alpha1.User{}).
		Named("systemgroup").
		Complete(r)
}

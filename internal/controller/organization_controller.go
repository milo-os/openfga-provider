package controller

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
)

// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=organizations,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=organizations/finalizers,verbs=update

// OrganizationReconciler holds each Organization with the same finalizer as a
// Project, so an Organization stays in storage, and its name stays taken, until
// no tuple names it, as the object of a grant or as a Project's parent.
type OrganizationReconciler struct {
	client.Client
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
	// Locks is the pool the binding and Project controllers share.
	Locks      *ObjectLocks
	finalizers finalizer.Finalizers
}

// Reconcile adds the finalizer to a live Organization, and clears and
// releases one that is being deleted once Milo's own finalizer has left it.
func (r *OrganizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	org := &resourcemanagerv1alpha1.Organization{}
	if err := r.Get(ctx, req.NamespacedName, org); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !org.DeletionTimestamp.IsZero() {
		if !drained(org) {
			// Milo's finalizer leaving wakes this controller.
			return ctrl.Result{}, nil
		}
		if err := finalizeWhenClear(ctx, r.Locks, r.finalizerLogic(), r.finalizers, org); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to finalize Organization %s: %w", org.Name, err)
		}
		return ctrl.Result{}, nil
	}
	res, err := r.finalizers.Finalize(ctx, org)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to finalize Organization %s: %w", org.Name, err)
	}
	if res.Updated {
		return ctrl.Result{}, r.Update(ctx, org)
	}
	return ctrl.Result{}, nil
}

func (r *OrganizationReconciler) registerFinalizer() error {
	r.finalizers = finalizer.NewFinalizers()
	return r.finalizers.Register(resourceOwnerHierarchyFinalizer, r.finalizerLogic())
}

// finalizerLogic is the finalizer this controller registers, and clears with.
func (r *OrganizationReconciler) finalizerLogic() *ResourceOwnerHierarchyFinalizerLogic {
	return &ResourceOwnerHierarchyFinalizerLogic{Client: r.Client, FGAClient: r.FGAClient, FGAStoreID: r.FGAStoreID}
}

// SetupWithManager registers the controller with the manager.
func (r *OrganizationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Locks == nil {
		return errNoLocks
	}
	if err := r.registerFinalizer(); err != nil {
		return fmt.Errorf("failed to register finalizer: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("organization-controller").
		For(&resourcemanagerv1alpha1.Organization{}).
		Complete(r)
}

// Package controller implements Kubernetes controller-runtime controllers for
// managing Milo IAM resources and their interaction with OpenFGA.
package controller

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// protectedResourceFinalizerKey is the finalizer key added to the
	// ProtectedResource to ensure the type is removed from the OpenFGA
	// authorization model before the ProtectedResource is deleted.
	protectedResourceFinalizerKey = "iam.miloapis.com/protectedresource"
)

// ProtectedResourceFinalizer implements the controller runtime
// finalizer.Finalizer interface to ensure the ProtectedResource type is
// removed from the OpenFGA authorization model before the ProtectedResource
// is deleted.
type ProtectedResourceFinalizer struct {
	client.Client
	modelBuilder *openfga.AuthorizationModelReconciler
}

// Finalize will delete the protected resource from the OpenFGA authorization
// model if the ProtectedResource is being deleted.
func (f *ProtectedResourceFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx)
	pr, ok := obj.(*iamdatumapiscomv1alpha1.ProtectedResource)
	if !ok {
		return finalizer.Result{}, fmt.Errorf("unexpected object type %T, expected ProtectedResource", obj)
	}

	log.Info("Finalizing ProtectedResource, triggering OpenFGA model rebuild", "protectedResourceName", pr.Name)

	var currentPRs iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := f.List(ctx, &currentPRs); err != nil {
		log.Error(err, "Failed to list ProtectedResources during finalization")
		return finalizer.Result{}, fmt.Errorf("failed to list ProtectedResources during finalization: %w", err)
	}

	var activePRs []iamdatumapiscomv1alpha1.ProtectedResource
	for _, item := range currentPRs.Items {
		if item.UID != pr.UID {
			activePRs = append(activePRs, item)
		}
	}
	log.Info("Rebuilding FGA model with remaining ProtectedResources", "count", len(activePRs))

	if err := f.modelBuilder.ReconcileAuthorizationModel(ctx, activePRs); err != nil {
		log.Error(err, "Failed to reconcile authorization model during ProtectedResource finalization")
		return finalizer.Result{}, fmt.Errorf("failed to reconcile FGA model during finalization: %w", err)
	}

	log.Info("Successfully triggered model rebuild during ProtectedResource finalization.", "protectedResourceName", pr.Name)
	return finalizer.Result{}, nil
}

// AuthorizationModelReconciler manages the lifecycle of the IAM authorization
// model. It watches for changes to ProtectedResource custom resources and
// triggers updates to the OpenFGA store to ensure the authorization model
// reflects the state defined by these resources.
type AuthorizationModelReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	FGAClient    openfgav1.OpenFGAServiceClient
	FGAStoreID   string
	modelBuilder *openfga.AuthorizationModelReconciler
	Finalizers   finalizer.Finalizers
}

//+kubebuilder:rbac:groups=iam.miloapis.com,resources=protectedresources,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=iam.miloapis.com,resources=protectedresources/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=iam.miloapis.com,resources=protectedresources/finalizers,verbs=update

// Reconcile is the core reconciliation loop for the
// AuthorizationModelReconciler. It is invoked when changes are detected in
// ProtectedResource custom resources or when a requeue is requested. The method
// orchestrates fetching the resource, handling its deletion, ensuring
// finalizers, or reconciling its active state with the OpenFGA model.
func (r *AuthorizationModelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("controller", "AuthorizationModelReconciler", "trigger", req.NamespacedName)
	log.Info("Reconciling IAM Authorization Model due to ProtectedResource change")

	triggeringPR := &iamdatumapiscomv1alpha1.ProtectedResource{}
	if err := r.Get(ctx, req.NamespacedName, triggeringPR); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Triggering ProtectedResource not found. Assuming it was deleted.", "protectedResourceName", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle setting / removing the finalizer from the resource.
	finalizeResult, err := r.Finalizers.Finalize(ctx, triggeringPR)
	if err != nil {
		log.Error(err, "Finalization process failed for ProtectedResource")
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for ProtectedResource: %w", err)
	}

	if finalizeResult.Updated {
		log.Info("finalizer updated the protected resource, updating API server")
		if updateErr := r.Update(ctx, triggeringPR); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
	}

	if triggeringPR.GetDeletionTimestamp() != nil {
		log.Info("ProtectedResource is marked for deletion, stopping reconciliation")
		return ctrl.Result{}, nil
	}

	return r.reconcileProtectedResource(ctx, triggeringPR)
}

// reconcileProtectedResource performs the main reconciliation for a
// ProtectedResource that is not being deleted. It gathers all current
// ProtectedResource instances to build a complete view of the desired
// authorization state and then triggers the ModelBuilder to apply this state to
// the OpenFGA store.
func (r *AuthorizationModelReconciler) reconcileProtectedResource(ctx context.Context, triggeringPR *iamdatumapiscomv1alpha1.ProtectedResource) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("protectedResourceName", triggeringPR.Name, "operation", "reconcileProtectedResource")
	log.Info("Proceeding with regular reconciliation")

	// Capture the old status before making any changes
	oldStatus := triggeringPR.Status.DeepCopy()

	var prList iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := r.List(ctx, &prList); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list ProtectedResources: %w", err)
	}

	if err := r.modelBuilder.ReconcileAuthorizationModel(ctx, prList.Items); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to reconcile IAM authorization model: %w", err)
	}

	log.Info("Successfully reconciled IAM authorization model.")
	if err := r.updateTriggeringPRStatus(ctx, triggeringPR, oldStatus, true, "IAMSystemConfigured", "Resource is configured to be protected by the IAM system."); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update ProtectedResource status: %w", err)
	}

	return ctrl.Result{}, nil
}

// updateTriggeringPRStatus updates the status subresource of a given
// ProtectedResource. This is used to reflect the outcome of reconciliation
// attempts, providing visibility into whether the resource is correctly
// configured within the IAM system. It sets the ObservedGeneration to match the
// reconciled generation and updates the Ready condition. The status is only
// updated if it differs from the old status to avoid unnecessary API calls.
func (r *AuthorizationModelReconciler) updateTriggeringPRStatus(
	ctx context.Context,
	pr *iamdatumapiscomv1alpha1.ProtectedResource,
	oldStatus *iamdatumapiscomv1alpha1.ProtectedResourceStatus,
	isSuccess bool,
	reasonForCondition string,
	messageForCondition string,
) error {
	log := logf.FromContext(ctx).WithValues("protectedResourceName", pr.Name, "targetSuccess", isSuccess, "reason", reasonForCondition)

	pr.Status.ObservedGeneration = pr.Generation

	conditionStatus := metav1.ConditionFalse
	if isSuccess {
		conditionStatus = metav1.ConditionTrue
	}

	meta.SetStatusCondition(&pr.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  conditionStatus,
		Reason:  reasonForCondition,
		Message: messageForCondition,
	})

	// Only update if the status has actually changed
	if !equality.Semantic.DeepEqual(oldStatus, &pr.Status) {
		if err := r.Status().Update(ctx, pr); err != nil {
			log.Error(err, "Failed to update ProtectedResource status")
			return err
		}
		log.Info("Successfully updated ProtectedResource status.")
	} else {
		log.V(1).Info("ProtectedResource status unchanged; skipping update")
	}
	return nil
}

// SetupWithManager configures the AuthorizationModelReconciler with the
// provided controller manager. This involves setting up watches for
// ProtectedResource custom resources, initializing the OpenFGA model builder if
// necessary, and registering the finalizer implementation.
func (r *AuthorizationModelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.FGAClient == nil {
		return fmt.Errorf("FGAClient is not set on AuthorizationModelReconciler")
	}
	if r.FGAStoreID == "" {
		return fmt.Errorf("FGAStoreID is not set on AuthorizationModelReconciler")
	}

	// Always initialize ModelBuilder internally using the FGAClient and
	// FGAStoreID. This component is responsible for interacting with OpenFGA to
	// reconcile the authorization model.
	r.modelBuilder = &openfga.AuthorizationModelReconciler{
		StoreID: r.FGAStoreID,
		OpenFGA: r.FGAClient,
	}

	// Initialize the finalizer manager and register our custom
	// ProtectedResourceFinalizer. This finalizer is responsible for cleaning up
	// OpenFGA configurations when a ProtectedResource is deleted.
	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(protectedResourceFinalizerKey, &ProtectedResourceFinalizer{
		Client:       r.Client,
		modelBuilder: r.modelBuilder,
	}); err != nil {
		return fmt.Errorf("failed to register protected resource finalizer: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&iamdatumapiscomv1alpha1.ProtectedResource{}).
		Named("authorizationmodel_controller").
		Complete(r)
}

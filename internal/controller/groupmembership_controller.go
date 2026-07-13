package controller

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	groupMembershipFinalizerKey = "iam.miloapis.com/groupmembership"

	ConditionTypeUserRefValid  = "UserRefValid"
	ConditionTypeGroupRefValid = "GroupRefValid"
)

// GroupMembershipReconciler reconciles a GroupMembership object
type GroupMembershipReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	FgaClient           openfgav1.OpenFGAServiceClient
	StoreID             string
	Finalizers          finalizer.Finalizers
	EventRecorder       record.EventRecorder
	UserGroupReconciler *openfga.UserGroupReconciler
}

// UserGroupFinalizer implements the finalizer.Finalizer interface for GroupMembership cleanup.
// This is used to remove the group membership tuple from the OpenFGA store when the GroupMembership is deleted.
type UserGroupFinalizer struct {
	K8sClient           client.Client
	UserGroupReconciler *openfga.UserGroupReconciler
}

func (f *UserGroupFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx)
	groupMembership, ok := obj.(*iammiloapiscomv1alpha1.GroupMembership)
	if !ok {
		return finalizer.Result{}, fmt.Errorf("unexpected object type %T, expected GroupMembership", obj)
	}

	// Fetch the referenced User
	user := &iammiloapiscomv1alpha1.User{}
	err := f.K8sClient.Get(ctx, client.ObjectKey{
		Name: groupMembership.Spec.UserRef.Name,
	}, user)
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to get User for finalization")
		return finalizer.Result{}, err
	}

	// Fetch the referenced Group
	group := &iammiloapiscomv1alpha1.Group{}
	err = f.K8sClient.Get(ctx, client.ObjectKey{
		Name:      groupMembership.Spec.GroupRef.Name,
		Namespace: groupMembership.Spec.GroupRef.Namespace,
	}, group)
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to get Group for finalization")
		return finalizer.Result{}, err
	}

	if group.UID == "" || user.UID == "" {
		log.Info("Group or user is not found, skipping finalization", "groupName", group.Name, "userName", user.Name)
		return finalizer.Result{}, nil
	}

	log.Info("Removing group membership during finalization", "GroupMembership", groupMembership.Name, "groupRef", group.UID, "userRef", user.UID)

	// Remove the group membership tuple from the OpenFGA store
	groupMembershipRequest := openfga.GroupMembershipRequest{
		GroupUID:  group.UID,
		MemberUID: types.UID(user.Name),
	}
	err = f.UserGroupReconciler.RemoveMemberFromGroup(ctx, groupMembershipRequest)
	if err != nil {
		log.Error(err, "Failed to remove group membership during finalization")
		return finalizer.Result{}, err
	}

	log.Info("Successfully finalized GroupMembership (removed from OpenFGA)")
	return finalizer.Result{}, nil
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=groupmemberships,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=groupmemberships/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=groupmemberships/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the GroupMembership object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *GroupMembershipReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling GroupMembership")

	// Get the GroupMembership object
	groupMembership := &iammiloapiscomv1alpha1.GroupMembership{}
	err := r.Get(ctx, req.NamespacedName, groupMembership)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("GroupMembership resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get GroupMembership")
		return ctrl.Result{}, err
	}

	// Capture the old status before making any changes
	oldStatus := groupMembership.Status.DeepCopy()

	// Run the finalizer
	finalizeResult, err := r.Finalizers.Finalize(ctx, groupMembership)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for GroupMembership: %w", err)
	}

	if finalizeResult.Updated {
		log.Info("finalizer updated the group membership object, updating API server")
		if updateErr := r.Update(ctx, groupMembership); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if groupMembership.GetDeletionTimestamp() != nil {
		log.Info("GroupMembership is marked for deletion, stopping reconciliation")
		return ctrl.Result{}, nil
	}

	// Validate UserRef
	user := &iammiloapiscomv1alpha1.User{}
	isUserRefValid, err := r.validateRef(
		ctx,
		user,
		client.ObjectKey{Name: groupMembership.Spec.UserRef.Name},
		ConditionTypeUserRefValid,
		&groupMembership.Status.Conditions,
	)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Validate GroupRef
	group := &iammiloapiscomv1alpha1.Group{}
	isGroupRefValid, err := r.validateRef(
		ctx,
		group,
		client.ObjectKey{
			Name:      groupMembership.Spec.GroupRef.Name,
			Namespace: groupMembership.Spec.GroupRef.Namespace,
		},
		ConditionTypeGroupRefValid,
		&groupMembership.Status.Conditions,
	)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Set Ready condition after both validations
	if !isUserRefValid || !isGroupRefValid {
		log.Info("GroupMembership conditions are not valid",
			"GroupMembership", groupMembership.Name,
			"userRefValid", isUserRefValid,
			"groupRefValid", isGroupRefValid)

		meta.SetStatusCondition(&groupMembership.Status.Conditions, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionFalse,
			Reason:  "ReferenceInvalid",
			Message: fmt.Sprintf("User and/or Group reference are invalid. See %s and %s conditions for details.", ConditionTypeUserRefValid, ConditionTypeGroupRefValid),
		})

		// Only update if the status has actually changed
		if !equality.Semantic.DeepEqual(oldStatus, &groupMembership.Status) {
			err = r.Status().Update(ctx, groupMembership)
			if err != nil {
				log.Error(err, "Failed to update GroupMembership status")
				return ctrl.Result{}, err
			}
			log.V(1).Info("GroupMembership status updated")
		} else {
			log.V(1).Info("GroupMembership status unchanged; skipping update")
		}

		return ctrl.Result{}, nil
	}

	log.Info("GroupMembership conditions are valid. Proceeding with reconciliation.", "userRefValid", isUserRefValid, "groupRefValid", isGroupRefValid)

	// Add the group membership tuple to the OpenFGA store
	groupMembershipRequest := openfga.GroupMembershipRequest{
		GroupUID:  group.UID,
		MemberUID: types.UID(user.Name),
	}
	err = r.UserGroupReconciler.AddMemberToGroup(ctx, groupMembershipRequest)
	if err != nil {
		log.Error(err, "Failed to reconcile group membership")
		r.EventRecorder.Event(groupMembership, "Warning", "OpenFGAError", fmt.Sprintf("Failed to write group membership tuple: %v", err))
		return ctrl.Result{}, fmt.Errorf("failed to write group membership tuple: %w", err)
	}

	// Update status conditions
	meta.SetStatusCondition(&groupMembership.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "Reconciled",
		Message: "Group membership successfully reconciled",
	})

	// Only update if the status has actually changed
	if !equality.Semantic.DeepEqual(oldStatus, &groupMembership.Status) {
		if err := r.Status().Update(ctx, groupMembership); err != nil {
			log.Error(err, "Failed to update GroupMembership status")
			return ctrl.Result{}, err
		}
		log.V(1).Info("GroupMembership status updated")
	} else {
		log.V(1).Info("GroupMembership status unchanged; skipping update")
	}

	log.Info("Successfully reconciled GroupMembership")
	return ctrl.Result{}, nil
}

// validateRef is a helper function that validates a reference to a k8s object
func (r *GroupMembershipReconciler) validateRef(
	ctx context.Context,
	obj client.Object,
	key client.ObjectKey,
	conditionType string,
	conditions *[]metav1.Condition,
) (bool, error) {
	log := logf.FromContext(ctx)
	err := r.Get(ctx, key, obj)
	if err != nil {
		if errors.IsNotFound(err) {
			meta.SetStatusCondition(conditions, metav1.Condition{
				Type:    conditionType,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonValidationFailed,
				Message: fmt.Sprintf("Reference not found: %v", err),
			})
			return false, nil
		}
		log.Error(err, "Failed to get referenced object", "conditionType", conditionType)
		return false, err
	}

	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:    conditionType,
		Status:  metav1.ConditionTrue,
		Reason:  ReasonValidationSuccessful,
		Message: "Reference is valid.",
	})
	return true, nil
}

// GroupMembershipChangeRequest contains the parameters for enqueuing GroupMemberships for changes
type GroupMembershipChangeRequest struct {
	Ctx          context.Context
	Obj          client.Object
	ResourceType string
	FieldName    string
	Namespace    string
}

// enqueueGroupMembershipsForChange is a helper function that returns GroupMembership requests for resource changes
func (r *GroupMembershipReconciler) enqueueGroupMembershipsForChange(req GroupMembershipChangeRequest) []ctrl.Request {
	log := logf.FromContext(req.Ctx)

	log.Info("Enqueuing GroupMemberships for resource change", "resourceType", req.ResourceType, "fieldName", req.FieldName)

	_, ok := req.Obj.(metav1.Object)
	if !ok {
		log.Error(fmt.Errorf("object is not a metav1.Object"), "failed to get metadata")
		return nil
	}

	var groupMembershipList iammiloapiscomv1alpha1.GroupMembershipList
	if err := r.List(req.Ctx, &groupMembershipList, client.InNamespace(req.Namespace)); err != nil {
		log.Error(err, "failed to list GroupMemberships")
		return nil
	}

	log.Info("Processing GroupMemberships for resource change", "resourceType", req.ResourceType, "totalGroupMemberships", len(groupMembershipList.Items))

	var requests []ctrl.Request
	switch req.ResourceType {
	case "user":
		user, ok := req.Obj.(*iammiloapiscomv1alpha1.User)
		if !ok {
			log.Error(fmt.Errorf("expected a User but got a %T", req.Obj), "failed to get User from object")
			return nil
		}
		for _, groupMembership := range groupMembershipList.Items {
			if groupMembership.Spec.UserRef.Name == user.Name {
				requests = append(requests, ctrl.Request{
					NamespacedName: client.ObjectKey{
						Name:      groupMembership.Name,
						Namespace: groupMembership.Namespace,
					},
				})
			}
		}
		log.Info("Requeuing GroupMemberships", "resourceType", req.ResourceType, "name", user.Name, "field", req.FieldName, "requestCount", len(requests))

	case "group":
		group, ok := req.Obj.(*iammiloapiscomv1alpha1.Group)
		if !ok {
			log.Error(fmt.Errorf("expected a Group but got a %T", req.Obj), "failed to get Group from object")
			return nil
		}
		for _, groupMembership := range groupMembershipList.Items {
			if groupMembership.Spec.GroupRef.Name == group.Name && groupMembership.Spec.GroupRef.Namespace == group.Namespace {
				requests = append(requests, ctrl.Request{
					NamespacedName: client.ObjectKey{
						Name:      groupMembership.Name,
						Namespace: groupMembership.Namespace,
					},
				})
			}
		}
		log.Info("Requeuing GroupMemberships", "resourceType", req.ResourceType, "name", fmt.Sprintf("%s/%s", group.Namespace, group.Name), "field", req.FieldName, "requestCount", len(requests))
	}

	return requests
}

// enqueueGroupMembershipsForUserChange returns GroupMembership requests that reference the changed User
func (r *GroupMembershipReconciler) enqueueGroupMembershipsForUserChange(ctx context.Context, obj client.Object) []ctrl.Request {
	return r.enqueueGroupMembershipsForChange(GroupMembershipChangeRequest{
		Ctx:          ctx,
		Obj:          obj,
		ResourceType: "user",
		FieldName:    "userRef",
		Namespace:    "", // "" means all namespaces
	})
}

// enqueueGroupMembershipsForGroupChange returns GroupMembership requests that reference the changed Group
func (r *GroupMembershipReconciler) enqueueGroupMembershipsForGroupChange(ctx context.Context, obj client.Object) []ctrl.Request {
	return r.enqueueGroupMembershipsForChange(GroupMembershipChangeRequest{
		Ctx:          ctx,
		Obj:          obj,
		ResourceType: "group",
		FieldName:    "groupRef",
		Namespace:    obj.GetNamespace(),
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *GroupMembershipReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.UserGroupReconciler = &openfga.UserGroupReconciler{
		StoreID:   r.StoreID,
		Client:    r.FgaClient,
		K8sClient: r.Client,
	}

	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(groupMembershipFinalizerKey, &UserGroupFinalizer{
		K8sClient:           r.Client,
		UserGroupReconciler: r.UserGroupReconciler,
	}); err != nil {
		return fmt.Errorf("failed to register group membership finalizer: %w", err)
	}

	controllerBuilder := ctrl.NewControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.GroupMembership{}).
		Named("groupmembership")

	controllerBuilder.Watches(
		&iammiloapiscomv1alpha1.User{},
		handler.EnqueueRequestsFromMapFunc(r.enqueueGroupMembershipsForUserChange),
		builder.WithPredicates(predicate.GenerationChangedPredicate{}),
	)

	controllerBuilder.Watches(
		&iammiloapiscomv1alpha1.Group{},
		handler.EnqueueRequestsFromMapFunc(r.enqueueGroupMembershipsForGroupChange),
		builder.WithPredicates(predicate.GenerationChangedPredicate{}),
	)

	return controllerBuilder.Complete(r)
}

package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	roleFinalizerKey = "iam.miloapis.com/openfga-role"
)

// parsePermissionString splits a permission string into its components.
// Expected format: <apiGroup>/<resourcePlural>.<permissionName>
// Returns apiGroup, resourcePlural, permName, and a boolean indicating if the format is valid.
func parsePermissionString(permStr string) (string, string, string, bool) {
	parts := strings.SplitN(permStr, "/", 2)
	if len(parts) != 2 {
		return "", "", "", false
	}
	apiGroup := parts[0]

	resourceAndPerm := strings.SplitN(parts[1], ".", 2)
	if len(resourceAndPerm) != 2 {
		return apiGroup, "", "", false
	}
	resourcePlural := resourceAndPerm[0]
	permName := resourceAndPerm[1]
	return apiGroup, resourcePlural, permName, true
}

// OpenFGARoleFinalizer handles deletion of OpenFGA tuples for a Role.
type OpenFGARoleFinalizer struct {
	client.Client
	roleReconciler *openfga.RoleReconciler
}

// Finalize ensures that OpenFGA tuples for the Role are removed.
func (f *OpenFGARoleFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx)
	role, ok := obj.(*iamdatumapiscomv1alpha1.Role)
	if !ok {
		return finalizer.Result{}, fmt.Errorf("object is not a Role: %T", obj)
	}

	log.Info("Performing Finalization Tasks for Role before deletion", "Role", role.Name)

	if err := f.roleReconciler.DeleteRole(ctx, *role); err != nil {
		return finalizer.Result{}, fmt.Errorf("failed to delete role configuration: %w", err)
	}

	log.Info("Successfully deleted role configuration during finalization")
	return finalizer.Result{}, nil
}

// RoleReconciler reconciles a Role object
type RoleReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	FgaClient     openfgav1.OpenFGAServiceClient
	StoreID       string
	Finalizers    finalizer.Finalizers
	EventRecorder record.EventRecorder
}

// getAllEffectivePermissions collects all unique permissions for a role, including inherited ones.
func (r *RoleReconciler) getAllEffectivePermissions(ctx context.Context, role *iamdatumapiscomv1alpha1.Role, visited map[string]struct{}) ([]string, error) {
	if visited == nil {
		visited = make(map[string]struct{})
	}

	roleIdentifier := role.Namespace + "/" + role.Name // Ensure uniqueness for visited roles across namespaces
	if _, ok := visited[roleIdentifier]; ok {
		return nil, nil // Prevent cycles
	}
	visited[roleIdentifier] = struct{}{}

	permissionSet := make(map[string]struct{})
	for _, p := range role.Spec.IncludedPermissions {
		permissionSet[p] = struct{}{}
	}

	for _, inheritedRoleRef := range role.Spec.InheritedRoles {
		inheritedRole := &iamdatumapiscomv1alpha1.Role{}

		// Determine the namespace for the inherited role.
		// Default to the current role's namespace if not specified.
		namespace := role.Namespace
		if inheritedRoleRef.Namespace != "" {
			namespace = inheritedRoleRef.Namespace
		}

		err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: inheritedRoleRef.Name}, inheritedRole)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("inherited role '%s' not found in namespace '%s'", inheritedRoleRef.Name, namespace)
			}
			return nil, fmt.Errorf("failed to get inherited role %s/%s: %w", namespace, inheritedRoleRef.Name, err)
		}

		inheritedPerms, err := r.getAllEffectivePermissions(ctx, inheritedRole, visited)
		if err != nil {
			return nil, err // Propagate error up
		}
		for _, p := range inheritedPerms {
			permissionSet[p] = struct{}{}
		}
	}

	finalPermissions := make([]string, 0, len(permissionSet))
	for p := range permissionSet {
		finalPermissions = append(finalPermissions, p)
	}
	return finalPermissions, nil
}

// validateRolePermissions checks if all effective permissions in a role are validly defined by known ProtectedResources.
func (r *RoleReconciler) validateRolePermissions(ctx context.Context, role *iamdatumapiscomv1alpha1.Role, protectedResources []iamdatumapiscomv1alpha1.ProtectedResource, effectivePermissions []string) ([]string, error) {
	log := logf.FromContext(ctx).WithValues("roleName", role.Name)
	var invalidPermissions []string

	for _, permStr := range effectivePermissions {
		permAPIGroup, permResourcePlural, permName, isValidFormat := parsePermissionString(permStr)
		if !isValidFormat {
			log.Info("Invalid permission format encountered during validation", "permission", permStr, "role", role.Name)
			invalidPermissions = append(invalidPermissions, permStr+" (invalid format)")
			continue
		}

		isPermissionDefined := false
	validationLoop:
		for _, pr := range protectedResources {
			if pr.Spec.ServiceRef.Name == permAPIGroup && pr.Spec.Plural == permResourcePlural {
				for _, definedPerm := range pr.Spec.Permissions {
					if definedPerm == permName {
						isPermissionDefined = true
						break validationLoop
					}
				}
			}
		}
		if !isPermissionDefined {
			invalidPermissions = append(invalidPermissions, permStr)
		}
	}

	// Ensure deterministic order for downstream comparison/logging
	sort.Strings(invalidPermissions)
	return invalidPermissions, nil
}

// isRoleAffectedByProtectedResource checks if a role's effective permissions might be affected by a change
// in the specified ProtectedResource definition.
func (r *RoleReconciler) isRoleAffectedByProtectedResource(ctx context.Context, role *iamdatumapiscomv1alpha1.Role, pr *iamdatumapiscomv1alpha1.ProtectedResource) (bool, error) {
	roleLog := logf.FromContext(ctx).WithValues(
		"roleBeingChecked", role.Name, "roleNamespace", role.Namespace,
		"changedProtectedResource", pr.Name,
		"serviceRef", pr.Spec.ServiceRef.Name, "kindDefined", pr.Spec.Kind,
	)

	effectivePermissions, err := r.getAllEffectivePermissions(ctx, role, nil)
	if err != nil {
		roleLog.V(1).Info("Could not get effective permissions for role, cannot determine if affected by ProtectedResource change", "error", err.Error())
		return false, err
	}

	changedPrAPIGroup := pr.Spec.ServiceRef.Name
	changedPrPlural := pr.Spec.Plural

	if changedPrAPIGroup == "" || changedPrPlural == "" {
		roleLog.Info("ProtectedResource has empty ServiceRef.Name or Plural, cannot determine affected roles.",
			"serviceRefName", changedPrAPIGroup, "plural", changedPrPlural)
		return false, fmt.Errorf("ProtectedResource %s has empty ServiceRef.Name or Plural", pr.Name)
	}

	for _, permStr := range effectivePermissions {
		permAPIGroup, permResourcePlural, permName, isValidFormat := parsePermissionString(permStr)
		if !isValidFormat {
			continue
		}

		if permAPIGroup == changedPrAPIGroup && permResourcePlural == changedPrPlural {
			for _, definedPerm := range pr.Spec.Permissions {
				if definedPerm == permName {
					roleLog.V(1).Info("Role is affected by ProtectedResource change due to matching permission", "permission", permStr)
					return true, nil
				}
			}
		}
	}

	roleLog.V(1).Info("Role is not affected by this ProtectedResource change")
	return false, nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Role object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *RoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("role", req.NamespacedName)

	role := &iamdatumapiscomv1alpha1.Role{}
	if err := r.Get(ctx, req.NamespacedName, role); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Role resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Role")
		return ctrl.Result{}, err
	}

	oldStatus := role.Status.DeepCopy()
	currentGeneration := role.Generation
	role.Status.ObservedGeneration = currentGeneration

	finalizeResult, err := r.Finalizers.Finalize(ctx, role)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for Role: %w", err)
	}
	if finalizeResult.Updated {
		log.Info("Role updated by finalizer (e.g., finalizer removed or status updated).")
		if err := r.Update(ctx, role); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update Role after finalizer operation: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if role.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	var protectedResourceList iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := r.List(ctx, &protectedResourceList); err != nil {
		return ctrl.Result{}, err
	}

	// Compute effective permissions once for both status population and validation
	effectivePermissions, effectivePermsErr := r.getAllEffectivePermissions(ctx, role, nil)
	if effectivePermsErr != nil {
		log.Error(effectivePermsErr, "Failed to compute effective permissions for role")
		meta.SetStatusCondition(&role.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "EffectivePermissionsError",
			Message:            fmt.Sprintf("Failed to compute effective permissions: %s", effectivePermsErr.Error()),
			ObservedGeneration: currentGeneration,
		})
		if statusUpdateErr := r.updateRoleStatus(ctx, role, oldStatus); statusUpdateErr != nil {
			log.Error(statusUpdateErr, "Failed to update Role status after effective permissions error")
		}
		return ctrl.Result{}, effectivePermsErr
	}
	// Sort for deterministic output and populate status
	sort.Strings(effectivePermissions)
	role.Status.EffectivePermissions = effectivePermissions

	invalidPermissions, validationErr := r.validateRolePermissions(ctx, role, protectedResourceList.Items, effectivePermissions)
	permValidationCondition := metav1.Condition{
		Type:               "PermissionsValid",
		Status:             metav1.ConditionTrue,
		Reason:             "ValidationSuccessful",
		Message:            "All permissions validated successfully.",
		ObservedGeneration: currentGeneration,
	}
	if validationErr != nil {
		log.Error(validationErr, "Error validating role permissions")
		permValidationCondition.Status = metav1.ConditionFalse
		permValidationCondition.Reason = "ValidationError"
		permValidationCondition.Message = fmt.Sprintf("Error during permission validation: %s", validationErr.Error())
	} else if len(invalidPermissions) > 0 {
		log.Info("Role contains invalid or undefined permissions", "invalidPermissions", invalidPermissions)
		permValidationCondition.Status = metav1.ConditionFalse
		permValidationCondition.Reason = "InvalidPermissions"
		permValidationCondition.Message = fmt.Sprintf("Role contains invalid/undefined permissions: %s", strings.Join(invalidPermissions, ", "))
	}
	meta.SetStatusCondition(&role.Status.Conditions, permValidationCondition)

	if permValidationCondition.Status == metav1.ConditionTrue {
		openFgaReconciler := openfga.RoleReconciler{
			StoreID:      r.StoreID,
			OpenFGA:      r.FgaClient,
			ControlPlane: r.Client,
		}
		if err := openFgaReconciler.ReconcileRole(ctx, role); err != nil {
			log.Error(err, "Failed to reconcile Role with OpenFGA")
			meta.SetStatusCondition(&role.Status.Conditions, metav1.Condition{
				Type:    "Ready",
				Status:  metav1.ConditionFalse,
				Reason:  "OpenFGAReconciliationFailed",
				Message: fmt.Sprintf("Failed to reconcile with OpenFGA: %s", err.Error()),
			})
			if statusUpdateErr := r.updateRoleStatus(ctx, role, oldStatus); statusUpdateErr != nil {
				log.Error(statusUpdateErr, "Failed to update Role status after OpenFGA reconciliation failure")
			}
			return ctrl.Result{}, err
		}
		log.Info("Role successfully reconciled with OpenFGA")
		meta.SetStatusCondition(&role.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionTrue,
			Reason:             "ReconciliationSuccessful",
			Message:            "Role reconciled successfully with OpenFGA.",
			ObservedGeneration: currentGeneration,
		})
	} else {
		log.Info("Skipping OpenFGA reconciliation due to invalid permissions.")
		meta.SetStatusCondition(&role.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "InvalidPermissions",
			Message:            permValidationCondition.Message,
			ObservedGeneration: currentGeneration,
		})
	}

	if err := r.updateRoleStatus(ctx, role, oldStatus); err != nil {
		log.Error(err, "Failed to update Role status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// enqueueRequestsForInheritedRoleChange is a handler that enqueues reconcile
// requests for every Role that transitively inherits the changed Role. A Role's
// effective permissions are computed from its inherited Roles, so when an
// inherited (ancestor) Role's permissions change, the descendant Roles must be
// re-reconciled to refresh their Status.EffectivePermissions. The changed Role
// itself is reconciled via the primary For() watch and is skipped here.
func (r *RoleReconciler) enqueueRequestsForInheritedRoleChange(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	changedRole, ok := obj.(*iamdatumapiscomv1alpha1.Role)
	if !ok {
		log.Error(fmt.Errorf("unexpected object type in Role handler for Roles: %T", obj), "cannot enqueue Roles")
		return []reconcile.Request{}
	}

	changedKey := client.ObjectKey{Namespace: changedRole.Namespace, Name: changedRole.Name}
	dependents, err := rolesDependentOnRole(ctx, r.Client, changedKey)
	if err != nil {
		log.Error(err, "failed to compute Roles dependent on changed Role",
			"roleName", changedRole.Name, "roleNamespace", changedRole.Namespace)
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0, len(dependents))
	for key := range dependents {
		if key == changedKey {
			continue // reconciled via the primary For() watch
		}
		requests = append(requests, reconcile.Request{NamespacedName: key})
		log.V(1).Info("Enqueuing Role due to inherited Role change",
			"roleName", key.Name, "roleNamespace", key.Namespace,
			"changedRoleName", changedRole.Name, "changedRoleNamespace", changedRole.Namespace)
	}
	return requests
}

// enqueueRequestsForProtectedResourceChange is a handler that enqueues Role reconcile requests
// when a ProtectedResource changes.
func (r *RoleReconciler) enqueueRequestsForProtectedResourceChange(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	protectedResource, ok := obj.(*iamdatumapiscomv1alpha1.ProtectedResource)
	if !ok {
		log.Error(fmt.Errorf("unexpected object type in ProtectedResource handler for Roles: %T", obj), "cannot enqueue Roles")
		return []reconcile.Request{}
	}

	log.V(1).Info("ProtectedResource changed, evaluating Roles for re-reconciliation",
		"protectedResourceName", protectedResource.Name,
		"serviceRef", protectedResource.Spec.ServiceRef.Name,
		"kindDefined", protectedResource.Spec.Kind)

	roleList := &iamdatumapiscomv1alpha1.RoleList{}
	if err := r.List(context.Background(), roleList); err != nil {
		log.Error(err, "failed to list Roles for ProtectedResource change handler")
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0, len(roleList.Items))
	for i := range roleList.Items {
		role := &roleList.Items[i]
		affected, err := r.isRoleAffectedByProtectedResource(ctx, role, protectedResource)
		if err != nil {
			log.Error(err, "Failed to check if role is affected by ProtectedResource change", "roleName", role.Name, "roleNamespace", role.Namespace)
			continue
		}
		if affected {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKey{Name: role.Name, Namespace: role.Namespace},
			})
			log.V(1).Info("Enqueuing Role due to relevant ProtectedResource change", "roleName", role.Name, "roleNamespace", role.Namespace)
		}
	}
	return requests
}

func (r *RoleReconciler) updateRoleStatus(ctx context.Context, actualRole *iamdatumapiscomv1alpha1.Role, oldStatus *iamdatumapiscomv1alpha1.RoleStatus) error {
	log := logf.FromContext(ctx).WithValues("roleStatusUpdate", actualRole.Name, "roleNamespace", actualRole.Namespace)

	if !equality.Semantic.DeepEqual(oldStatus, &actualRole.Status) {
		if err := r.Client.Status().Update(ctx, actualRole); err != nil {
			log.Error(err, "Failed to update role status")
			return fmt.Errorf("failed to update role status: %w", err)
		}
		log.V(1).Info("Role status updated")
	} else {
		log.V(1).Info("Role status unchanged; skipping update")
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(roleFinalizerKey, &OpenFGARoleFinalizer{
		Client: r.Client,
		roleReconciler: &openfga.RoleReconciler{
			StoreID:      r.StoreID,
			OpenFGA:      r.FgaClient,
			ControlPlane: r.Client,
		},
	}); err != nil {
		return fmt.Errorf("failed to register role finalizer: %w", err)
	}

	controllerBuilder := ctrl.NewControllerManagedBy(mgr).
		For(&iamdatumapiscomv1alpha1.Role{}).
		Named("role")

	controllerBuilder.Watches(
		&iamdatumapiscomv1alpha1.ProtectedResource{},
		handler.EnqueueRequestsFromMapFunc(r.enqueueRequestsForProtectedResourceChange),
	)

	// Watch for changes to other Roles and enqueue the Roles that inherit them,
	// so descendant Roles refresh their effective permissions when an inherited
	// (ancestor) Role's permissions change. Filtered to spec changes
	// (generation bumps) to avoid reacting to our own status updates.
	controllerBuilder.Watches(
		&iamdatumapiscomv1alpha1.Role{},
		handler.EnqueueRequestsFromMapFunc(r.enqueueRequestsForInheritedRoleChange),
		builder.WithPredicates(predicate.GenerationChangedPredicate{}),
	)

	return controllerBuilder.Complete(r)
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=roles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=roles/finalizers,verbs=update
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=protectedresources,verbs=get;list;watch

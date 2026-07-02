package openfga

import (
	"context"
	"fmt"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// PolicyReconciler writes and removes permission tuples in OpenFGA.
//
// Tuples are written as one tuple per (subject × permission) pair directly
// on the target resource object.
type PolicyReconciler struct {
	StoreID   string
	Client    openfgav1.OpenFGAServiceClient
	K8sClient client.Client
}

// ReconcilePolicy ensures the correct tuples for a
// PolicyBinding are present in the OpenFGA store.
func (r *PolicyReconciler) ReconcilePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	if err := r.reconcilePolicy(ctx, binding); err != nil {
		return fmt.Errorf("reconciliation failed: %w", err)
	}
	return nil
}

// DeletePolicy removes only the tuples that are exclusively owned by this
// PolicyBinding. Tuples that are also desired by another binding targeting the
// same resource with overlapping subjects are preserved.
func (r *PolicyReconciler) DeletePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	log := logf.FromContext(ctx)

	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	existingTuples, err := r.getExistingTuples(ctx, binding, targetObject)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing direct tuples for deletion: %w", err)
	}

	if len(existingTuples) == 0 {
		log.Info("No existing tuples found for PolicyBinding, nothing to delete", "binding", binding.Name)
		return nil
	}

	validPerms, err := r.getHierarchicalPermissionsForSelector(ctx, binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to compute hierarchical permissions: %w", err)
	}

	// Find tuples that other overlapping bindings still need, so we don't
	// delete them.
	stillDesired, err := r.siblingDesiredTuples(ctx, binding, targetObject, validPerms)
	if err != nil {
		return fmt.Errorf("failed to compute sibling desired tuples: %w", err)
	}

	// Only delete tuples that no remaining binding needs.
	// diffTuples(existing, current) returns (added, removed) where:
	//   removed = in existing but NOT in current
	//   added   = in current but NOT in existing
	// We want to delete tuples in existingTuples that are NOT in stillDesired.
	_, toDelete := diffTuples(existingTuples, stillDesired)
	if len(toDelete) == 0 {
		log.Info("All tuples for PolicyBinding are still needed by other bindings, nothing to delete", "binding", binding.Name)
		return nil
	}

	_, err = r.Client.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.StoreID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(toDelete),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete policy tuples: %w", err)
	}

	log.Info("Successfully deleted tuples for PolicyBinding", "binding", binding.Name, "tupleCount", len(toDelete))
	return nil
}

// ---------------------------------------------------

// reconcilePolicy computes the desired tuple set for the single triggering
// PolicyBinding and diffs it against the existing tuples in OpenFGA.
//
// Each binding independently manages tuples for its own subjects only.
// getExistingTuples reads all tuples for the binding's subjects on the target
// object, so diffTuples will not re-write tuples that are already present,
// regardless of which binding originally created them.
func (r *PolicyReconciler) reconcilePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	validPerms, err := r.getHierarchicalPermissionsForSelector(ctx, binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to compute hierarchical permissions: %w", err)
	}

	role, err := r.fetchRole(ctx, binding)
	if err != nil {
		return fmt.Errorf("failed to fetch role: %w", err)
	}

	desired, err := r.buildPermissionTuples(binding, role, targetObject, validPerms)
	if err != nil {
		return fmt.Errorf("failed to build permission tuples: %w", err)
	}

	existingTuples, err := r.getExistingTuples(ctx, binding, targetObject)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing tuples: %w", err)
	}

	added, removed := diffTuples(existingTuples, desired)

	// Filter removals: don't remove tuples that other overlapping bindings
	// still need. This prevents clobbering permissions granted by sibling
	// bindings that use different roles on the same subject+resource.
	if len(removed) > 0 {
		siblingTuples, err := r.siblingDesiredTuples(ctx, binding, targetObject, validPerms)
		if err != nil {
			return fmt.Errorf("failed to compute sibling desired tuples: %w", err)
		}
		if len(siblingTuples) > 0 {
			siblingSet := make(map[string]struct{}, len(siblingTuples))
			for _, t := range siblingTuples {
				siblingSet[t.User+"|"+t.Relation+"|"+t.Object] = struct{}{}
			}
			filtered := make([]*openfgav1.TupleKey, 0, len(removed))
			for _, t := range removed {
				if _, ok := siblingSet[t.User+"|"+t.Relation+"|"+t.Object]; !ok {
					filtered = append(filtered, t)
				}
			}
			removed = filtered
		}
	}

	writeReq := &openfgav1.WriteRequest{
		StoreId: r.StoreID,
	}

	if len(added) > 0 {
		writeReq.Writes = &openfgav1.WriteRequestWrites{
			TupleKeys: added,
		}
	}

	if len(removed) > 0 {
		writeReq.Deletes = &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(removed),
		}
	}

	if writeReq.Deletes == nil && writeReq.Writes == nil {
		return nil
	}

	_, err = r.Client.Write(ctx, writeReq)
	if err != nil {
		return fmt.Errorf("failed to write permission tuples: %w", err)
	}

	return nil
}

// siblingDesiredTuples returns the set of tuples that other PolicyBindings
// (targeting the same resource with at least one overlapping subject) still
// desire. This is used by both DeletePolicy and reconcilePolicy to avoid
// removing tuples that another binding still needs.
func (r *PolicyReconciler) siblingDesiredTuples(
	ctx context.Context,
	binding iamdatumapiscomv1alpha1.PolicyBinding,
	targetObject string,
	validPerms map[string]struct{},
) ([]*openfgav1.TupleKey, error) {
	var siblingBindings iamdatumapiscomv1alpha1.PolicyBindingList
	if err := r.K8sClient.List(ctx, &siblingBindings, client.MatchingFields{
		TargetObjectIndexField: targetObject,
	}); err != nil {
		return nil, fmt.Errorf("failed to list sibling PolicyBindings: %w", err)
	}

	triggerSubjects := make(map[string]struct{})
	for _, s := range binding.Spec.Subjects {
		triggerSubjects[s.Kind+"/"+s.Name] = struct{}{}
	}

	var desired []*openfgav1.TupleKey
	for i := range siblingBindings.Items {
		other := siblingBindings.Items[i]

		// Skip the binding itself.
		if other.Namespace == binding.Namespace && other.Name == binding.Name {
			continue
		}

		// Must share at least one subject.
		hasOverlap := false
		for _, s := range other.Spec.Subjects {
			if _, ok := triggerSubjects[s.Kind+"/"+s.Name]; ok {
				hasOverlap = true
				break
			}
		}
		if !hasOverlap {
			continue
		}

		role, err := r.fetchRole(ctx, other)
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("failed to fetch role for sibling binding %s/%s: %w", other.Namespace, other.Name, err)
		}
		tuples, err := r.buildPermissionTuples(other, role, targetObject, validPerms)
		if err != nil {
			continue
		}
		desired = append(desired, tuples...)
	}

	return desired, nil
}

// fetchRole retrieves the Role referenced by the binding.
func (r *PolicyReconciler) fetchRole(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) (*iamdatumapiscomv1alpha1.Role, error) {
	roleNamespace := binding.Spec.RoleRef.Namespace
	if roleNamespace == "" {
		return nil, fmt.Errorf("RoleRef.Namespace is required but was not provided for Role '%s' in PolicyBinding '%s/%s'", binding.Spec.RoleRef.Name, binding.Namespace, binding.Name)
	}

	role := &iamdatumapiscomv1alpha1.Role{}
	if err := r.K8sClient.Get(ctx, types.NamespacedName{
		Name:      binding.Spec.RoleRef.Name,
		Namespace: roleNamespace,
	}, role); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("role '%s' not found: %w", binding.Spec.RoleRef.Name, err)
		}
		return nil, fmt.Errorf("failed to get role '%s': %w", binding.Spec.RoleRef.Name, err)
	}

	return role, nil
}

// buildPermissionTuples expands the Role's effective permissions into one
// OpenFGA tuple per (subject, permission) pair targeting the given object.
//
// Effective permissions are the fully-resolved set of permissions including
// those inherited through InheritedRoles. They are pre-computed by the role
// controller and stored in Status.EffectivePermissions.
//
// For a Role with effective permissions [get, list] on organizations and
// subjects [alice], this produces:
//
//	(InternalUser:alice,  hash(svc/organizations.get),  apiGroup/Organization:org-1)
//	(InternalUser:alice,  hash(svc/organizations.list), apiGroup/Organization:org-1)
func (r *PolicyReconciler) buildPermissionTuples(
	binding iamdatumapiscomv1alpha1.PolicyBinding,
	role *iamdatumapiscomv1alpha1.Role,
	targetObject string,
	validPerms map[string]struct{},
) ([]*openfgav1.TupleKey, error) {
	effectivePerms := role.Status.EffectivePermissions
	if len(effectivePerms) == 0 {
		// Fall back to spec-level permissions if the role controller hasn't
		// computed effective permissions yet.
		effectivePerms = role.Spec.IncludedPermissions
	}

	var tuples []*openfgav1.TupleKey

	for _, subject := range binding.Spec.Subjects {
		tupleUser, err := getTupleUser(subject)
		if err != nil {
			return nil, fmt.Errorf("failed to get tuple user for subject %s: %w", subject.Name, err)
		}

		for _, permName := range effectivePerms {
			// Skip permissions not valid for the target resource type.
			// validPerms contains the hierarchical permission set: the
			// target resource's own permissions plus all descendant
			// resource permissions.
			if len(validPerms) > 0 {
				if _, ok := validPerms[permName]; !ok {
					continue
				}
			}
			hashedPerm := hashPermission(permName)
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     tupleUser,
				Relation: hashedPerm,
				Object:   targetObject,
			})
		}
	}

	return tuples, nil
}

// getHierarchicalPermissionsForSelector computes the full set of permissions
// valid on a target resource type, including permissions inherited from child
// resources in the hierarchy. This mirrors calculateHierarchicalPermissions
// used by the authorization model builder.
func (r *PolicyReconciler) getHierarchicalPermissionsForSelector(ctx context.Context, selector iamdatumapiscomv1alpha1.ResourceSelector) (map[string]struct{}, error) {
	var apiGroup, kind string
	switch {
	case selector.ResourceRef != nil:
		apiGroup = selector.ResourceRef.APIGroup
		kind = selector.ResourceRef.Kind
	case selector.ResourceKind != nil:
		apiGroup = selector.ResourceKind.APIGroup
		kind = selector.ResourceKind.Kind
	default:
		return nil, fmt.Errorf("resourceSelector must specify either resourceRef or resourceKind")
	}

	var prList iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := r.K8sClient.List(ctx, &prList); err != nil {
		return nil, fmt.Errorf("failed to list ProtectedResources: %w", err)
	}

	// Build the resource graph and compute hierarchical permissions, reusing
	// the same logic as the authorization model builder.
	resourceGraph, err := getResourceGraph(prList.Items)
	if err != nil {
		return nil, fmt.Errorf("failed to build resource graph: %w", err)
	}
	hierarchicalPermissions := calculateHierarchicalPermissions(resourceGraph)

	// Find the target resource type in the graph.
	targetResourceType := apiGroup + "/" + kind
	perms, ok := hierarchicalPermissions[targetResourceType]
	if !ok {
		// If the resource type is not in the graph, it might be a
		// Root-scoped resource. Return all permissions across all types.
		allPerms := make(map[string]struct{})
		for _, typePerms := range hierarchicalPermissions {
			for _, p := range typePerms {
				allPerms[p] = struct{}{}
			}
		}
		return allPerms, nil
	}

	permSet := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		permSet[p] = struct{}{}
	}
	return permSet, nil
}

// getExistingTuples reads all tuples owned by this
// PolicyBinding. Because tuples are indexed by subject user
// and target object we query for each subject individually.
func (r *PolicyReconciler) getExistingTuples(
	ctx context.Context,
	binding iamdatumapiscomv1alpha1.PolicyBinding,
	targetObject string,
) ([]*openfgav1.TupleKey, error) {
	var all []*openfgav1.TupleKey

	for _, subject := range binding.Spec.Subjects {
		tupleUser, err := getTupleUser(subject)
		if err != nil {
			return nil, fmt.Errorf("failed to get tuple user for subject %s: %w", subject.Name, err)
		}

		// Read all tuples for (user, *, targetObject) — the relation wildcard
		// returns every permission tuple for this subject on this resource.
		existing, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
			User:   tupleUser,
			Object: targetObject,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get existing tuples for subject %s: %w", subject.Name, err)
		}
		all = append(all, existing...)
	}

	return all, nil
}

// --- shared helpers -----------------------------------------------------------

// getTargetObjectFromResourceSelector extracts the target object identifier from ResourceSelector
func (r *PolicyReconciler) getTargetObjectFromResourceSelector(selector iamdatumapiscomv1alpha1.ResourceSelector) (string, error) {
	return TargetObjectFromResourceSelector(selector)
}

func convertTuplesForDelete(tuples []*openfgav1.TupleKey) []*openfgav1.TupleKeyWithoutCondition {
	newTuples := make([]*openfgav1.TupleKeyWithoutCondition, len(tuples))
	for i, tuple := range tuples {
		newTuples[i] = &openfgav1.TupleKeyWithoutCondition{
			User:     tuple.User,
			Relation: tuple.Relation,
			Object:   tuple.Object,
		}
	}
	return newTuples
}

// tupleKeyEqual compares two TupleKey proto messages by their semantic fields
// (User, Relation, Object, Condition). Using proto.Equal ensures correct
// comparison of protobuf messages regardless of internal state differences
// between newly-constructed messages and those deserialized from the wire.
func tupleKeyEqual(a, b *openfgav1.TupleKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	// Compare only the semantic fields to avoid false negatives from
	// protobuf internal bookkeeping state.
	return a.User == b.User && a.Relation == b.Relation && a.Object == b.Object &&
		proto.Equal(a.Condition, b.Condition)
}

// diffTuples returns the tuples that need to be added and removed.
func diffTuples(existing, current []*openfgav1.TupleKey) (added, removed []*openfgav1.TupleKey) {
	// Any of the current tuples that don't exist in the new set of tuples will
	// need to be removed.
	for _, existingTuple := range existing {
		found := false
		for _, currentTuple := range current {
			if tupleKeyEqual(existingTuple, currentTuple) {
				found = true
				break
			}
		}
		if !found {
			removed = append(removed, existingTuple)
		}
	}

	for _, currentTuple := range current {
		found := false
		for _, existingTuple := range existing {
			if tupleKeyEqual(currentTuple, existingTuple) {
				found = true
				break
			}
		}
		if !found {
			added = append(added, currentTuple)
		}
	}
	return added, removed
}

func getTupleKeys(ctx context.Context, storeID string, client openfgav1.OpenFGAServiceClient, tuple *openfgav1.ReadRequestTupleKey) ([]*openfgav1.TupleKey, error) {
	tupleKeys := []*openfgav1.TupleKey{}
	continuationToken := ""
	for {
		resp, err := client.Read(ctx, &openfgav1.ReadRequest{
			StoreId:           storeID,
			ContinuationToken: continuationToken,
			PageSize:          wrapperspb.Int32(100),
			TupleKey:          tuple,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to read existing tuples: %w", err)
		}

		for _, t := range resp.Tuples {
			tupleKeys = append(tupleKeys, t.GetKey())
		}

		continuationToken = resp.ContinuationToken
		if resp.ContinuationToken == "" {
			break
		}
	}

	return tupleKeys, nil
}

// getTupleUser returns the OpenFGA user string for a subject under the
// permission model. Group members are referenced via the #member
// relation (InternalUserGroup:<uid>#member). ServiceAccount subjects are
// treated as InternalUser principals, using the resource name as the identity
// token (consistent with how the auth webhook sets the SAR user UID).
func getTupleUser(subject iamdatumapiscomv1alpha1.Subject) (string, error) {
	switch subject.Kind {
	case "User":
		if subject.UID == "" {
			return "", fmt.Errorf("user subject must have a UID")
		}
		// Use the subject name as the OpenFGA user identifier. The user.Name is
		// the Kubernetes resource name, which matches the uid field passed in
		// SubjectAccessReview requests (the system uses names as identity
		// tokens, not the K8s metadata UID).
		return TypeInternalUser + ":" + subject.Name, nil
	case "ServiceAccount":
		if subject.UID == "" {
			return "", fmt.Errorf("serviceaccount subject must have a UID")
		}
		// Machine accounts are represented as InternalUser principals in OpenFGA.
		// For machine accounts, we use the literal Kubernetes UID as the identity
		// token, which matches how the authentication webhook populates the
		// SubjectAccessReview (using the resource's UID).
		return TypeInternalUser + ":" + subject.UID, nil
	case "Group":
		// System groups (names starting with "system:") don't require UID and use the group name directly
		if strings.HasPrefix(subject.Name, "system:") {
			// Replace colons with underscores to avoid OpenFGA tuple parsing issues
			escapedName := strings.ReplaceAll(subject.Name, ":", "_")
			return TypeInternalUserGroup + ":" + escapedName + "#member", nil
		}
		// Regular groups require UID
		if subject.UID == "" {
			return "", fmt.Errorf("group subject must have a UID")
		}
		return TypeInternalUserGroup + ":" + subject.UID + "#member", nil
	default:
		return "", fmt.Errorf("unsupported subject kind: %s", subject.Kind)
	}
}

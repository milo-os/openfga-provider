package openfga

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/features"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/protobuf/types/known/wrapperspb"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// PolicyReconciler writes and removes permission tuples in OpenFGA.
//
// The tuple format written depends on which feature gates are enabled:
//
//   - DirectPermissionTuples=true (default): writes one tuple per
//     (subject × permission) pair directly on the target resource object.
//     Avoids the RoleBinding/InternalRole intersection and reduces Check
//     reads from ~27 to 1-3.
//
//   - LegacyRoleBindingModel=true: writes the old three-tuple linkage chain:
//     (RoleBinding → resource), (InternalRole → RoleBinding),
//     (subject → RoleBinding). When both gates are enabled the reconciler
//     writes both tuple sets (dual-write migration mode).
type PolicyReconciler struct {
	StoreID   string
	Client    openfgav1.OpenFGAServiceClient
	K8sClient client.Client
}

// ReconcilePolicy ensures the correct tuples for a PolicyBinding are present
// in the OpenFGA store. Which tuples are written is controlled by feature gates:
//
//   - DirectPermissionTuples=true → write direct (user, hash(perm), resource) tuples
//   - LegacyRoleBindingModel=true → write legacy RoleBinding linkage tuples
//   - Both true → dual-write mode (both tuple formats written against the hybrid model)
func (r *PolicyReconciler) ReconcilePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	directEnabled := utilfeature.DefaultFeatureGate.Enabled(features.DirectPermissionTuples)
	legacyEnabled := utilfeature.DefaultFeatureGate.Enabled(features.LegacyRoleBindingModel)

	if directEnabled {
		if err := r.reconcileDirectPolicy(ctx, binding); err != nil {
			return fmt.Errorf("direct-permission reconciliation failed: %w", err)
		}
	}

	if legacyEnabled {
		if err := r.reconcileLegacyPolicy(ctx, binding); err != nil {
			return fmt.Errorf("legacy RoleBinding reconciliation failed: %w", err)
		}
	}

	return nil
}

// DeletePolicy removes all tuples that were written for a PolicyBinding,
// covering both the direct-permission and legacy tuple formats.
func (r *PolicyReconciler) DeletePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	log := logf.FromContext(ctx)

	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	// Always attempt to delete direct tuples regardless of the current gate
	// state — the gate may have been toggled after tuples were written.
	directTuples, err := r.getExistingDirectTuples(ctx, binding, targetObject)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing direct tuples for deletion: %w", err)
	}

	// Always attempt to delete legacy tuples for the same reason.
	legacyTuples, err := r.getExistingLegacyTuples(ctx, binding, targetObject)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing legacy tuples for deletion: %w", err)
	}

	allTuples := append(directTuples, legacyTuples...)

	if len(allTuples) == 0 {
		log.Info("No existing tuples found for PolicyBinding, nothing to delete", "binding", binding.Name)
		return nil
	}

	_, err = r.Client.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.StoreID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(allTuples),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete policy tuples: %w", err)
	}

	log.Info("Successfully deleted tuples for PolicyBinding", "binding", binding.Name, "tupleCount", len(allTuples))
	return nil
}

// --- direct-permission path ---------------------------------------------------

// reconcileDirectPolicy writes/removes (user, hash(perm), resource) tuples.
func (r *PolicyReconciler) reconcileDirectPolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	role, err := r.fetchRole(ctx, binding)
	if err != nil {
		return err
	}

	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	// Compute the full set of permissions valid on the target resource type,
	// including permissions inherited from child resources. This mirrors how
	// the authorization model builder computes hierarchical permissions.
	validPerms, err := r.getHierarchicalPermissionsForSelector(ctx, binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to compute hierarchical permissions: %w", err)
	}

	desiredTuples, err := r.buildDirectPermissionTuples(binding, role, targetObject, validPerms)
	if err != nil {
		return fmt.Errorf("failed to build permission tuples: %w", err)
	}

	existingTuples, err := r.getExistingDirectTuples(ctx, binding, targetObject)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing tuples: %w", err)
	}

	added, removed := diffTuples(existingTuples, desiredTuples)

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
		return fmt.Errorf("failed to write direct permission tuples: %w", err)
	}

	return nil
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

// buildDirectPermissionTuples expands the Role's effective permissions into one
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
func (r *PolicyReconciler) buildDirectPermissionTuples(
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

// getExistingDirectTuples reads all direct-permission tuples owned by this
// PolicyBinding. Because direct-permission tuples are indexed by subject user
// and target object we query for each subject individually.
func (r *PolicyReconciler) getExistingDirectTuples(
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

// --- legacy RoleBinding path --------------------------------------------------

// reconcileLegacyPolicy writes the three-tuple RoleBinding linkage chain used
// by the legacy authorization model:
//
//	(RoleBinding:<bindingUID>, rolebinding, <resource>)
//	(InternalRole:<roleUID>,   internalrole, RoleBinding:<bindingUID>)
//	(InternalUser:<subjectUID>, internaluser, RoleBinding:<bindingUID>)  // one per subject
func (r *PolicyReconciler) reconcileLegacyPolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	policyBindingObjectIdentifier := TypeRoleBinding + ":" + string(binding.UID)

	role, err := r.fetchRole(ctx, binding)
	if err != nil {
		return err
	}
	roleUID := role.UID

	existingTuples, err := r.getExistingLegacyTuplesForRole(ctx, binding, roleUID)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing legacy tuples: %w", err)
	}

	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	tuples := []*openfgav1.TupleKey{
		// Associates the resource to the role binding.
		{
			User:     policyBindingObjectIdentifier,
			Relation: RelationRoleBinding,
			Object:   targetObject,
		},
		// Associates the role binding to the role.
		{
			User:     TypeInternalRole + ":" + string(roleUID),
			Relation: RelationInternalRole,
			Object:   policyBindingObjectIdentifier,
		},
	}

	for _, subject := range binding.Spec.Subjects {
		tupleUser, err := getLegacyTupleUser(subject)
		if err != nil {
			return fmt.Errorf("failed to get legacy tuple user for subject %s: %w", subject.Name, err)
		}

		tuples = append(tuples, &openfgav1.TupleKey{
			User:     tupleUser,
			Relation: RelationInternalUser,
			Object:   policyBindingObjectIdentifier,
		})
	}

	added, removed := diffTuples(existingTuples, tuples)

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
		return fmt.Errorf("failed to write legacy policy tuples: %w", err)
	}

	return nil
}

// getExistingLegacyTuples reads legacy RoleBinding linkage tuples for a
// PolicyBinding, without needing the role UID (used during deletion where the
// role may already be gone).
func (r *PolicyReconciler) getExistingLegacyTuples(
	ctx context.Context,
	binding iamdatumapiscomv1alpha1.PolicyBinding,
	targetObject string,
) ([]*openfgav1.TupleKey, error) {
	policyBindingObjectIdentifier := TypeRoleBinding + ":" + string(binding.UID)

	// Tuple 1: binding → resource
	bindingToResource, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
		User:     policyBindingObjectIdentifier,
		Relation: RelationRoleBinding,
		Object:   targetObject,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get binding-to-resource legacy tuples: %w", err)
	}

	// Tuples 2+: anything pointing to the binding object (role + subjects)
	bindingTargetTuples, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
		Object: policyBindingObjectIdentifier,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get legacy tuples targeting binding object: %w", err)
	}

	return append(bindingToResource, bindingTargetTuples...), nil
}

// getExistingLegacyTuplesForRole reads legacy tuples using explicit role UID
// lookup, matching the approach used on the main branch.
func (r *PolicyReconciler) getExistingLegacyTuplesForRole(
	ctx context.Context,
	policy iamdatumapiscomv1alpha1.PolicyBinding,
	roleUID types.UID,
) ([]*openfgav1.TupleKey, error) {
	policyBindingObjectIdentifier := TypeRoleBinding + ":" + string(policy.UID)

	targetObject, err := r.getTargetObjectFromResourceSelector(policy.Spec.ResourceSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	var allTuples []*openfgav1.TupleKey

	// Tuple linking binding to target resource.
	bindingToResource, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
		User:     policyBindingObjectIdentifier,
		Relation: RelationRoleBinding,
		Object:   targetObject,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get tuples linking binding to resource: %w", err)
	}
	allTuples = append(allTuples, bindingToResource...)

	// Tuple linking role to binding.
	roleLinkage, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
		User:     TypeInternalRole + ":" + string(roleUID),
		Relation: RelationInternalRole,
		Object:   policyBindingObjectIdentifier,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get role linkage tuple: %w", err)
	}
	allTuples = append(allTuples, roleLinkage...)

	// Tuples linking each subject to the binding.
	for _, subject := range policy.Spec.Subjects {
		tupleUser, err := getLegacyTupleUser(subject)
		if err != nil {
			return nil, fmt.Errorf("failed to get legacy tuple user: %w", err)
		}

		subjectLinkage, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
			User:     tupleUser,
			Relation: RelationInternalUser,
			Object:   policyBindingObjectIdentifier,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get subject linkage tuple for %s: %w", subject.UID, err)
		}
		allTuples = append(allTuples, subjectLinkage...)
	}

	return allTuples, nil
}

// --- shared helpers -----------------------------------------------------------

// getTargetObjectFromResourceSelector extracts the target object identifier from ResourceSelector
func (r *PolicyReconciler) getTargetObjectFromResourceSelector(selector iamdatumapiscomv1alpha1.ResourceSelector) (string, error) {
	if selector.ResourceRef != nil {
		// For specific resource instances: apiGroup/Kind:name
		return fmt.Sprintf("%s/%s:%s", selector.ResourceRef.APIGroup, selector.ResourceRef.Kind, selector.ResourceRef.Name), nil
	}

	if selector.ResourceKind != nil {
		// For all instances of a resource kind the direct-permission model
		// targets the kind-level root object in the same format as a specific
		// instance but using the TypeRoot prefix.
		return fmt.Sprintf("%s:%s/%s", TypeRoot, selector.ResourceKind.APIGroup, selector.ResourceKind.Kind), nil
	}

	return "", fmt.Errorf("resourceSelector must specify either resourceRef or resourceKind")
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

// diffTuples returns the tuples that need to be added and removed.
func diffTuples(existing, current []*openfgav1.TupleKey) (added, removed []*openfgav1.TupleKey) {
	// Any of the current tuples that don't exist in the new set of tuples will
	// need to be removed.
	for _, existingTuple := range existing {
		found := false
		for _, currentTuple := range current {
			if cmp.Equal(existingTuple, currentTuple, cmpopts.IgnoreUnexported(openfgav1.TupleKey{})) {
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
			if cmp.Equal(currentTuple, existingTuple, cmpopts.IgnoreUnexported(openfgav1.TupleKey{})) {
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
// direct-permission model. Group members are referenced via the #member
// relation (InternalUserGroup:<uid>#member).
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

// getLegacyTupleUser returns the OpenFGA user string for a subject under the
// legacy RoleBinding model. Group members are referenced via the #assignee
// relation (InternalUserGroup:<uid>#assignee).
func getLegacyTupleUser(subject iamdatumapiscomv1alpha1.Subject) (string, error) {
	switch subject.Kind {
	case "User":
		if subject.UID == "" {
			return "", fmt.Errorf("user subject must have a UID")
		}
		return TypeInternalUser + ":" + subject.Name, nil
	case "Group":
		if strings.HasPrefix(subject.Name, "system:") {
			escapedName := strings.ReplaceAll(subject.Name, ":", "_")
			return TypeInternalUserGroup + ":" + escapedName + "#assignee", nil
		}
		if subject.UID == "" {
			return "", fmt.Errorf("group subject must have a UID")
		}
		return TypeInternalUserGroup + ":" + subject.UID + "#assignee", nil
	default:
		return "", fmt.Errorf("unsupported subject kind: %s", subject.Kind)
	}
}

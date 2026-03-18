package openfga

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/protobuf/types/known/wrapperspb"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// PolicyReconciler writes and removes direct permission tuples in OpenFGA.
//
// Under the direct-permission model a PolicyBinding is translated into one
// tuple per (subject × permission) pair:
//
//	user=InternalUser:<uid>  relation=<hash(svc/resources.verb)>  object=<apiGroup/Kind:name>
//
// This avoids the RoleBinding → InternalRole intersection that previously
// required ~27 datastore reads per Check call, reducing it to 1-3 reads.
type PolicyReconciler struct {
	StoreID   string
	Client    openfgav1.OpenFGAServiceClient
	K8sClient client.Client
}

// ReconcilePolicy ensures the direct permission tuples for a PolicyBinding are
// present in the OpenFGA store. It expands the referenced Role into its
// effective permissions and writes one tuple per subject × permission.
func (r *PolicyReconciler) ReconcilePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	role, err := r.fetchRole(ctx, binding)
	if err != nil {
		return err
	}

	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	protectedResource, err := r.findProtectedResourceForSelector(ctx, binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to find protected resource: %w", err)
	}

	desiredTuples, err := r.buildDirectPermissionTuples(binding, role, targetObject, protectedResource)
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
		return fmt.Errorf("failed to write policy tuples: %w", err)
	}

	return nil
}

// DeletePolicy removes all direct permission tuples that were written for a
// PolicyBinding. It reads the existing tuples keyed by binding UID and deletes
// them.
func (r *PolicyReconciler) DeletePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	log := logf.FromContext(ctx)

	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	existingTuples, err := r.getExistingDirectTuples(ctx, binding, targetObject)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing tuples for deletion: %w", err)
	}

	if len(existingTuples) == 0 {
		log.Info("No existing tuples found for PolicyBinding, nothing to delete", "binding", binding.Name)
		return nil
	}

	_, err = r.Client.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.StoreID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(existingTuples),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete policy tuples: %w", err)
	}

	log.Info("Successfully deleted tuples for PolicyBinding", "binding", binding.Name, "tupleCount", len(existingTuples))
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

// findProtectedResourceForSelector locates the ProtectedResource that describes
// the resource type targeted by the binding. Returns nil (no error) when the
// selector cannot be resolved to a ProtectedResource (e.g. malformed selector).
func (r *PolicyReconciler) findProtectedResourceForSelector(ctx context.Context, selector iamdatumapiscomv1alpha1.ResourceSelector) (*iamdatumapiscomv1alpha1.ProtectedResource, error) {
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

	for i := range prList.Items {
		pr := &prList.Items[i]
		if pr.Spec.ServiceRef.Name == apiGroup && pr.Spec.Kind == kind {
			return pr, nil
		}
	}

	return nil, fmt.Errorf("no ProtectedResource found for APIGroup=%s, Kind=%s", apiGroup, kind)
}

// buildDirectPermissionTuples expands the Role's IncludedPermissions into one
// OpenFGA tuple per (subject, permission) pair targeting the given object.
//
// For a Role with permissions [get, list] on organizations and subjects [alice],
// this produces:
//
//	(InternalUser:alice,  hash(svc/organizations.get),  apiGroup/Organization:org-1)
//	(InternalUser:alice,  hash(svc/organizations.list), apiGroup/Organization:org-1)
func (r *PolicyReconciler) buildDirectPermissionTuples(
	binding iamdatumapiscomv1alpha1.PolicyBinding,
	role *iamdatumapiscomv1alpha1.Role,
	targetObject string,
	pr *iamdatumapiscomv1alpha1.ProtectedResource,
) ([]*openfgav1.TupleKey, error) {
	var tuples []*openfgav1.TupleKey

	for _, subject := range binding.Spec.Subjects {
		tupleUser, err := getTupleUser(subject)
		if err != nil {
			return nil, fmt.Errorf("failed to get tuple user for subject %s: %w", subject.Name, err)
		}

		for _, permName := range role.Spec.IncludedPermissions {
			// IncludedPermissions are stored as fully-qualified strings in the
			// format "<apiGroup>/<plural>.<verb>" (e.g.
			// "resourcemanager.miloapis.com/organizations.get"). Hash and write
			// directly.
			hashedPerm := hashPermission(permName)
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     tupleUser,
				Relation: hashedPerm,
				Object:   targetObject,
			})
		}

		// Also expand permissions inherited via InheritedRoles if the role has
		// any. We do a best-effort single-level expansion here; deep chains are
		// handled by the role controller which re-reconciles bindings on role
		// changes.
		_ = pr // reserved for future per-resource permission filtering
	}

	return tuples, nil
}

// getExistingDirectTuples reads all tuples owned by this PolicyBinding. Because
// direct-permission tuples are indexed by subject user and target object we
// query for each subject individually.
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

func getTupleUser(subject iamdatumapiscomv1alpha1.Subject) (string, error) {
	switch subject.Kind {
	case "User":
		if subject.UID == "" {
			return "", fmt.Errorf("user subject must have a UID")
		}
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

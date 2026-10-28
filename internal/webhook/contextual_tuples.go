package webhook

import (
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// buildGroupContextualTuples creates contextual tuples for the user's system
// group memberships. These are needed by the legacy RoleBinding model where
// group membership is injected per-request rather than stored as persistent
// tuples.
func buildGroupContextualTuples(attributes authorizer.Attributes) []*openfgav1.TupleKey {
	tuples := make([]*openfgav1.TupleKey, 0, len(attributes.GetUser().GetGroups()))

	userUID := attributes.GetUser().GetUID()
	for _, group := range attributes.GetUser().GetGroups() {
		// Only add system groups to contextual tuples.
		if !strings.HasPrefix(group, "system:") {
			continue
		}

		// Escape colons in group names to match the format used in the legacy
		// policy reconciler (getLegacyTupleUser).
		escapedGroup := strings.ReplaceAll(group, ":", "_")
		tuples = append(tuples, &openfgav1.TupleKey{
			User:     "iam.miloapis.com/InternalUser:" + userUID,
			Relation: "member",
			Object:   "iam.miloapis.com/InternalUserGroup:" + escapedGroup,
		})
	}

	return tuples
}

// buildRootBindingContextualTuple creates a root binding contextual tuple that
// links a specific resource instance to its kind-level Root object. This is
// required by the legacy RoleBinding model so that ResourceKind policy bindings
// (stored on Root objects) are visible when checking a specific resource.
func buildRootBindingContextualTuple(rootResourceType, targetResource string) *openfgav1.TupleKey {
	return &openfgav1.TupleKey{
		User:     "iam.miloapis.com/Root:" + rootResourceType,
		Relation: "iam.miloapis.com/RootBinding",
		Object:   targetResource,
	}
}

// buildAllContextualTuples returns the union of root-binding and group
// contextual tuples for a given target resource.
func buildAllContextualTuples(attributes authorizer.Attributes, rootResourceType, targetResource string) []*openfgav1.TupleKey {
	groupTuples := buildGroupContextualTuples(attributes)
	tuples := make([]*openfgav1.TupleKey, 0, 1+len(groupTuples))
	tuples = append(tuples, buildRootBindingContextualTuple(rootResourceType, targetResource))
	tuples = append(tuples, groupTuples...)
	return tuples
}

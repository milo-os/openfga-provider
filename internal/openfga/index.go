package openfga

import (
	"fmt"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

const (
	// TargetObjectIndexField indexes PolicyBindings by their OpenFGA target object key.
	TargetObjectIndexField = "openfga.targetObject"
	// TargetKindIndexField indexes PolicyBindings by APIGroup/Kind target selector.
	TargetKindIndexField = "openfga.targetKind"
	// RoleRefIndexField indexes PolicyBindings by roleRef namespace/name.
	RoleRefIndexField = "openfga.roleRef"
)

// TargetObjectFromResourceSelector returns the OpenFGA target object identifier for a selector.
func TargetObjectFromResourceSelector(selector iamdatumapiscomv1alpha1.ResourceSelector) (string, error) {
	if selector.ResourceRef != nil {
		ref := selector.ResourceRef
		if ref.Namespace != "" {
			return fmt.Sprintf("%s/%s:%s/%s", ref.APIGroup, ref.Kind, ref.Namespace, ref.Name), nil
		}
		return fmt.Sprintf("%s/%s:%s", ref.APIGroup, ref.Kind, ref.Name), nil
	}

	if selector.ResourceKind != nil {
		return fmt.Sprintf("%s:%s/%s", TypeRoot, selector.ResourceKind.APIGroup, selector.ResourceKind.Kind), nil
	}

	return "", fmt.Errorf("resourceSelector must specify either resourceRef or resourceKind")
}

// TargetKindFromResourceSelector returns the APIGroup/Kind key for a PolicyBinding selector.
func TargetKindFromResourceSelector(selector iamdatumapiscomv1alpha1.ResourceSelector) (string, error) {
	if selector.ResourceRef != nil {
		return fmt.Sprintf("%s/%s", selector.ResourceRef.APIGroup, selector.ResourceRef.Kind), nil
	}

	if selector.ResourceKind != nil {
		return fmt.Sprintf("%s/%s", selector.ResourceKind.APIGroup, selector.ResourceKind.Kind), nil
	}

	return "", fmt.Errorf("resourceSelector must specify either resourceRef or resourceKind")
}

// RoleRefIndexKey returns the index key for a PolicyBinding roleRef.
// When roleRef.Namespace is empty it defaults to the PolicyBinding namespace.
func RoleRefIndexKey(policyBindingNamespace string, roleRef iamdatumapiscomv1alpha1.RoleReference) string {
	namespace := roleRef.Namespace
	if namespace == "" {
		namespace = policyBindingNamespace
	}
	return namespace + "/" + roleRef.Name
}

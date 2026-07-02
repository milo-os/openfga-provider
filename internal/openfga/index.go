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
		return fmt.Sprintf("%s/%s:%s", selector.ResourceRef.APIGroup, selector.ResourceRef.Kind, selector.ResourceRef.Name), nil
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
func RoleRefIndexKey(roleRef iamdatumapiscomv1alpha1.RoleReference) string {
	return roleRef.Namespace + "/" + roleRef.Name
}

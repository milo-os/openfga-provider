package openfga

import (
	"testing"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

func TestTargetObjectFromResourceSelector(t *testing.T) {
	key, err := TargetObjectFromResourceSelector(iamdatumapiscomv1alpha1.ResourceSelector{
		ResourceRef: &iamdatumapiscomv1alpha1.ResourceReference{
			APIGroup: "resourcemanager.miloapis.com",
			Kind:     "Organization",
			Name:     "org-abc",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "resourcemanager.miloapis.com/Organization:org-abc" {
		t.Fatalf("got %q", key)
	}
}

func TestTargetObjectFromResourceSelectorWithNamespace(t *testing.T) {
	key, err := TargetObjectFromResourceSelector(iamdatumapiscomv1alpha1.ResourceSelector{
		ResourceRef: &iamdatumapiscomv1alpha1.ResourceReference{
			APIGroup:  "resourcemanager.miloapis.com",
			Kind:      "Project",
			Name:      "proj-abc",
			Namespace: "org-ns",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "resourcemanager.miloapis.com/Project:proj-abc" {
		t.Fatalf("got %q", key)
	}
}

func TestTargetKindFromResourceSelector(t *testing.T) {
	key, err := TargetKindFromResourceSelector(iamdatumapiscomv1alpha1.ResourceSelector{
		ResourceRef: &iamdatumapiscomv1alpha1.ResourceReference{
			APIGroup: "resourcemanager.miloapis.com",
			Kind:     "Organization",
			Name:     "org-abc",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "resourcemanager.miloapis.com/Organization" {
		t.Fatalf("got %q", key)
	}
}

func TestRoleRefIndexKey(t *testing.T) {
	key := RoleRefIndexKey("datum-cloud", iamdatumapiscomv1alpha1.RoleReference{
		Name:      "owner",
		Namespace: "datum-cloud",
	})
	if key != "datum-cloud/owner" {
		t.Fatalf("got %q", key)
	}
}

func TestRoleRefIndexKeyDefaultsToPolicyBindingNamespace(t *testing.T) {
	key := RoleRefIndexKey("org-abc", iamdatumapiscomv1alpha1.RoleReference{
		Name: "owner",
	})
	if key != "org-abc/owner" {
		t.Fatalf("got %q", key)
	}
}

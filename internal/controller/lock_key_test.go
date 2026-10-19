package controller

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
)

// The three writers that must exclude each other name one object by one key:
// a binding by its target, a Project's parent tuple by its owner, and the
// finalizer by the object it holds. A key that differs at one site is a lock
// that excludes nothing.
func TestOneObjectHasOneLockKey(t *testing.T) {
	logic := newFinalizerLogic(t, &fgaTupleStore{})
	for _, obj := range []client.Object{
		&resourcemanagerv1alpha1.Organization{ObjectMeta: metav1.ObjectMeta{Name: "org-a"}},
		&resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{Name: "p1"}},
	} {
		finalizerKey, err := logic.objectName(obj)
		require.NoError(t, err)
		gvk, err := logic.groupKind(obj)
		require.NoError(t, err)
		bindingKey, err := openfga.TargetObjectFromResourceSelector(iamdatumapiscomv1alpha1.ResourceSelector{
			ResourceRef: &iamdatumapiscomv1alpha1.ResourceReference{APIGroup: gvk.Group, Kind: gvk.Kind, Name: obj.GetName()},
		})
		require.NoError(t, err)
		parentKey := parentUser(metav1.OwnerReference{
			APIVersion: resourcemanagerv1alpha1.GroupVersion.String(), Kind: gvk.Kind, Name: obj.GetName(),
		})

		want := openfga.ObjectName(resourcemanagerv1alpha1.GroupVersion.Group, gvk.Kind, obj.GetName())
		require.Equal(t, want, finalizerKey, "the finalizer's key")
		require.Equal(t, want, bindingKey, "a binding's key")
		require.Equal(t, want, parentKey, "a parent tuple's key")
	}
}

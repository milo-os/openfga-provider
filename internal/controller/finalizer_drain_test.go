package controller

import (
	"context"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"

	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
)

const (
	miloProjectFinalizer    = "resourcemanager.miloapis.com/project-controller"
	zitadelProjectFinalizer = "auth-provider-zitadel.miloapis.com/project"
)

// newProjectFinalizing is a hierarchy reconciler with its finalizer registered,
// over the ProtectedResources the cleanup reads parents from.
func newProjectFinalizing(t *testing.T, store *fgaTupleStore, objs ...client.Object) *ResourceOwnerHierarchyReconciler {
	t.Helper()
	r := newHierarchyReconciler(t, store, append(hierarchyResources(), objs...)...)
	r.Finalizers = finalizer.NewFinalizers()
	require.NoError(t, r.Finalizers.Register(resourceOwnerHierarchyFinalizer, &ResourceOwnerHierarchyFinalizerLogic{
		Client: r.Client, FGAClient: store, FGAStoreID: testStoreID,
	}))
	return r
}

func deletingProject(finalizers ...string) *resourcemanagerv1alpha1.Project {
	now := metav1.Now()
	return &resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{
		Name: "p1", UID: targetUID, DeletionTimestamp: &now, Finalizers: finalizers,
	}}
}

func reconcileProject(t *testing.T, r *ResourceOwnerHierarchyReconciler) {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1"}})
	require.NoError(t, err)
}

// removeFinalizer takes one finalizer off the stored object, as its owner does.
func removeFinalizer(t *testing.T, c client.Client, obj client.Object, name string) {
	t.Helper()
	require.NoError(t, c.Get(context.Background(), client.ObjectKeyFromObject(obj), obj))
	controllerutil.RemoveFinalizer(obj, name)
	require.NoError(t, c.Update(context.Background(), obj))
}

// Access lasts while Milo drains a Project: its tuples are cleared only once
// Milo's own finalizer has left it, and then even while another component's
// finalizer, which waits for nothing of ours, is still on it.
func TestProjectTuplesLastThroughMilosDrain(t *testing.T) {
	const object = projectType + ":p1"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{grant("alice", object)}}
	project := deletingProject(miloProjectFinalizer, zitadelProjectFinalizer, resourceOwnerHierarchyFinalizer)
	r := newProjectFinalizing(t, store, project)

	reconcileProject(t, r)
	require.Len(t, store.naming(object), 1, "the Project's tuples were cleared while Milo was still draining it")

	removeFinalizer(t, r.Client, &resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}, miloProjectFinalizer)
	reconcileProject(t, r)
	require.Empty(t, store.naming(object), "the tuples stayed after Milo's drain, while another finalizer was still on")

	got := &resourcemanagerv1alpha1.Project{}
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Name: "p1"}, got))
	require.Equal(t, []string{zitadelProjectFinalizer}, got.Finalizers, "ours stayed, or another's was taken")
}

// An Organization's tuples are cleared only once Milo's own finalizer has left
// it; Milo removes its namespace after the Organization is gone, so waiting for
// the namespace would deadlock.
func TestOrganizationTuplesWaitForMilosFinalizerOnly(t *testing.T) {
	const object = organizationType + ":org-a"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{grant("alice", object)}}
	org := deletingOrganization("org-a")
	org.Finalizers = []string{miloOrgFinalizer, resourceOwnerHierarchyFinalizer}
	r := newOrganizationReconciler(t, store, org)

	require.NoError(t, reconcileOrganization(t, r, "org-a"))
	require.Len(t, store.naming(object), 1, "the Organization's tuples were cleared while Milo's finalizer was on it")

	removeFinalizer(t, r.Client, &resourcemanagerv1alpha1.Organization{ObjectMeta: metav1.ObjectMeta{Name: "org-a"}}, miloOrgFinalizer)
	require.NoError(t, reconcileOrganization(t, r, "org-a"))
	require.Empty(t, store.naming(object))
	err := r.Get(context.Background(), types.NamespacedName{Name: "org-a"}, &resourcemanagerv1alpha1.Organization{})
	require.True(t, apierrors.IsNotFound(err), "the Organization stayed after its tuples were gone: %v", err)
}

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
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
)

func newOrganizationReconciler(t *testing.T, store *fgaTupleStore, objs ...client.Object) *OrganizationReconciler {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(protectedResourceScheme(t)).
		WithObjects(append(hierarchyResources(), objs...)...).
		Build()
	r := &OrganizationReconciler{Client: c, FGAClient: store, FGAStoreID: testStoreID, Locks: NewObjectLocks(0)}
	require.NoError(t, r.registerFinalizer())
	return r
}

func reconcileOrganization(t *testing.T, r *OrganizationReconciler, name string) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	return err
}

func deletingOrganization(name string) *resourcemanagerv1alpha1.Organization {
	now := metav1.Now()
	return &resourcemanagerv1alpha1.Organization{ObjectMeta: metav1.ObjectMeta{
		Name:              name,
		DeletionTimestamp: &now,
		Finalizers:        []string{resourceOwnerHierarchyFinalizer},
	}}
}

func TestOrganizationReconcilerHoldsALiveOrganization(t *testing.T) {
	org := &resourcemanagerv1alpha1.Organization{ObjectMeta: metav1.ObjectMeta{Name: "org-a"}}
	r := newOrganizationReconciler(t, &fgaTupleStore{}, org)

	require.NoError(t, reconcileOrganization(t, r, "org-a"))

	got := &resourcemanagerv1alpha1.Organization{}
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Name: "org-a"}, got))
	require.True(t, controllerutil.ContainsFinalizer(got, resourceOwnerHierarchyFinalizer),
		"a live Organization carries no finalizer, so its deletion would not wait for its tuples")
}

func TestOrganizationReconcilerReleasesOnlyAfterItsTuplesAreGone(t *testing.T) {
	const object = organizationType + ":org-a"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{grant("alice", object), parentTuple(object, projectType+":p1")}}
	r := newOrganizationReconciler(t, store, deletingOrganization("org-a"))

	require.NoError(t, reconcileOrganization(t, r, "org-a"))

	require.Empty(t, store.naming(object))
	err := r.Get(context.Background(), types.NamespacedName{Name: "org-a"}, &resourcemanagerv1alpha1.Organization{})
	require.True(t, apierrors.IsNotFound(err), "the Organization stayed after its tuples were gone: %v", err)
}

func TestOrganizationReconcilerHoldsWhileATupleRemains(t *testing.T) {
	const object = organizationType + ":org-a"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{grant("alice", object)}}
	store.afterWrite = func(s *fgaTupleStore) {
		s.afterWrite = nil
		s.put(grant("carol", object))
	}
	r := newOrganizationReconciler(t, store, deletingOrganization("org-a"))

	require.Error(t, reconcileOrganization(t, r, "org-a"))

	got := &resourcemanagerv1alpha1.Organization{}
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Name: "org-a"}, got),
		"the Organization was released while a tuple named it")
	require.True(t, controllerutil.ContainsFinalizer(got, resourceOwnerHierarchyFinalizer))
}

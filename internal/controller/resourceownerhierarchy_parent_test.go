package controller

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

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

const (
	ownerUID         = "uid-org-a"
	miloOrgFinalizer = "resourcemanager.miloapis.com/organization-namespace"
)

func newHierarchyReconciler(t *testing.T, store *fgaTupleStore, objs ...client.Object) *ResourceOwnerHierarchyReconciler {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(protectedResourceScheme(t)).WithObjects(objs...).Build()
	return &ResourceOwnerHierarchyReconciler{
		Client:                 c,
		FGAClient:              store,
		FGAStoreID:             testStoreID,
		validProjectParentGVKs: projectParentGVKs(),
		Locks:                  NewObjectLocks(0),
	}
}

// ownedProject is a Project that already carries the provider's finalizer, so a
// reconcile goes straight to its parent tuples.
func ownedProject() *resourcemanagerv1alpha1.Project {
	return &resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{
		Name:       "p1",
		Finalizers: []string{resourceOwnerHierarchyFinalizer},
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: resourcemanagerv1alpha1.GroupVersion.String(),
			Kind:       "Organization",
			Name:       "org-a",
			UID:        ownerUID,
		}},
	}}
}

// owner is the Project's Organization with the given UID and finalizers; for a
// deleting owner, its deletion has started.
func owner(uid types.UID, deleting bool, finalizers ...string) *resourcemanagerv1alpha1.Organization {
	org := &resourcemanagerv1alpha1.Organization{ObjectMeta: metav1.ObjectMeta{Name: "org-a", UID: uid, Finalizers: finalizers}}
	if deleting {
		now := metav1.Now()
		org.DeletionTimestamp = &now
	}
	return org
}

func TestProjectParentTupleFollowsItsOwnersHold(t *testing.T) {
	const org, project = organizationType + ":org-a", projectType + ":p1"
	ours := resourceOwnerHierarchyFinalizer
	cases := []struct {
		name       string
		owner      *resourcemanagerv1alpha1.Organization
		stored     bool
		wantParent bool
	}{
		{name: "held: kept", owner: owner(ownerUID, false, ours), stored: true, wantParent: true},
		{name: "held: written", owner: owner(ownerUID, false, ours), wantParent: true},
		{name: "not yet held: held, then written", owner: owner(ownerUID, false), wantParent: true},
		{name: "deleting: kept for its finalizer", owner: owner(ownerUID, true, miloOrgFinalizer, ours), stored: true, wantParent: true},
		{name: "deleting: not written", owner: owner(ownerUID, true, miloOrgFinalizer, ours)},
		{name: "replaced: deleted", owner: owner("uid-org-a-later", false, ours), stored: true},
		{name: "missing: deleted", stored: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fgaTupleStore{}
			if tc.stored {
				store.put(parentTuple(org, project))
			}
			objs := []client.Object{ownedProject()}
			if tc.owner != nil {
				objs = append(objs, tc.owner)
			}
			r := newHierarchyReconciler(t, store, objs...)

			res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1"}})

			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, res)
			require.Equal(t, tc.wantParent, len(store.naming(org)) == 1, "parent tuples naming the owner: %v", store.naming(org))
			wantWrites := 0
			if tc.wantParent && !tc.stored {
				wantWrites = 1
			}
			require.Equal(t, wantWrites, store.added, "a parent tuple was written, though it should not have been")
			if tc.wantParent {
				got := &resourcemanagerv1alpha1.Organization{}
				require.NoError(t, r.Get(context.Background(), types.NamespacedName{Name: "org-a"}, got))
				require.True(t, controllerutil.ContainsFinalizer(got, ours), "a parent tuple names an owner our finalizer does not hold")
			}
		})
	}
}

// While a parent tuple's write is in flight, the owner's finalizer waits: the
// Organization's deletion cannot complete between the hold check and the write.
func TestOrganizationFinalizerWaitsForAParentWrite(t *testing.T) {
	const org = organizationType + ":org-a"
	store := &fgaTupleStore{}
	h := newHierarchyReconciler(t, store, append(hierarchyResources(), ownedProject(), owner(ownerUID, false, resourceOwnerHierarchyFinalizer))...)
	o := &OrganizationReconciler{Client: h.Client, FGAClient: store, FGAStoreID: testStoreID, Locks: h.Locks}
	require.NoError(t, o.registerFinalizer())
	writing, proceed := make(chan struct{}), make(chan struct{})
	store.beforeWrite = func(s *fgaTupleStore) {
		s.beforeWrite = nil
		close(writing)
		<-proceed
	}
	var landedAfterDeletion atomic.Bool
	store.afterWrite = func(*fgaTupleStore) {
		err := h.Get(context.Background(), types.NamespacedName{Name: "org-a"}, &resourcemanagerv1alpha1.Organization{})
		landedAfterDeletion.Store(landedAfterDeletion.Load() || apierrors.IsNotFound(err))
	}
	synced := make(chan struct{})
	go func() {
		defer close(synced)
		_, _ = h.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1"}})
	}()
	<-writing

	require.NoError(t, h.Delete(context.Background(), owner(ownerUID, false)))
	finalized := make(chan struct{})
	go func() {
		defer close(finalized)
		_ = reconcileOrganization(t, o, "org-a")
	}()
	select {
	case <-finalized:
	case <-time.After(200 * time.Millisecond):
	}
	close(proceed)
	<-synced
	<-finalized

	require.False(t, landedAfterDeletion.Load(), "a parent tuple landed after its Organization's deletion completed")
	require.NoError(t, reconcileOrganization(t, o, "org-a"))
	require.Empty(t, store.naming(org), "a tuple names the deleted Organization")
}

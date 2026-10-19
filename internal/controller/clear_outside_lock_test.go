package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"

	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
)

// slowDelete is how long the store takes over one delete in these tests,
// standing in for a Project whose grants take seconds to clear.
const slowDelete = 600 * time.Millisecond

// A Project's slow clear holds no lock that a binding on another target waits
// on: the binding waits at most for the finalizer's one locked read.
func TestSlowClearDoesNotHoldUpAnotherTargetsWrite(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	// Every object on one lock, as two objects that hash to the same lock are.
	one := NewObjectLocks(1)
	w.binding.Locks, w.hierarchy.Locks = one, one
	const clearing = projectType + ":p0"
	deleting := &resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{
		Name: "p0", UID: "uid-p0", Finalizers: []string{resourceOwnerHierarchyFinalizer}}}
	require.NoError(t, w.client.Create(context.Background(), deleting))
	require.NoError(t, w.client.Delete(context.Background(), deleting))
	w.store.put(grant("bob", clearing))
	started := make(chan struct{})
	var once sync.Once
	w.store.beforeDelete = func(*fgaTupleStore) {
		once.Do(func() { close(started); time.Sleep(slowDelete) })
	}
	cleared := make(chan error, 1)
	go func() {
		_, err := w.hierarchy.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "p0"}})
		cleared <- err
	}()
	<-started

	begin := time.Now()
	_, ready := w.reconcileBinding(t)
	waited := time.Since(begin)

	require.NoError(t, <-cleared)
	t.Logf("a binding on another target wrote in %v while a clear took %v", waited, slowDelete)
	require.Equal(t, metav1.ConditionTrue, ready.Status, ready.Message)
	require.Len(t, w.store.naming(w.object), 1, "the binding on the other target did not write")
	require.Less(t, waited, slowDelete/3, "the binding waited on the clear")
	require.Empty(t, w.store.naming(clearing), "a tuple names the deleted Project")
}

// A write that lands during the clear, after its read, is found by the
// finalizer's locked read: the finalizer stays, and the retry clears it.
func TestWriteDuringTheClearIsCaughtByTheLockedRead(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	w.startDeletion(t)
	w.store.put(grant("alice", w.object))
	var once sync.Once
	w.store.beforeDelete = func(s *fgaTupleStore) {
		once.Do(func() { s.put(grant("carol", w.object)) })
	}

	_, err := w.hierarchy.Reconcile(context.Background(), w.projectRequest())

	require.Error(t, err, "the finalizer released while a tuple named the Project")
	held := gateProject()
	require.NoError(t, w.client.Get(context.Background(), types.NamespacedName{Name: "p1"}, held))
	require.True(t, controllerutil.ContainsFinalizer(held, resourceOwnerHierarchyFinalizer))
	require.Len(t, w.store.naming(w.object), 1, "the write that landed during the clear is not the one left")

	reconcileProject(t, w.hierarchy)
	require.Empty(t, w.store.naming(w.object), "a tuple names the deleted Project")
}

// A live Project and a live Organization keep every tuple that names them
// across reconciles: only a deletion, after Milo's drain, clears them. A clear
// on a live object would revoke everyone's access.
func TestLiveObjectsKeepTheirTuples(t *testing.T) {
	const org, project = organizationType + ":org-a", projectType + ":p1"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{grant("alice", org), grant("bob", project), parentTuple(org, project)}}
	h := newHierarchyReconciler(t, store, append(hierarchyResources(), ownedProject(), owner(ownerUID, false, resourceOwnerHierarchyFinalizer))...)
	h.Finalizers = finalizer.NewFinalizers()
	require.NoError(t, h.Finalizers.Register(resourceOwnerHierarchyFinalizer, h.finalizerLogic()))
	o := &OrganizationReconciler{Client: h.Client, FGAClient: store, FGAStoreID: testStoreID, Locks: h.Locks}
	require.NoError(t, o.registerFinalizer())

	for range 2 {
		reconcileProject(t, h)
		require.NoError(t, reconcileOrganization(t, o, "org-a"))
	}

	require.Len(t, store.naming(project), 2, "a live Project lost a tuple naming it")
	require.Len(t, store.naming(org), 2, "a live Organization lost a tuple naming it")
}

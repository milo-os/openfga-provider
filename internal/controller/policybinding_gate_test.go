package controller

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"

	"go.miloapis.com/auth-provider-openfga/internal/openfga"
)

const (
	targetUID     = "uid-p1"
	viewerPerm    = "resourcemanager.miloapis.com/projects.get"
	bindingName   = "p1-viewer"
	bindingNS     = "milo-system"
	aliceUID      = "uid-alice"
	gateStressRun = 200
)

// gateWorld is one PolicyBinding on one target, with the binding controller and
// the hierarchy controller sharing a client and an OpenFGA store.
type gateWorld struct {
	binding   *PolicyBindingReconciler
	hierarchy *ResourceOwnerHierarchyReconciler
	client    client.Client
	store     *fgaTupleStore
	object    string
}

func newGateWorld(t *testing.T, kind string, target client.Object, funcs interceptor.Funcs) *gateWorld {
	t.Helper()
	s := protectedResourceScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&iamdatumapiscomv1alpha1.PolicyBinding{}).
		WithIndex(&iamdatumapiscomv1alpha1.ProtectedResource{}, protectedResourceServiceKindIndexField, protectedResourceServiceKind).
		WithIndex(&iamdatumapiscomv1alpha1.PolicyBinding{}, openfga.TargetObjectIndexField, bindingTargetObject).
		WithObjects(append(hierarchyResources(), target, gateRole(), gateUser(), gateBinding(kind, target.GetName()))...).
		WithInterceptorFuncs(funcs).
		Build()
	store := &fgaTupleStore{}
	r := &PolicyBindingReconciler{Client: c, Scheme: s, RESTMapper: gateMapper(), FgaClient: store, StoreID: testStoreID,
		Finalizers: finalizer.NewFinalizers()}
	require.NoError(t, r.Finalizers.Register(policyBindingFinalizerKey, &openFGAFinalizer{Client: c, fgaClient: store, storeID: testStoreID,
		policyReconciler: &openfga.PolicyReconciler{StoreID: testStoreID, Client: store, K8sClient: c}}))
	h := &ResourceOwnerHierarchyReconciler{Client: c, FGAClient: store, FGAStoreID: testStoreID, validProjectParentGVKs: projectParentGVKs(),
		Finalizers: finalizer.NewFinalizers()}
	require.NoError(t, h.Finalizers.Register(resourceOwnerHierarchyFinalizer, &ResourceOwnerHierarchyFinalizerLogic{Client: c, FGAClient: store, FGAStoreID: testStoreID}))
	return &gateWorld{binding: r, hierarchy: h, client: c, store: store, object: fgaObject(resourceManagerGroup, kind, target.GetName())}
}

func bindingTargetObject(rawObj client.Object) []string {
	pb, ok := rawObj.(*iamdatumapiscomv1alpha1.PolicyBinding)
	if !ok {
		return nil
	}
	object, err := openfga.TargetObjectFromResourceSelector(pb.Spec.ResourceSelector)
	if err != nil {
		return nil
	}
	return []string{object}
}

func gateMapper() meta.RESTMapper {
	m := meta.NewDefaultRESTMapper([]schema.GroupVersion{resourcemanagerv1alpha1.GroupVersion, iamdatumapiscomv1alpha1.SchemeGroupVersion})
	m.Add(resourcemanagerv1alpha1.GroupVersion.WithKind("Project"), meta.RESTScopeRoot)
	m.Add(resourcemanagerv1alpha1.GroupVersion.WithKind("Organization"), meta.RESTScopeRoot)
	m.Add(iamdatumapiscomv1alpha1.SchemeGroupVersion.WithKind("User"), meta.RESTScopeRoot)
	return m
}

func gateRole() *iamdatumapiscomv1alpha1.Role {
	return &iamdatumapiscomv1alpha1.Role{ObjectMeta: metav1.ObjectMeta{Name: "viewer", Namespace: bindingNS},
		Spec: iamdatumapiscomv1alpha1.RoleSpec{IncludedPermissions: []string{viewerPerm}}}
}

func gateUser() *iamdatumapiscomv1alpha1.User {
	return &iamdatumapiscomv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: "alice", UID: aliceUID}}
}

func gateBinding(kind, target string) *iamdatumapiscomv1alpha1.PolicyBinding {
	return &iamdatumapiscomv1alpha1.PolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: bindingName, Namespace: bindingNS, Finalizers: []string{policyBindingFinalizerKey}},
		Spec: iamdatumapiscomv1alpha1.PolicyBindingSpec{
			RoleRef:  iamdatumapiscomv1alpha1.RoleReference{Name: "viewer", Namespace: bindingNS},
			Subjects: []iamdatumapiscomv1alpha1.Subject{{Kind: "User", Name: "alice", UID: aliceUID}},
			ResourceSelector: iamdatumapiscomv1alpha1.ResourceSelector{ResourceRef: &iamdatumapiscomv1alpha1.ResourceReference{
				APIGroup: resourceManagerGroup, Kind: kind, Name: target, UID: targetUID,
			}},
		},
	}
}

// aliceGrant is the tuple the binding writes on its target.
func (w *gateWorld) aliceGrant() *openfgav1.TupleKey {
	return &openfgav1.TupleKey{User: openfga.TypeInternalUser + ":alice", Relation: openfga.HashPermission(viewerPerm), Object: w.object}
}

func gateProject(finalizers ...string) *resourcemanagerv1alpha1.Project {
	return &resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{Name: "p1", UID: targetUID, Finalizers: finalizers}}
}

// reconcileBinding runs the binding controller once and returns its result and
// the binding's Ready condition.
func (w *gateWorld) reconcileBinding(t *testing.T) (ctrl.Result, *metav1.Condition) {
	t.Helper()
	res, err := w.binding.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: bindingName, Namespace: bindingNS}})
	require.NoError(t, err)
	pb := &iamdatumapiscomv1alpha1.PolicyBinding{}
	require.NoError(t, w.client.Get(context.Background(), types.NamespacedName{Name: bindingName, Namespace: bindingNS}, pb))
	return res, meta.FindStatusCondition(pb.Status.Conditions, "Ready")
}

// startDeletion starts the target's deletion, as a user does.
func (w *gateWorld) startDeletion(t *testing.T) {
	t.Helper()
	require.NoError(t, w.client.Delete(context.Background(), gateProject()))
}

// A converged binding keeps its status while Milo drains its Project and after,
// and writes nothing: its tuples already exist, and access lasts through the drain.
func TestConvergedBindingStaysReadyThroughTheDrain(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(miloProjectFinalizer, resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	w.store.put(w.aliceGrant())
	w.startDeletion(t)

	_, ready := w.reconcileBinding(t)
	require.Equal(t, metav1.ConditionTrue, ready.Status, "a converged binding went Not Ready while its Project drains: %s", ready.Message)

	removeFinalizer(t, w.client, gateProject(), miloProjectFinalizer)
	_, ready = w.reconcileBinding(t)
	require.Equal(t, metav1.ConditionTrue, ready.Status, "a converged binding went Not Ready after the drain: %s", ready.Message)
	require.Zero(t, w.store.added, "a converged binding wrote")
	require.Len(t, w.store.naming(w.object), 1)
}

// A binding that needs a write onto a target being deleted writes nothing, says
// why in plain words, and is retried.
func TestBindingWritesNothingOntoADeletingTarget(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(miloProjectFinalizer, resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	w.startDeletion(t)

	res, ready := w.reconcileBinding(t)

	require.Zero(t, w.store.added, "the binding wrote onto a Project being deleted")
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Equal(t, reasonWaitingForTarget, ready.Reason)
	require.Equal(t, "No permissions were written, because the Project p1 is being deleted. Retrying.", ready.Message)
	require.Equal(t, ctrl.Result{Requeue: true}, res)
}

// A binding whose target lacks our finalizer adds it itself, then writes in the
// same reconcile: a new Project's first access does not wait on the hierarchy
// controller's queue.
func TestBindingHoldsItsTargetThenWrites(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(), interceptor.Funcs{})
	var heldAtWrite bool
	w.store.beforeWrite = func(*fgaTupleStore) {
		target := gateProject()
		require.NoError(t, w.client.Get(context.Background(), types.NamespacedName{Name: "p1"}, target))
		heldAtWrite = controllerutil.ContainsFinalizer(target, resourceOwnerHierarchyFinalizer)
	}

	_, ready := w.reconcileBinding(t)

	require.Equal(t, metav1.ConditionTrue, ready.Status, ready.Message)
	require.Len(t, w.store.naming(w.object), 1, "the binding did not write")
	require.True(t, heldAtWrite, "the binding wrote while its target lacked our finalizer")
}

// A target our finalizer already holds costs the binding no write to it.
func TestHeldTargetCostsNoWrite(t *testing.T) {
	var projectUpdates atomic.Int32
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if obj.GetObjectKind().GroupVersionKind().Kind == "Project" {
				projectUpdates.Add(1)
			}
			return c.Update(ctx, obj, opts...)
		},
	})

	_, ready := w.reconcileBinding(t)

	require.Equal(t, metav1.ConditionTrue, ready.Status, ready.Message)
	require.Len(t, w.store.naming(w.object), 1)
	require.Zero(t, projectUpdates.Load(), "the binding wrote to a target already held")
}

// At rollout, an Organization lacks our finalizer until its turn comes; a
// converged binding on it keeps its status and writes nothing.
func TestConvergedBindingStaysReadyOnAnOrganizationNotYetHeld(t *testing.T) {
	org := &resourcemanagerv1alpha1.Organization{ObjectMeta: metav1.ObjectMeta{Name: "org-a", UID: targetUID, Finalizers: []string{miloOrgFinalizer}}}
	w := newGateWorld(t, "Organization", org, interceptor.Funcs{})
	w.store.put(w.aliceGrant())

	_, ready := w.reconcileBinding(t)

	require.Equal(t, metav1.ConditionTrue, ready.Status, "a converged binding flipped at rollout: %s", ready.Message)
	require.Zero(t, w.store.added)
}

// A failed read of the target writes nothing.
func TestBindingWritesNothingWhenTheTargetCannotBeRead(t *testing.T) {
	var projectGets atomic.Int32
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if obj.GetObjectKind().GroupVersionKind().Kind == "Project" && projectGets.Add(1) > 1 {
				return errors.New("milo unavailable")
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})

	_, err := w.binding.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: bindingName, Namespace: bindingNS}})

	require.Error(t, err)
	require.Zero(t, w.store.added, "the binding wrote although its target could not be read")
}

// While a binding's guarded write is in flight, the target's finalizer waits:
// the target's deletion cannot complete between the check and the write.
func TestFinalizerWaitsForAGuardedWrite(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	writing, proceed := make(chan struct{}), make(chan struct{})
	w.store.beforeWrite = func(s *fgaTupleStore) {
		s.beforeWrite = nil
		close(writing)
		<-proceed
	}
	var landedAfterDeletion atomic.Bool
	w.store.afterWrite = func(s *fgaTupleStore) {
		if apierrors.IsNotFound(w.client.Get(context.Background(), types.NamespacedName{Name: "p1"}, gateProject())) {
			landedAfterDeletion.Store(true)
		}
	}
	bindingDone := make(chan struct{})
	go func() {
		defer close(bindingDone)
		_, _ = w.binding.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: bindingName, Namespace: bindingNS}})
	}()
	<-writing

	w.startDeletion(t)
	finalized := make(chan struct{})
	go func() {
		defer close(finalized)
		_, _ = w.hierarchy.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1"}})
	}()
	select {
	case <-finalized:
		close(proceed)
	case <-time.After(200 * time.Millisecond):
		close(proceed)
		<-finalized
	}
	<-bindingDone

	require.False(t, landedAfterDeletion.Load(), "a binding's tuple landed after its Project's deletion completed")
	reconcileProject(t, w.hierarchy)
	require.Empty(t, w.store.naming(w.object), "a tuple names the deleted Project")
}

// timeToWrite measures how long one binding reconcile takes to land its write,
// so the stress can start each deletion across that span.
func timeToWrite(t *testing.T) time.Duration {
	t.Helper()
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	start := time.Now()
	var landed time.Duration
	w.store.afterWrite = func(*fgaTupleStore) { landed = time.Since(start) }
	w.reconcileBinding(t)
	require.Positive(t, landed, "the binding did not write, so there is nothing to race")
	return landed
}

// A binding's write races its target's deletion, many times over: no tuple ever
// lands after the deletion completes, and none names the target once it is gone.
func TestBindingWriteRacingTheFinalizerStress(t *testing.T) {
	toWrite := timeToWrite(t)
	wrote, deleted := 0, 0
	for i := range gateStressRun {
		// The deletion starts anywhere from before the binding begins to after it has written.
		delay := time.Duration(rand.Int64N(int64(2 * toWrite)))
		w, d := raceOnce(t, fmt.Sprintf("run-%d", i), delay)
		wrote += w
		deleted += d
	}
	t.Logf("%d runs: a write landed in %d, the deletion completed in %d", gateStressRun, wrote, deleted)
	require.Positive(t, wrote, "no run wrote, so the race was never exercised")
	require.Positive(t, deleted, "no run completed the deletion, so the race was never exercised")
}

// raceOnce runs one binding reconcile against one deletion started after
// delay, checks the invariants, and returns 1 for a write that landed and 1 for
// a deletion that completed.
func raceOnce(t *testing.T, name string, delay time.Duration) (wrote, deleted int) {
	t.Run(name, func(t *testing.T) {
		w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
		var landedAfterDeletion atomic.Bool
		w.store.afterWrite = func(*fgaTupleStore) {
			if apierrors.IsNotFound(w.client.Get(context.Background(), types.NamespacedName{Name: "p1"}, gateProject())) {
				landedAfterDeletion.Store(true)
			}
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			w.reconcileRepeatedly(func() error { _, err := w.binding.Reconcile(context.Background(), w.bindingRequest()); return err })
		}()
		go func() {
			defer wg.Done()
			time.Sleep(delay)
			_ = w.client.Delete(context.Background(), gateProject())
			w.reconcileRepeatedly(func() error { _, err := w.hierarchy.Reconcile(context.Background(), w.projectRequest()); return err })
		}()
		wg.Wait()

		require.False(t, landedAfterDeletion.Load(), "a binding's tuple landed after its Project's deletion completed")
		wrote = min(w.store.added, 1)
		if apierrors.IsNotFound(w.client.Get(context.Background(), types.NamespacedName{Name: "p1"}, gateProject())) {
			deleted = 1
			require.Empty(t, w.store.naming(w.object), "a tuple names the deleted Project")
		}
	})
	return wrote, deleted
}

// reconcileRepeatedly runs a reconcile three times, as requeues would.
func (w *gateWorld) reconcileRepeatedly(reconcile func() error) {
	for range 3 {
		_ = reconcile()
	}
}

func (w *gateWorld) bindingRequest() ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: bindingName, Namespace: bindingNS}}
}

func (w *gateWorld) projectRequest() ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1"}}
}

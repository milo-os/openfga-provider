package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func storedBinding(t *testing.T, w *gateWorld) *iamdatumapiscomv1alpha1.PolicyBinding {
	t.Helper()
	binding := &iamdatumapiscomv1alpha1.PolicyBinding{}
	require.NoError(t, w.client.Get(context.Background(), types.NamespacedName{Name: bindingName, Namespace: bindingNS}, binding))
	return binding
}

func TestUnchangedBindingSkipsOpenFGAReads(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})

	w.reconcileBinding(t)
	firstReads := w.store.reads
	require.Positive(t, firstReads)
	fingerprint := storedBinding(t, w).Annotations[programmedTupleFingerprintAnnotation]
	require.NotEmpty(t, fingerprint)

	w.reconcileBinding(t)

	require.Equal(t, firstReads, w.store.reads, "an unchanged binding read OpenFGA again")
	require.Equal(t, fingerprint, storedBinding(t, w).Annotations[programmedTupleFingerprintAnnotation])
}

func TestChangedRoleProgramsThenRecordsNewFingerprint(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	w.reconcileBinding(t)
	firstFingerprint := storedBinding(t, w).Annotations[programmedTupleFingerprintAnnotation]

	const updatedPermission = "resourcemanager.miloapis.com/projects.update"
	role := &iamdatumapiscomv1alpha1.Role{}
	require.NoError(t, w.client.Get(context.Background(), types.NamespacedName{Name: "viewer", Namespace: bindingNS}, role))
	role.Spec.IncludedPermissions = []string{updatedPermission}
	require.NoError(t, w.client.Update(context.Background(), role))

	w.reconcileBinding(t)

	tuples := w.store.naming(w.object)
	require.Len(t, tuples, 1)
	require.Equal(t, openfga.HashPermission(updatedPermission), tuples[0].Relation)
	secondFingerprint := storedBinding(t, w).Annotations[programmedTupleFingerprintAnnotation]
	require.NotEmpty(t, secondFingerprint)
	require.NotEqual(t, firstFingerprint, secondFingerprint)
}

func TestFailedReconcileDoesNotRecordFingerprint(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	w.store.readErr = errors.New("OpenFGA unavailable")

	_, err := w.binding.Reconcile(context.Background(), w.bindingRequest())
	require.Error(t, err)
	require.Empty(t, storedBinding(t, w).Annotations[programmedTupleFingerprintAnnotation])

	w.store.readErr = nil
	w.reconcileBinding(t)
	require.NotEmpty(t, storedBinding(t, w).Annotations[programmedTupleFingerprintAnnotation])
}

func TestMissingFingerprintRecoversFromProgrammedTuples(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	w.store.put(w.aliceGrant())

	w.reconcileBinding(t)
	require.Zero(t, w.store.added, "crash recovery rewrote an existing tuple")
	require.NotEmpty(t, storedBinding(t, w).Annotations[programmedTupleFingerprintAnnotation])
	readsAfterRecovery := w.store.reads

	w.reconcileBinding(t)
	require.Equal(t, readsAfterRecovery, w.store.reads, "recovered binding did not take the fast path")
}

func TestChangedBindingPreservesSharedTuple(t *testing.T) {
	w := newGateWorld(t, "Project", gateProject(resourceOwnerHierarchyFinalizer), interceptor.Funcs{})
	sharedRole := gateRole()
	sharedRole.Name = "shared-viewer"
	require.NoError(t, w.client.Create(context.Background(), sharedRole))
	sharedBinding := gateBinding("Project", "p1")
	sharedBinding.Name = "p1-shared-viewer"
	sharedBinding.Spec.RoleRef.Name = sharedRole.Name
	require.NoError(t, w.client.Create(context.Background(), sharedBinding))

	w.reconcileBinding(t)
	_, err := w.binding.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: sharedBinding.Name, Namespace: bindingNS}})
	require.NoError(t, err)

	const updatedPermission = "resourcemanager.miloapis.com/projects.update"
	role := &iamdatumapiscomv1alpha1.Role{}
	require.NoError(t, w.client.Get(context.Background(), types.NamespacedName{Name: "viewer", Namespace: bindingNS}, role))
	role.Spec.IncludedPermissions = []string{updatedPermission}
	require.NoError(t, w.client.Update(context.Background(), role))

	w.reconcileBinding(t)

	relations := map[string]bool{}
	for _, tuple := range w.store.naming(w.object) {
		relations[tuple.Relation] = true
	}
	require.True(t, relations[openfga.HashPermission(viewerPerm)], "the changed binding revoked a tuple its sibling still grants")
	require.True(t, relations[openfga.HashPermission(updatedPermission)], "the changed binding did not activate its new grant")
}

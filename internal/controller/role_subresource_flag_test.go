package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
)

const (
	declaredSubresourcePermission   = "test.example/logs/api.get"
	undeclaredSubresourcePermission = "test.example/logs/archive.get"
	plainPermission                 = "test.example/logs.list"
)

func reconcileRoleConditions(t *testing.T, enabled bool, target string, roles ...*iam.Role) (permissionsValid, ready *metav1.Condition, effective []string) {
	t.Helper()
	s := degradationScheme(t)
	pr := &iam.ProtectedResource{
		ObjectMeta: metav1.ObjectMeta{Name: "logs"},
		Spec: iam.ProtectedResourceSpec{
			ServiceRef:   iam.ServiceReference{Name: "test.example"},
			Kind:         "Log",
			Plural:       "logs",
			Permissions:  []string{"list"},
			Subresources: []iam.SubresourceDefinition{{Name: "api", Permissions: []string{"get"}}},
		},
	}
	builder := fake.NewClientBuilder().WithScheme(s).WithObjects(pr).WithStatusSubresource(&iam.Role{})
	for _, r := range roles {
		builder = builder.WithObjects(r)
	}
	r := &RoleReconciler{Client: builder.Build(), Scheme: s, Finalizers: finalizer.NewFinalizers(), EnableSubresourceAuthorization: enabled}
	key := types.NamespacedName{Namespace: "org-x", Name: target}
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	require.NoError(t, err)
	got := &iam.Role{}
	require.NoError(t, r.Get(context.Background(), key, got))
	return meta.FindStatusCondition(got.Status.Conditions, "PermissionsValid"),
		meta.FindStatusCondition(got.Status.Conditions, "Ready"),
		got.Status.EffectivePermissions
}

func TestRoleSubresourcePermissionsWithFlagOff(t *testing.T) {
	viewer := role("org-x", "logs-viewer", []string{plainPermission, declaredSubresourcePermission})
	orgViewer := role("org-x", "org-viewer", nil, iam.ScopedRoleReference{Name: "logs-viewer"})
	owner := role("org-x", "owner", []string{"test.example/logs.list"}, iam.ScopedRoleReference{Name: "org-viewer"})
	undeclared := role("org-x", "bad", []string{plainPermission, undeclaredSubresourcePermission})

	for _, name := range []string{"logs-viewer", "org-viewer", "owner"} {
		valid, ready, effective := reconcileRoleConditions(t, false, name, viewer.DeepCopy(), orgViewer.DeepCopy(), owner.DeepCopy())
		require.Equal(t, metav1.ConditionTrue, valid.Status, "%s: %s", name, valid.Message)
		require.Equal(t, metav1.ConditionTrue, ready.Status, "%s: %s", name, ready.Message)
		require.Contains(t, effective, declaredSubresourcePermission, name)
		require.Contains(t, valid.Message, "grant nothing: "+declaredSubresourcePermission, name)
	}

	valid, ready, _ := reconcileRoleConditions(t, false, "bad", undeclared)
	require.Equal(t, metav1.ConditionFalse, valid.Status)
	require.Equal(t, "InvalidPermissions", valid.Reason)
	require.Contains(t, valid.Message, undeclaredSubresourcePermission)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
}

func TestRoleSubresourcePermissionsWithFlagOn(t *testing.T) {
	viewer := role("org-x", "logs-viewer", []string{plainPermission, declaredSubresourcePermission})
	orgViewer := role("org-x", "org-viewer", nil, iam.ScopedRoleReference{Name: "logs-viewer"})
	undeclared := role("org-x", "bad", []string{plainPermission, undeclaredSubresourcePermission})

	for _, name := range []string{"logs-viewer", "org-viewer"} {
		valid, ready, _ := reconcileRoleConditions(t, true, name, viewer.DeepCopy(), orgViewer.DeepCopy())
		require.Equal(t, metav1.ConditionTrue, valid.Status, "%s: %s", name, valid.Message)
		require.Equal(t, metav1.ConditionTrue, ready.Status, name)
		require.Equal(t, "All permissions validated successfully.", valid.Message, name)
	}

	valid, _, _ := reconcileRoleConditions(t, true, "bad", undeclared)
	require.Equal(t, metav1.ConditionFalse, valid.Status)
	require.Contains(t, valid.Message, undeclaredSubresourcePermission)
}

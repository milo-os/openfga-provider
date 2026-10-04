package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSubresourceRoleValidationAndRegistrationRemoval(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, iam.AddToScheme(scheme))
	permission := "test.example/widgets/status.patch"
	parent := &iam.Role{ObjectMeta: metav1.ObjectMeta{Name: "status-writer", Namespace: "default"}, Spec: iam.RoleSpec{IncludedPermissions: []string{permission}}}
	inheriting := &iam.Role{ObjectMeta: metav1.ObjectMeta{Name: "inherited-writer", Namespace: "default"}, Spec: iam.RoleSpec{InheritedRoles: []iam.ScopedRoleReference{{Name: parent.Name}}}}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(parent, inheriting).Build()
	pr := iam.ProtectedResource{Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "widgets", Kind: "Widget", Permissions: []string{"patch", "custom.verb", "custom/action"}, Subresources: []iam.SubresourceDefinition{{Name: "status", Permissions: []string{"patch"}}}}}
	for _, enabled := range []bool{false, true} {
		r := RoleReconciler{Client: cli, EnableSubresourceAuthorization: enabled}
		invalid, err := r.validateRolePermissions(ctx, parent, []iam.ProtectedResource{pr}, []string{permission})
		require.NoError(t, err)
		require.Empty(t, invalid)
		invalid, err = r.validateRolePermissions(ctx, parent, []iam.ProtectedResource{pr}, []string{"test.example/widgets.custom.verb", "test.example/widgets.custom/action"})
		require.NoError(t, err)
		require.Empty(t, invalid)
		removed := pr.DeepCopy()
		removed.Spec.Subresources = nil
		affected, err := r.isRoleAffectedByProtectedResource(ctx, inheriting, removed)
		require.NoError(t, err)
		require.True(t, affected, "removed permission must requeue inherited Role")
		invalid, err = r.validateRolePermissions(ctx, parent, []iam.ProtectedResource{*removed}, []string{permission})
		require.NoError(t, err)
		require.Equal(t, []string{permission}, invalid)
	}
}

func TestSubresourceRegistrationRequeuesParentAndRootBindings(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, iam.AddToScheme(scheme))
	bindings := []iam.PolicyBinding{
		{ObjectMeta: metav1.ObjectMeta{Name: "instance", Namespace: "default"}, Spec: iam.PolicyBindingSpec{ResourceSelector: iam.ResourceSelector{ResourceRef: &iam.ResourceReference{APIGroup: "test.example", Kind: "Widget", Name: "one"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "parent", Namespace: "default"}, Spec: iam.PolicyBindingSpec{ResourceSelector: iam.ResourceSelector{ResourceRef: &iam.ResourceReference{APIGroup: "test.example", Kind: "Project", Name: "one"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "root", Namespace: "default"}, Spec: iam.PolicyBindingSpec{ResourceSelector: iam.ResourceSelector{ResourceKind: &iam.ResourceKind{APIGroup: "test.example", Kind: "Project"}}}},
	}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&bindings[0], &bindings[1], &bindings[2]).Build()
	r := PolicyBindingReconciler{Client: cli, EnableSubresourceAuthorization: true}
	pr := &iam.ProtectedResource{Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "widgets", Kind: "Widget"}}
	requests := r.enqueuePolicyBindingsForProtectedResourceChange(context.Background(), pr)
	require.Len(t, requests, 3)
}

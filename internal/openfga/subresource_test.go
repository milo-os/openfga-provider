package openfga

import (
	"context"
	"fmt"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestSubresourceModelAndPolicyHierarchy(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, iam.AddToScheme(scheme))
	parent := iam.ProtectedResource{ObjectMeta: metav1.ObjectMeta{Name: "projects"}, Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "projects", Kind: "Project", Permissions: []string{"get"}}}
	child := iam.ProtectedResource{ObjectMeta: metav1.ObjectMeta{Name: "widgets"}, Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "widgets", Kind: "Widget", Permissions: []string{"patch"}, ParentResources: []iam.ParentResourceRef{{APIGroup: "test.example", Kind: "Project"}}, Subresources: []iam.SubresourceDefinition{{Name: "status", Permissions: []string{"patch", "update"}}}}}
	status := "test.example/widgets/status.patch"
	for _, enabled := range []bool{false, true} {
		builder := &AuthorizationModelReconciler{EnableSubresourceAuthorization: enabled}
		model, err := builder.createExpectedAuthorizationModel([]iam.ProtectedResource{parent, child})
		require.NoError(t, err)
		for _, kind := range []string{"test.example/Widget", "test.example/Project", TypeRoot} {
			found := false
			for _, td := range model.TypeDefinitions {
				if td.Type == kind {
					_, exists := td.Relations[HashPermission(status)]
					require.Equal(t, enabled, exists, kind)
					found = true
				}
			}
			require.True(t, found, kind)
		}
		cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&parent, &child).Build()
		reconciler := PolicyReconciler{K8sClient: cli, EnableSubresourceAuthorization: enabled}
		for _, kind := range []string{"Widget", "Project"} {
			selector := iam.ResourceSelector{ResourceKind: &iam.ResourceKind{APIGroup: "test.example", Kind: kind}}
			valid, err := reconciler.getHierarchicalPermissionsForSelector(ctx, selector)
			require.NoError(t, err)
			binding := iam.PolicyBinding{Spec: iam.PolicyBindingSpec{ResourceSelector: selector, Subjects: []iam.Subject{{Kind: "User", Name: "alice", UID: "alice-id"}}}}
			role := &iam.Role{Spec: iam.RoleSpec{IncludedPermissions: []string{status}}}
			object, err := TargetObjectFromResourceSelector(selector)
			require.NoError(t, err)
			tuples, err := reconciler.buildPermissionTuples(binding, role, object, valid)
			require.NoError(t, err)
			if enabled {
				require.Len(t, tuples, 1)
				require.Equal(t, HashPermission(status), tuples[0].Relation)
				require.Equal(t, object, tuples[0].Object)
			} else {
				require.Empty(t, tuples)
			}
			// Empty registration sets must not turn into wildcard grants.
			tuples, err = reconciler.buildPermissionTuples(binding, role, object, map[string]struct{}{})
			require.NoError(t, err)
			require.Empty(t, tuples)
		}
		childUpdated := child.DeepCopy()
		childUpdated.Spec.Subresources = nil
		require.NoError(t, cli.Update(ctx, childUpdated))
		valid, err := reconciler.getHierarchicalPermissionsForSelector(ctx, iam.ResourceSelector{ResourceKind: &iam.ResourceKind{APIGroup: "test.example", Kind: "Project"}})
		require.NoError(t, err)
		_, exists := valid[status]
		require.False(t, exists, "revoked registration must disappear from ancestor permissions")
	}
}

// Publishing the model ID is part of reconciliation: otherwise a flag change
// can leave authorization and tuple writes pinned to the old model forever.
func TestSubresourceModelPublicationRetries(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	failure := true
	cli := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if failure {
				return fmt.Errorf("temporary publication failure")
			}
			return c.Create(ctx, obj, opts...)
		},
	}).Build()
	builder := &AuthorizationModelReconciler{EnableSubresourceAuthorization: true, K8sClient: cli, Namespace: "system", ConfigMapName: AuthorizationModelConfigMapName}
	model, err := builder.createExpectedAuthorizationModel(nil)
	require.NoError(t, err)
	model.Id = "model-current"
	builder.OpenFGA = &MockOpenFGAServiceClient{ReadAuthorizationModelFunc: func(context.Context, *openfgav1.ReadAuthorizationModelRequest, ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
		return &openfgav1.ReadAuthorizationModelResponse{AuthorizationModel: model}, nil
	}, ReadAuthorizationModelsFunc: func(context.Context, *openfgav1.ReadAuthorizationModelsRequest, ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
		return &openfgav1.ReadAuthorizationModelsResponse{AuthorizationModels: []*openfgav1.AuthorizationModel{model}}, nil
	}}
	require.ErrorContains(t, builder.ReconcileAuthorizationModel(ctx, nil), "temporary publication failure")
	failure = false
	require.NoError(t, builder.ReconcileAuthorizationModel(ctx, nil))
	cm := &corev1.ConfigMap{}
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Namespace: "system", Name: AuthorizationModelConfigMapName}, cm))
	require.Equal(t, "model-current", cm.Data[AuthorizationModelIDKey])
}

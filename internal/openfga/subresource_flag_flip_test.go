package openfga

import (
	"context"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type tupleStoreClient struct {
	openfgav1.OpenFGAServiceClient
	tuples []*openfgav1.TupleKey
	writes []*openfgav1.WriteRequest
}

func (c *tupleStoreClient) Read(_ context.Context, in *openfgav1.ReadRequest, _ ...grpc.CallOption) (*openfgav1.ReadResponse, error) {
	resp := &openfgav1.ReadResponse{}
	for _, t := range c.tuples {
		if t.User == in.TupleKey.User && t.Object == in.TupleKey.Object {
			resp.Tuples = append(resp.Tuples, &openfgav1.Tuple{Key: t})
		}
	}
	return resp, nil
}

func (c *tupleStoreClient) Write(_ context.Context, in *openfgav1.WriteRequest, _ ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
	c.writes = append(c.writes, in)
	return &openfgav1.WriteResponse{}, nil
}

func TestSubresourceFlagOffRevokesOnlySubresourceTuples(t *testing.T) {
	const (
		namespace = "org-x"
		verbGet   = "get"
	)
	scheme := runtime.NewScheme()
	require.NoError(t, iam.AddToScheme(scheme))
	plain := "test.example/logs.list"
	sub := "test.example/logs/api.get"
	pr := &iam.ProtectedResource{ObjectMeta: metav1.ObjectMeta{Name: "logs"}, Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "logs", Kind: "Log", Permissions: []string{"list"}, Subresources: []iam.SubresourceDefinition{{Name: "api", Permissions: []string{verbGet}}}}}
	role := &iam.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "viewer", Namespace: namespace},
		Spec:       iam.RoleSpec{IncludedPermissions: []string{plain, sub}},
		Status: iam.RoleStatus{
			EffectivePermissions: []string{plain, sub},
			Conditions:           []metav1.Condition{{Type: "PermissionsValid", Status: metav1.ConditionFalse, Reason: "InvalidPermissions"}},
		},
	}
	selector := iam.ResourceSelector{ResourceKind: &iam.ResourceKind{APIGroup: "test.example", Kind: "Log"}}
	binding := iam.PolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: namespace},
		Spec: iam.PolicyBindingSpec{
			RoleRef:          iam.RoleReference{Name: "viewer", Namespace: namespace},
			ResourceSelector: selector,
			Subjects:         []iam.Subject{{Kind: "User", Name: "alice", UID: "alice-id"}},
		},
	}
	object, err := TargetObjectFromResourceSelector(selector)
	require.NoError(t, err)
	user := TypeInternalUser + ":alice"
	fga := &tupleStoreClient{tuples: []*openfgav1.TupleKey{
		{User: user, Relation: HashPermission(plain), Object: object},
		{User: user, Relation: HashPermission(sub), Object: object},
	}}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pr, role, &binding).
		WithIndex(&iam.PolicyBinding{}, TargetObjectIndexField, func(obj client.Object) []string {
			key, _ := TargetObjectFromResourceSelector(obj.(*iam.PolicyBinding).Spec.ResourceSelector)
			return []string{key}
		}).Build()

	reconciler := PolicyReconciler{K8sClient: cli, Client: fga, EnableSubresourceAuthorization: false}
	require.NoError(t, reconciler.ReconcilePolicy(context.Background(), binding))

	require.Len(t, fga.writes, 1)
	require.Nil(t, fga.writes[0].Writes)
	require.Len(t, fga.writes[0].Deletes.TupleKeys, 1)
	require.Equal(t, HashPermission(sub), fga.writes[0].Deletes.TupleKeys[0].Relation)
}

package openfga

import (
	"context"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// strictTupleStore keeps tuples as OpenFGA does: a write that adds a tuple that exists, or deletes one that does not,
// fails as a whole with code 2017, unless the write asks to ignore it. afterRead runs once, after the first Read, which
// is where another binding's write lands when two bindings that share a tuple reconcile at the same time.
type strictTupleStore struct {
	openfgav1.OpenFGAServiceClient
	tuples    map[string]*openfgav1.TupleKey
	afterRead func(tuples map[string]*openfgav1.TupleKey)
	writeErr  error
}

func tupleID(user, relation, object string) string { return user + "|" + relation + "|" + object }

func (s *strictTupleStore) Read(_ context.Context, in *openfgav1.ReadRequest, _ ...grpc.CallOption) (*openfgav1.ReadResponse, error) {
	resp := &openfgav1.ReadResponse{}
	for _, t := range s.tuples {
		if t.User == in.TupleKey.User && t.Object == in.TupleKey.Object {
			resp.Tuples = append(resp.Tuples, &openfgav1.Tuple{Key: t})
		}
	}
	if s.afterRead != nil {
		s.afterRead(s.tuples)
		s.afterRead = nil
	}
	return resp, nil
}

func (s *strictTupleStore) Write(_ context.Context, in *openfgav1.WriteRequest, _ ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
	if s.writeErr != nil {
		return nil, s.writeErr
	}
	for _, t := range in.GetWrites().GetTupleKeys() {
		if _, ok := s.tuples[tupleID(t.User, t.Relation, t.Object)]; ok && in.GetWrites().GetOnDuplicate() != "ignore" {
			return nil, status.Error(codes.Code(2017), "cannot write a tuple which already exists")
		}
	}
	for _, t := range in.GetDeletes().GetTupleKeys() {
		if _, ok := s.tuples[tupleID(t.User, t.Relation, t.Object)]; !ok && in.GetDeletes().GetOnMissing() != "ignore" {
			return nil, status.Error(codes.Code(2017), "cannot delete a tuple which does not exist")
		}
	}
	for _, t := range in.GetWrites().GetTupleKeys() {
		s.tuples[tupleID(t.User, t.Relation, t.Object)] = t
	}
	for _, t := range in.GetDeletes().GetTupleKeys() {
		delete(s.tuples, tupleID(t.User, t.Relation, t.Object))
	}
	return &openfgav1.WriteResponse{}, nil
}

// logViewerBinding returns a binding of alice to a role whose effective permissions are perms, on the Log kind, with
// a reconciler on a fake cluster that holds the role, the binding and the Log ProtectedResource.
func logViewerBinding(t *testing.T, store *strictTupleStore, perms ...string) (PolicyReconciler, iam.PolicyBinding, string) {
	t.Helper()
	const namespace = "org-x"
	scheme := runtime.NewScheme()
	require.NoError(t, iam.AddToScheme(scheme))
	pr := &iam.ProtectedResource{ObjectMeta: metav1.ObjectMeta{Name: "logs"}, Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "logs", Kind: "Log", Permissions: []string{"list", "get"}}}
	role := &iam.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "viewer", Namespace: namespace},
		Spec:       iam.RoleSpec{IncludedPermissions: perms},
		Status:     iam.RoleStatus{EffectivePermissions: perms},
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
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pr, role, &binding).
		WithIndex(&iam.PolicyBinding{}, TargetObjectIndexField, func(obj client.Object) []string {
			key, _ := TargetObjectFromResourceSelector(obj.(*iam.PolicyBinding).Spec.ResourceSelector)
			return []string{key}
		}).Build()
	return PolicyReconciler{K8sClient: cli, Client: store}, binding, object
}

// TestReconcilePolicyAddsSharedAndDistinctTuples checks that a binding's whole write succeeds when another binding
// writes one shared tuple after the read, while a distinct tuple in the same batch is still added.
func TestReconcilePolicyAddsSharedAndDistinctTuples(t *testing.T) {
	user := TypeInternalUser + ":alice"
	list, get := HashPermission("test.example/logs.list"), HashPermission("test.example/logs.get")
	store := &strictTupleStore{tuples: map[string]*openfgav1.TupleKey{}}
	reconciler, binding, object := logViewerBinding(t, store, "test.example/logs.list", "test.example/logs.get")
	store.afterRead = func(tuples map[string]*openfgav1.TupleKey) {
		tuples[tupleID(user, list, object)] = &openfgav1.TupleKey{User: user, Relation: list, Object: object}
	}

	require.NoError(t, reconciler.ReconcilePolicy(context.Background(), binding))
	require.Contains(t, store.tuples, tupleID(user, list, object))
	require.Contains(t, store.tuples, tupleID(user, get, object))
}

func TestReconcilePolicyReturnsGenuineWriteFailure(t *testing.T) {
	store := &strictTupleStore{
		tuples:   map[string]*openfgav1.TupleKey{},
		writeErr: status.Error(codes.Unavailable, "genuine write failure"),
	}
	reconciler, binding, _ := logViewerBinding(t, store, "test.example/logs.list")

	err := reconciler.ReconcilePolicy(context.Background(), binding)
	require.ErrorContains(t, err, "genuine write failure")
	require.Empty(t, store.tuples)
}

// TestDeletePolicyRemovesATupleAnotherBindingJustRemoved checks that a deleted binding's clean-up succeeds when one of
// its tuples was removed by another writer after the clean-up read.
func TestDeletePolicyRemovesATupleAnotherBindingJustRemoved(t *testing.T) {
	user := TypeInternalUser + ":alice"
	list, get := HashPermission("test.example/logs.list"), HashPermission("test.example/logs.get")
	store := &strictTupleStore{tuples: map[string]*openfgav1.TupleKey{}}
	reconciler, binding, object := logViewerBinding(t, store, "test.example/logs.list", "test.example/logs.get")
	store.tuples[tupleID(user, list, object)] = &openfgav1.TupleKey{User: user, Relation: list, Object: object}
	store.tuples[tupleID(user, get, object)] = &openfgav1.TupleKey{User: user, Relation: get, Object: object}
	store.afterRead = func(tuples map[string]*openfgav1.TupleKey) { delete(tuples, tupleID(user, get, object)) }

	require.NoError(t, reconciler.DeletePolicy(context.Background(), binding))
	require.Empty(t, store.tuples)
}

// TestReconcilePolicyRemovesATupleAnotherBindingJustRemoved checks that a binding's write succeeds when a tuple it no
// longer needs was removed by another binding after this binding read.
func TestReconcilePolicyRemovesATupleAnotherBindingJustRemoved(t *testing.T) {
	user := TypeInternalUser + ":alice"
	list, get := HashPermission("test.example/logs.list"), HashPermission("test.example/logs.get")
	store := &strictTupleStore{tuples: map[string]*openfgav1.TupleKey{}}
	reconciler, binding, object := logViewerBinding(t, store, "test.example/logs.list")
	store.tuples[tupleID(user, list, object)] = &openfgav1.TupleKey{User: user, Relation: list, Object: object}
	store.tuples[tupleID(user, get, object)] = &openfgav1.TupleKey{User: user, Relation: get, Object: object}
	store.afterRead = func(tuples map[string]*openfgav1.TupleKey) { delete(tuples, tupleID(user, get, object)) }

	require.NoError(t, reconciler.ReconcilePolicy(context.Background(), binding))
	require.NotContains(t, store.tuples, tupleID(user, get, object))
	require.Contains(t, store.tuples, tupleID(user, list, object))
}

package openfga

import (
	"context"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const siblingNamespace = "org-x"

var (
	siblingList = "test.example/logs.list"
	siblingGet  = "test.example/logs.get"
)

func siblingRole(name string, perms ...string) *iam.Role {
	return &iam.Role{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: siblingNamespace},
		Spec:       iam.RoleSpec{IncludedPermissions: perms},
		Status:     iam.RoleStatus{EffectivePermissions: perms},
	}
}

func siblingBinding(name, role string, subject iam.Subject) *iam.PolicyBinding {
	return &iam.PolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: siblingNamespace},
		Spec: iam.PolicyBindingSpec{
			RoleRef:          iam.RoleReference{Name: role, Namespace: siblingNamespace},
			ResourceSelector: iam.ResourceSelector{ResourceKind: &iam.ResourceKind{APIGroup: "test.example", Kind: "Log"}},
			Subjects:         []iam.Subject{subject},
		},
	}
}

type siblingFixture struct {
	reconciler PolicyReconciler
	cli        client.Client
	store      *strictTupleStore
	valid      iam.PolicyBinding
	object     string
}

func newSiblingFixture(t *testing.T, sibling *iam.PolicyBinding, extra ...client.Object) siblingFixture {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, iam.AddToScheme(scheme))
	pr := &iam.ProtectedResource{ObjectMeta: metav1.ObjectMeta{Name: "logs"}, Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "logs", Kind: "Log", Permissions: []string{"list", "get"}}}
	alice := &iam.User{ObjectMeta: metav1.ObjectMeta{Name: "alice", UID: types.UID("alice-id")}}
	valid := siblingBinding("valid", "lister", iam.Subject{Kind: "User", Name: "alice", UID: "alice-id"})
	objs := append([]client.Object{pr, alice, valid, sibling, siblingRole("lister", siblingList), siblingRole("reader", siblingList, siblingGet)}, extra...)
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).
		WithStatusSubresource(&iam.PolicyBinding{}).
		WithIndex(&iam.PolicyBinding{}, TargetObjectIndexField, func(obj client.Object) []string {
			key, _ := TargetObjectFromResourceSelector(obj.(*iam.PolicyBinding).Spec.ResourceSelector)
			return []string{key}
		}).Build()
	object, err := TargetObjectFromResourceSelector(valid.Spec.ResourceSelector)
	require.NoError(t, err)
	user := TypeInternalUser + ":alice"
	store := &strictTupleStore{tuples: map[string]*openfgav1.TupleKey{}}
	for _, p := range []string{siblingList, siblingGet} {
		h := HashPermission(p)
		store.tuples[tupleID(user, h, object)] = &openfgav1.TupleKey{User: user, Relation: h, Object: object}
	}
	return siblingFixture{reconciler: PolicyReconciler{K8sClient: cli, Client: store}, cli: cli, store: store, valid: *valid, object: object}
}

func (f siblingFixture) hasGet() bool {
	_, ok := f.store.tuples[tupleID(TypeInternalUser+":alice", HashPermission(siblingGet), f.object)]
	return ok
}

func (f siblingFixture) readyReason(t *testing.T, name string) string {
	t.Helper()
	var pb iam.PolicyBinding
	require.NoError(t, f.cli.Get(context.Background(), client.ObjectKey{Namespace: siblingNamespace, Name: name}, &pb))
	c := meta.FindStatusCondition(pb.Status.Conditions, "Ready")
	if c == nil || c.Status != metav1.ConditionFalse {
		return ""
	}
	return c.Reason
}

func TestReconcilePolicyRevokesDespiteSiblingWithMismatchedUID(t *testing.T) {
	forged := siblingBinding("forged", "reader", iam.Subject{Kind: "User", Name: "alice", UID: "someone-else"})
	f := newSiblingFixture(t, forged)

	require.NoError(t, f.reconciler.ReconcilePolicy(context.Background(), f.valid))

	require.False(t, f.hasGet(), "a sibling whose subject UID does not match must not keep a revoked tuple")
	require.Equal(t, "SubjectValidationFailed", f.readyReason(t, "forged"))
}

func TestDeletePolicyRevokesDespiteSiblingWithMismatchedGroupUID(t *testing.T) {
	group := &iam.Group{ObjectMeta: metav1.ObjectMeta{Name: "loaders", Namespace: siblingNamespace, UID: types.UID("loaders-id")}}
	forged := siblingBinding("forged", "reader", iam.Subject{Kind: "Group", Name: "loaders", Namespace: siblingNamespace, UID: "foreign-id"})
	forged.Spec.Subjects = append(forged.Spec.Subjects, iam.Subject{Kind: "User", Name: "alice", UID: "someone-else"})
	f := newSiblingFixture(t, forged, group)

	require.NoError(t, f.reconciler.DeletePolicy(context.Background(), f.valid))

	require.Empty(t, f.store.tuples)
	require.Equal(t, "SubjectValidationFailed", f.readyReason(t, "forged"))
}

func TestReconcilePolicyRevokesDespiteSiblingWithMissingSubject(t *testing.T) {
	forged := siblingBinding("forged", "reader", iam.Subject{Kind: "User", Name: "alice", UID: "alice-id"})
	forged.Spec.Subjects = append(forged.Spec.Subjects, iam.Subject{Kind: "Group", Name: "ghosts", Namespace: siblingNamespace, UID: "ghost-id"})
	f := newSiblingFixture(t, forged)

	require.NoError(t, f.reconciler.ReconcilePolicy(context.Background(), f.valid))

	require.False(t, f.hasGet())
}

func TestReconcilePolicyKeepsTupleAValidSiblingNeeds(t *testing.T) {
	sibling := siblingBinding("sibling", "reader", iam.Subject{Kind: "User", Name: "alice", UID: "alice-id"})
	f := newSiblingFixture(t, sibling)

	require.NoError(t, f.reconciler.ReconcilePolicy(context.Background(), f.valid))

	require.True(t, f.hasGet(), "a valid sibling's tuple must survive")
	require.Empty(t, f.readyReason(t, "sibling"))
}

func TestReconcilePolicyKeepsTupleForSiblingWithRemoteServiceAccount(t *testing.T) {
	sibling := siblingBinding("sibling", "reader", iam.Subject{Kind: "User", Name: "alice", UID: "alice-id"})
	sibling.Spec.Subjects = append(sibling.Spec.Subjects, iam.Subject{Kind: "ServiceAccount", Name: "robot", UID: "robot-id"})
	f := newSiblingFixture(t, sibling)

	require.NoError(t, f.reconciler.ReconcilePolicy(context.Background(), f.valid))

	require.True(t, f.hasGet())
}

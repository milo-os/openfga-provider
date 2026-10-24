package openfga

import (
	"context"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// deletePolicyMockClient is a minimal OpenFGAServiceClient mock covering the
// Read/Write calls exercised by PolicyReconciler.DeletePolicy.
type deletePolicyMockClient struct {
	openfgav1.OpenFGAServiceClient

	// existingTuples simulates the tuples currently stored in OpenFGA that
	// Read should return, keyed by "user" for simplicity (this test only ever
	// queries a single object).
	existingTuples []*openfgav1.TupleKey

	deleteCalls [][]*openfgav1.TupleKeyWithoutCondition
	writeCalled bool
}

func (m *deletePolicyMockClient) Read(ctx context.Context, in *openfgav1.ReadRequest, opts ...grpc.CallOption) (*openfgav1.ReadResponse, error) {
	var tuples []*openfgav1.Tuple
	for _, t := range m.existingTuples {
		if in.TupleKey != nil && in.TupleKey.User != "" && in.TupleKey.User != t.User {
			continue
		}
		tuples = append(tuples, &openfgav1.Tuple{Key: t})
	}
	return &openfgav1.ReadResponse{Tuples: tuples}, nil
}

func (m *deletePolicyMockClient) Write(ctx context.Context, in *openfgav1.WriteRequest, opts ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
	m.writeCalled = true
	if in.Deletes != nil {
		m.deleteCalls = append(m.deleteCalls, in.Deletes.TupleKeys)
	}
	return &openfgav1.WriteResponse{}, nil
}

func newDeletePolicyTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, iamdatumapiscomv1alpha1.AddToScheme(s))
	return s
}

func newDeletePolicyTestClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	s := newDeletePolicyTestScheme(t)
	return fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithIndex(&iamdatumapiscomv1alpha1.PolicyBinding{}, TargetObjectIndexField, func(obj client.Object) []string {
			pb := obj.(*iamdatumapiscomv1alpha1.PolicyBinding)
			key, err := TargetObjectFromResourceSelector(pb.Spec.ResourceSelector)
			if err != nil {
				return nil
			}
			return []string{key}
		}).
		Build()
}

func testProtectedResource() *iamdatumapiscomv1alpha1.ProtectedResource {
	return &iamdatumapiscomv1alpha1.ProtectedResource{
		ObjectMeta: metav1.ObjectMeta{Name: "widgets"},
		Spec: iamdatumapiscomv1alpha1.ProtectedResourceSpec{
			ServiceRef:  iamdatumapiscomv1alpha1.ServiceReference{Name: "test.miloapis.com"},
			Kind:        "Widget",
			Singular:    "widget",
			Plural:      "widgets",
			Permissions: []string{"get"},
		},
	}
}

func testResourceSelector() iamdatumapiscomv1alpha1.ResourceSelector {
	return iamdatumapiscomv1alpha1.ResourceSelector{
		ResourceRef: &iamdatumapiscomv1alpha1.ResourceReference{
			APIGroup: "test.miloapis.com",
			Kind:     "Widget",
			Name:     "widget-1",
			UID:      "widget-1-uid",
		},
	}
}

func TestDeletePolicy(t *testing.T) {
	logf.SetLogger(zap.New())

	targetObject := "test.miloapis.com/Widget:widget-1"

	t.Run("normal deletion cleans up tuples for a resolvable subject", func(t *testing.T) {
		binding := iamdatumapiscomv1alpha1.PolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "binding-1", Namespace: "org-1"},
			Spec: iamdatumapiscomv1alpha1.PolicyBindingSpec{
				RoleRef:          iamdatumapiscomv1alpha1.RoleReference{Name: "viewer", Namespace: "org-1"},
				ResourceSelector: testResourceSelector(),
				Subjects: []iamdatumapiscomv1alpha1.Subject{
					{Kind: "User", Name: "alice", UID: "alice-uid"},
				},
			},
		}

		existingTuple := &openfgav1.TupleKey{
			User:     TypeInternalUser + ":alice",
			Relation: hashPermission("test.miloapis.com/widgets.get"),
			Object:   targetObject,
		}

		mockFga := &deletePolicyMockClient{existingTuples: []*openfgav1.TupleKey{existingTuple}}
		k8sClient := newDeletePolicyTestClient(t, testProtectedResource())

		r := &PolicyReconciler{StoreID: "store-1", Client: mockFga, K8sClient: k8sClient}

		err := r.DeletePolicy(context.Background(), binding)
		require.NoError(t, err)
		require.True(t, mockFga.writeCalled, "expected Write to be called to delete the existing tuple")
		require.Len(t, mockFga.deleteCalls, 1)
		require.Len(t, mockFga.deleteCalls[0], 1)
		require.Equal(t, existingTuple.User, mockFga.deleteCalls[0][0].User)
	})

	t.Run("deletion completes for a binding whose subject can no longer be resolved (NotFound)", func(t *testing.T) {
		// Mirrors the staging scenario in issue #125: subject
		// "MachineAccount/dolly" was deleted from the cluster (SubjectValid:
		// False, reason NotFound) before the PolicyBinding was deleted. The
		// subject's Kind isn't one getTupleUser knows how to translate into an
		// OpenFGA user string, so there is nothing we can identify to retract.
		binding := iamdatumapiscomv1alpha1.PolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "binding-2", Namespace: "org-1"},
			Spec: iamdatumapiscomv1alpha1.PolicyBindingSpec{
				RoleRef:          iamdatumapiscomv1alpha1.RoleReference{Name: "viewer", Namespace: "org-1"},
				ResourceSelector: testResourceSelector(),
				Subjects: []iamdatumapiscomv1alpha1.Subject{
					{Kind: "MachineAccount", Name: "dolly", UID: "dolly-uid"},
				},
			},
		}

		mockFga := &deletePolicyMockClient{}
		k8sClient := newDeletePolicyTestClient(t, testProtectedResource())

		r := &PolicyReconciler{StoreID: "store-1", Client: mockFga, K8sClient: k8sClient}

		err := r.DeletePolicy(context.Background(), binding)
		require.NoError(t, err, "DeletePolicy must not error just because a subject is unresolvable, otherwise the finalizer never clears")
		require.False(t, mockFga.writeCalled, "there is nothing to delete when the only subject is unresolvable")
	})

	t.Run("deletion completes for a binding with an unrecognized subject kind (KindNotRecognized)", func(t *testing.T) {
		// Mirrors the staging scenario for "MachineAccount/ci-test-account" and
		// "MachineAccount/bot": the Kind itself isn't recognized by the API
		// server (or, as here, by getTupleUser's supported Kind set).
		binding := iamdatumapiscomv1alpha1.PolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "binding-3", Namespace: "org-1"},
			Spec: iamdatumapiscomv1alpha1.PolicyBindingSpec{
				RoleRef:          iamdatumapiscomv1alpha1.RoleReference{Name: "viewer", Namespace: "org-1"},
				ResourceSelector: testResourceSelector(),
				Subjects: []iamdatumapiscomv1alpha1.Subject{
					{Kind: "MachineAccount", Name: "bot"},
				},
			},
		}

		mockFga := &deletePolicyMockClient{}
		k8sClient := newDeletePolicyTestClient(t, testProtectedResource())

		r := &PolicyReconciler{StoreID: "store-1", Client: mockFga, K8sClient: k8sClient}

		err := r.DeletePolicy(context.Background(), binding)
		require.NoError(t, err)
		require.False(t, mockFga.writeCalled)
	})

	t.Run("resolvable subjects on a binding are still cleaned up when a sibling subject is unresolvable", func(t *testing.T) {
		binding := iamdatumapiscomv1alpha1.PolicyBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "binding-4", Namespace: "org-1"},
			Spec: iamdatumapiscomv1alpha1.PolicyBindingSpec{
				RoleRef:          iamdatumapiscomv1alpha1.RoleReference{Name: "viewer", Namespace: "org-1"},
				ResourceSelector: testResourceSelector(),
				Subjects: []iamdatumapiscomv1alpha1.Subject{
					{Kind: "User", Name: "alice", UID: "alice-uid"},
					{Kind: "MachineAccount", Name: "bot", UID: "bot-uid"},
				},
			},
		}

		existingTuple := &openfgav1.TupleKey{
			User:     TypeInternalUser + ":alice",
			Relation: hashPermission("test.miloapis.com/widgets.get"),
			Object:   targetObject,
		}

		mockFga := &deletePolicyMockClient{existingTuples: []*openfgav1.TupleKey{existingTuple}}
		k8sClient := newDeletePolicyTestClient(t, testProtectedResource())

		r := &PolicyReconciler{StoreID: "store-1", Client: mockFga, K8sClient: k8sClient}

		err := r.DeletePolicy(context.Background(), binding)
		require.NoError(t, err)
		require.True(t, mockFga.writeCalled)
		require.Len(t, mockFga.deleteCalls, 1)
		require.Len(t, mockFga.deleteCalls[0], 1)
		require.Equal(t, existingTuple.User, mockFga.deleteCalls[0][0].User)
	})
}

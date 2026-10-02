package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

type startupModelClient struct {
	openfgav1.OpenFGAServiceClient
	model      *openfgav1.AuthorizationModel
	writes     int
	writeError error
}

func (c *startupModelClient) ReadAuthorizationModels(context.Context, *openfgav1.ReadAuthorizationModelsRequest, ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
	response := &openfgav1.ReadAuthorizationModelsResponse{}
	if c.model != nil {
		response.AuthorizationModels = []*openfgav1.AuthorizationModel{c.model}
	}
	return response, nil
}

func (c *startupModelClient) ReadAuthorizationModel(context.Context, *openfgav1.ReadAuthorizationModelRequest, ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
	return &openfgav1.ReadAuthorizationModelResponse{AuthorizationModel: c.model}, nil
}

func (c *startupModelClient) WriteAuthorizationModel(_ context.Context, req *openfgav1.WriteAuthorizationModelRequest, _ ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
	if c.writeError != nil {
		return nil, c.writeError
	}
	c.writes++
	c.model = &openfgav1.AuthorizationModel{Id: fmt.Sprint(c.writes), SchemaVersion: req.SchemaVersion, TypeDefinitions: req.TypeDefinitions, Conditions: req.Conditions}
	return &openfgav1.WriteAuthorizationModelResponse{AuthorizationModelId: c.model.Id}, nil
}

func startupResource() *iam.ProtectedResource {
	pr := protectedResourceFixture(2, 2, false, true)
	pr.Spec = iam.ProtectedResourceSpec{
		ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "widgets", Kind: "Widget",
		Permissions: []string{"patch"}, Subresources: []iam.SubresourceDefinition{{Name: "status", Permissions: []string{"patch"}}},
	}
	return pr
}

func startupReconciler(cli client.Client, fga *startupModelClient, enabled bool) *AuthorizationModelReconciler {
	return &AuthorizationModelReconciler{Client: cli, modelBuilder: &openfga.AuthorizationModelReconciler{
		EnableSubresourceAuthorization: enabled, StoreID: "store", OpenFGA: fga,
	}}
}

func TestAuthorizationModelStartupFiltersReplayAndAppliesFlagChanges(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	require.NoError(t, iam.AddToScheme(scheme))
	gets, lists := 0, 0
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(startupResource()).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			gets++
			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			lists++
			return c.List(ctx, list, opts...)
		},
	}).Build()
	fga := &startupModelClient{}
	// Restarts must apply both enabling and disabling with no generation changes.
	for _, enabled := range []bool{false, true, false} {
		queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[ctrl.Request]())
		require.NoError(t, authorizationModelStartupSource().Start(ctx, queue))
		pred := protectedResourceEventPredicate()
		for i := range 1000 {
			pr := startupResource()
			pr.Name = fmt.Sprintf("observed-%d", i)
			if pred.Create(event.CreateEvent{Object: pr, IsInInitialList: true}) {
				queue.Add(ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pr)})
			}
		}
		require.Equal(t, 1, queue.Len(), "replayed resources must not create a startup backlog")
		req, shutdown := queue.Get()
		require.False(t, shutdown)
		require.Empty(t, req.Name)
		_, err := startupReconciler(cli, fga, enabled).Reconcile(ctx, req)
		require.NoError(t, err)
		queue.Done(req)
		queue.ShutDown()

		found := false
		for _, td := range fga.model.TypeDefinitions {
			if td.Type == "test.example/Widget" {
				_, found = td.Relations[openfga.HashPermission("test.example/widgets/status.patch")]
			}
		}
		require.Equal(t, enabled, found)
	}
	require.Zero(t, gets, "startup must not fetch individual resources")
	require.Equal(t, 3, lists, "one list per startup")
	require.Equal(t, 3, fga.writes, "one model update per configuration change")
}

func TestAuthorizationModelStartupWithNoActiveResources(t *testing.T) {
	for _, state := range []string{"empty", "disappeared", "deleting"} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			require.NoError(t, iam.AddToScheme(scheme))
			cli := fake.NewClientBuilder().WithScheme(scheme).Build()
			pr := startupResource()
			if state != "empty" {
				if state == "disappeared" {
					pr.Finalizers = nil
				}
				require.NoError(t, cli.Create(ctx, pr))
				require.NoError(t, cli.Delete(ctx, pr))
			}
			fga := &startupModelClient{}
			_, err := startupReconciler(cli, fga, true).Reconcile(ctx, ctrl.Request{})
			require.NoError(t, err)
			require.Equal(t, 1, fga.writes)
			for _, td := range fga.model.TypeDefinitions {
				require.NotEqual(t, "test.example/Widget", td.Type)
			}
		})
	}
}

func TestAuthorizationModelStartupRetriesFailures(t *testing.T) {
	for _, stage := range []string{"list", "model write"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			require.NoError(t, iam.AddToScheme(scheme))
			failure := errors.New("temporary failure")
			fail := true
			cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(startupResource()).WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if fail && stage == "list" {
						return failure
					}
					return c.List(ctx, list, opts...)
				},
			}).Build()
			fga := &startupModelClient{}
			if stage == "model write" {
				fga.writeError = failure
			}
			r := startupReconciler(cli, fga, true)
			queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[ctrl.Request]())
			defer queue.ShutDown()
			require.NoError(t, authorizationModelStartupSource().Start(ctx, queue))
			req, shutdown := queue.Get()
			require.False(t, shutdown)
			_, err := r.Reconcile(ctx, req)
			require.ErrorIs(t, err, failure)
			// Use the same rate-limited retry as controller-runtime.
			queue.AddRateLimited(req)
			queue.Done(req)
			fail, fga.writeError = false, nil
			retry, shutdown := queue.Get()
			require.False(t, shutdown)
			require.Equal(t, req, retry)
			_, err = r.Reconcile(ctx, retry)
			require.NoError(t, err)
			queue.Forget(retry)
			queue.Done(retry)
			require.Equal(t, 1, fga.writes)
		})
	}
}

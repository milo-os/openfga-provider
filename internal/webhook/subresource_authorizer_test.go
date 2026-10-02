package webhook_test

import (
	"context"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	"go.miloapis.com/auth-provider-openfga/internal/webhook"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestSubresourceAuthorizerUsesExactRelationOnOwningResource(t *testing.T) {
	pr := iam.ProtectedResource{Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "widgets", Kind: "Widget", Permissions: []string{"patch"}, Subresources: []iam.SubresourceDefinition{{Name: "status", Permissions: []string{"patch"}}}}}
	for _, tc := range []struct {
		name                             string
		enabled                          bool
		grantedPermission, grantedObject string
		allow                            bool
	}{
		{"legacy base grant", false, "test.example/widgets.patch", "test.example/Widget:one", true},
		{"base grant does not allow status", true, "test.example/widgets.patch", "test.example/Widget:one", false},
		{"explicit status instance", true, "test.example/widgets/status.patch", "test.example/Widget:one", true},
		{"explicit status root", true, "test.example/widgets/status.patch", "iam.miloapis.com/Root:test.example/Widget", true},
		{"explicit status parent", true, "test.example/widgets/status.patch", "resourcemanager.miloapis.com/Project:project-one", true},
		{"explicit status parent root", true, "test.example/widgets/status.patch", "iam.miloapis.com/Root:resourcemanager.miloapis.com/Project", true},
		{"update is not patch", true, "test.example/widgets/status.update", "test.example/Widget:one", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := authorizer.AttributesRecord{User: &user.DefaultInfo{UID: "alice-id", Name: "alice", Extra: map[string][]string{iam.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"}, iam.ParentKindExtraKey: {"Project"}, iam.ParentNameExtraKey: {"project-one"}}}, ResourceRequest: true, APIGroup: "test.example", Resource: "widgets", Subresource: "status", Name: "one", Verb: "patch"}
			called := false
			fga := &mockFGAClient{BatchCheckFunc: func(_ context.Context, req *openfgav1.BatchCheckRequest, _ ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				called = true
				response := &openfgav1.BatchCheckResponse{Result: map[string]*openfgav1.BatchCheckSingleResult{}}
				for _, item := range req.Checks {
					permission := "test.example/widgets.patch"
					if tc.enabled {
						permission = "test.example/widgets/status.patch"
					}
					require.Equal(t, openfga.HashPermission(permission), item.TupleKey.Relation)
					require.NotContains(t, item.TupleKey.Object, "status", "the object must remain the owning resource")
					allowed := item.TupleKey.Relation == openfga.HashPermission(tc.grantedPermission) && item.TupleKey.Object == tc.grantedObject
					response.Result[item.CorrelationId] = &openfgav1.BatchCheckSingleResult{CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: allowed}}
				}
				return response, nil
			}}
			auth := &webhook.SubjectAccessReviewAuthorizer{FGAClient: fga, EnableSubresourceAuthorization: tc.enabled, ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iam.ProtectedResource{pr})}
			decision, _, err := auth.Authorize(context.Background(), attrs)
			require.NoError(t, err)
			require.True(t, called)
			if tc.allow {
				require.Equal(t, authorizer.DecisionAllow, decision)
			} else {
				require.Equal(t, authorizer.DecisionDeny, decision)
			}
		})
	}
}

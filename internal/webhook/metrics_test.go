package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const metricsTestGroup = "metrics.example"

func decisionCount(t *testing.T, labels map[string]string) float64 {
	t.Helper()
	families, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	var total float64
	for _, family := range families {
		if family.GetName() != "authz_decisions_total" {
			continue
		}
	series:
		for _, m := range family.GetMetric() {
			if m.GetCounter() == nil {
				continue
			}
			got := map[string]string{}
			for _, l := range m.GetLabel() {
				got[l.GetName()] = l.GetValue()
			}
			for k, v := range labels {
				if got[k] != v {
					continue series
				}
			}
			total += m.GetCounter().GetValue()
		}
	}
	return total
}

func TestPermissionNotRegisteredDenialIsCounted(t *testing.T) {
	pr := iam.ProtectedResource{Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: metricsTestGroup}, Plural: "logs", Kind: "Log", Permissions: []string{"list"}}}
	for _, tc := range []struct {
		name     string
		enabled  bool
		decision string
	}{
		{"subresource authorization enabled", true, "denied"},
		{"subresource authorization disabled", false, "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			labels := map[string]string{
				"decision":       tc.decision,
				"scope":          "project",
				"resource_group": metricsTestGroup,
				"reason":         "permission_not_registered",
			}
			before := decisionCount(t, labels)

			auth := &SubjectAccessReviewAuthorizer{EnableSubresourceAuthorization: tc.enabled, ProtectedResourceCache: newProtectedResourceCacheFromItems([]iam.ProtectedResource{pr})}
			attrs := authorizer.AttributesRecord{
				User:            &user.DefaultInfo{UID: "alice-id", Name: "alice", Extra: map[string][]string{iam.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"}, iam.ParentKindExtraKey: {"Project"}, iam.ParentNameExtraKey: {"project-one"}}},
				ResourceRequest: true,
				APIGroup:        metricsTestGroup,
				Resource:        "logs",
				Verb:            "get",
			}
			decision, _, _ := auth.Authorize(context.Background(), attrs)
			require.Equal(t, authorizer.DecisionDeny, decision)
			require.Equal(t, before+1, decisionCount(t, labels))
		})
	}
}

func TestPermissionNotRegisteredCountedOncePerRequest(t *testing.T) {
	pr := iam.ProtectedResource{Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: metricsTestGroup}, Plural: "logs", Kind: "Log", Permissions: []string{"list"}}}
	for _, tc := range []struct {
		name     string
		enabled  bool
		decision string
	}{
		{"subresource authorization enabled", true, "denied"},
		{"subresource authorization disabled", false, "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			notRegistered := map[string]string{"resource_group": metricsTestGroup, "reason": reasonPermissionNotRegistered}
			scoped := map[string]string{"decision": tc.decision, "scope": "project", "resource_group": metricsTestGroup, "reason": reasonPermissionNotRegistered}
			perRequest := map[string]string{"decision": tc.decision, "scope": "unknown", "resource_group": metricsTestGroup, "reason": reasonHTTPRequest}
			notRegisteredBefore := decisionCount(t, notRegistered)
			scopedBefore := decisionCount(t, scoped)
			perRequestBefore := decisionCount(t, perRequest)

			hook := NewSubjectAccessReviewWebhook(Config{EnableSubresourceAuthorization: tc.enabled, ProtectedResourceCache: newProtectedResourceCacheFromItems([]iam.ProtectedResource{pr})})
			sar := authorizationv1.SubjectAccessReview{
				TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:               "alice",
					UID:                "alice-id",
					Extra:              map[string]authorizationv1.ExtraValue{iam.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"}, iam.ParentKindExtraKey: {"Project"}, iam.ParentNameExtraKey: {"project-one"}},
					ResourceAttributes: &authorizationv1.ResourceAttributes{Group: metricsTestGroup, Resource: "logs", Subresource: "api", Verb: "get"},
				},
			}
			body, err := json.Marshal(sar)
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			hook.ServeHTTP(httptest.NewRecorder(), req)

			require.Equal(t, notRegisteredBefore+1, decisionCount(t, notRegistered), "not-registered reason must be counted exactly once")
			require.Equal(t, scopedBefore+1, decisionCount(t, scoped))
			require.Equal(t, perRequestBefore+1, decisionCount(t, perRequest))
			require.Zero(t, decisionCount(t, map[string]string{"reason": ""}), "every series carries a reason")
		})
	}
}

type allowAllFGAClient struct {
	openfgav1.OpenFGAServiceClient
}

func (allowAllFGAClient) BatchCheck(_ context.Context, in *openfgav1.BatchCheckRequest, _ ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
	resp := &openfgav1.BatchCheckResponse{Result: map[string]*openfgav1.BatchCheckSingleResult{}}
	for _, item := range in.Checks {
		resp.Result[item.CorrelationId] = &openfgav1.BatchCheckSingleResult{CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true}}
	}
	return resp, nil
}

func TestOpenFGADecisionCarriesReason(t *testing.T) {
	pr := iam.ProtectedResource{Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: metricsTestGroup}, Plural: "logs", Kind: "Log", Permissions: []string{"list"}}}
	labels := map[string]string{"decision": "allowed", "scope": "project", "resource_group": metricsTestGroup, "reason": reasonOpenFGACheck}
	before := decisionCount(t, labels)

	auth := &SubjectAccessReviewAuthorizer{FGAClient: allowAllFGAClient{}, ProtectedResourceCache: newProtectedResourceCacheFromItems([]iam.ProtectedResource{pr})}
	attrs := authorizer.AttributesRecord{
		User:            &user.DefaultInfo{UID: "alice-id", Name: "alice", Extra: map[string][]string{iam.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"}, iam.ParentKindExtraKey: {"Project"}, iam.ParentNameExtraKey: {"project-one"}}},
		ResourceRequest: true,
		APIGroup:        metricsTestGroup,
		Resource:        "logs",
		Verb:            "list",
	}
	decision, _, err := auth.Authorize(context.Background(), attrs)
	require.NoError(t, err)
	require.Equal(t, authorizer.DecisionAllow, decision)
	require.Equal(t, before+1, decisionCount(t, labels))
	require.Zero(t, decisionCount(t, map[string]string{"reason": ""}), "every series carries a reason")
}

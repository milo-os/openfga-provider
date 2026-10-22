package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apidiscoveryv2 "k8s.io/api/apidiscovery/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/rest"
)

type servedVersion struct {
	resources []string
	stale     bool
}

// aggregatedDiscoveryServer serves aggregated discovery the way kube-apiserver
// does, including group versions marked stale while their APIService is
// unavailable.
type aggregatedDiscoveryServer struct {
	mu     sync.Mutex
	groups map[string]map[string]servedVersion
}

func (s *aggregatedDiscoveryServer) set(group, version string, served servedVersion) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.groups[group] == nil {
		s.groups[group] = map[string]servedVersion{}
	}
	s.groups[group][version] = served
}

func (s *aggregatedDiscoveryServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	list := apidiscoveryv2.APIGroupDiscoveryList{TypeMeta: metav1.TypeMeta{APIVersion: "apidiscovery.k8s.io/v2", Kind: "APIGroupDiscoveryList"}}
	for group, versions := range s.groups {
		if (r.URL.Path == "/api") != (group == "") {
			continue
		}
		g := apidiscoveryv2.APIGroupDiscovery{ObjectMeta: metav1.ObjectMeta{Name: group}}
		for version, served := range versions {
			v := apidiscoveryv2.APIVersionDiscovery{Version: version, Freshness: apidiscoveryv2.DiscoveryFreshnessCurrent}
			if served.stale {
				v.Freshness = apidiscoveryv2.DiscoveryFreshnessStale
			}
			for _, name := range served.resources {
				v.Resources = append(v.Resources, apidiscoveryv2.APIResourceDiscovery{
					Resource:     name,
					Scope:        apidiscoveryv2.ScopeNamespace,
					ResponseKind: &metav1.GroupVersionKind{Group: group, Version: version, Kind: name},
					Verbs:        []string{"get", "list", "create"},
				})
			}
			g.Versions = append(g.Versions, v)
		}
		list.Items = append(list.Items, g)
	}

	if r.URL.Path != "/api" && r.URL.Path != "/apis" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", discovery.AcceptV2)
	_ = json.NewEncoder(w).Encode(list)
}

func newAggregatedDiscovery(t *testing.T, ttl time.Duration) (*aggregatedDiscoveryServer, *ExpiringDiscoveryClient) {
	t.Helper()
	server := &aggregatedDiscoveryServer{groups: map[string]map[string]servedVersion{}}
	server.set("", "v1", servedVersion{resources: []string{"configmaps", servedCoreResource}})
	httpServer := httptest.NewServer(server)
	t.Cleanup(httpServer.Close)

	live, err := discovery.NewDiscoveryClientForConfig(&rest.Config{Host: httpServer.URL})
	require.NoError(t, err)
	return server, NewExpiringDiscoveryClient(memory.NewMemCacheClient(live), ttl)
}

func refusalReason(t *testing.T, client discovery.DiscoveryInterface, attrs authorizer.AttributesRecord) string {
	t.Helper()
	auth := &SubjectAccessReviewAuthorizer{
		EnableSubresourceAuthorization: true,
		ProtectedResourceCache:         newProtectedResourceCacheFromItems([]iam.ProtectedResource{}),
		DiscoveryClient:                client,
	}
	byReason := map[string]float64{}
	for _, reason := range []string{reasonPermissionNotRegistered, reasonResourceNotServed} {
		byReason[reason] = decisionCount(t, map[string]string{"decision": "denied", "scope": "cluster", "resource_group": attrs.APIGroup, "reason": reason})
	}
	decision, _, _ := auth.Authorize(context.Background(), attrs)
	require.Equal(t, authorizer.DecisionDeny, decision)
	for reason, before := range byReason {
		if decisionCount(t, map[string]string{"decision": "denied", "scope": "cluster", "resource_group": attrs.APIGroup, "reason": reason}) > before {
			return reason
		}
	}
	t.Fatal("refusal was not counted under any reason")
	return ""
}

func TestRefusalReasonWhenDiscoveryPartlyFails(t *testing.T) {
	staff := &user.DefaultInfo{UID: "staff-id", Name: "staff", Groups: []string{"system:authenticated"}}
	server, client := newAggregatedDiscovery(t, time.Hour)
	server.set(servedGroup, "v1", servedVersion{resources: []string{servedResource}, stale: true})
	server.set("partly.example.miloapis.com", "v1", servedVersion{resources: []string{servedResource}})
	server.set("partly.example.miloapis.com", "v2", servedVersion{resources: []string{servedResource}, stale: true})

	for _, tc := range []struct {
		name   string
		attrs  authorizer.AttributesRecord
		reason string
	}{
		{
			name:   "a resource in a stale group version",
			attrs:  authorizer.AttributesRecord{User: staff, ResourceRequest: true, APIGroup: servedGroup, APIVersion: "v1", Resource: servedResource, Verb: "create"},
			reason: reasonPermissionNotRegistered,
		},
		{
			name:   "an unserved version of a group whose every version is stale",
			attrs:  authorizer.AttributesRecord{User: staff, ResourceRequest: true, APIGroup: servedGroup, APIVersion: "v9", Resource: servedResource, Verb: "create"},
			reason: reasonPermissionNotRegistered,
		},
		{
			name:   "a resource with no version given in a group with a stale version",
			attrs:  authorizer.AttributesRecord{User: staff, ResourceRequest: true, APIGroup: "partly.example.miloapis.com", Resource: "widgets", Verb: "create"},
			reason: reasonPermissionNotRegistered,
		},
		{
			name:   "the stale version of a partly healthy group",
			attrs:  authorizer.AttributesRecord{User: staff, ResourceRequest: true, APIGroup: "partly.example.miloapis.com", APIVersion: "v2", Resource: "widgets", Verb: "create"},
			reason: reasonPermissionNotRegistered,
		},
		{
			name:   "a version no APIService registers in a partly healthy group",
			attrs:  authorizer.AttributesRecord{User: staff, ResourceRequest: true, APIGroup: "partly.example.miloapis.com", APIVersion: "v9", Resource: servedResource, Verb: "create"},
			reason: reasonResourceNotServed,
		},
		{
			name:   "a core resource discovery does not list",
			attrs:  authorizer.AttributesRecord{User: staff, ResourceRequest: true, APIVersion: "v1", Resource: "nodes", Verb: "list"},
			reason: reasonResourceNotServed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.reason, refusalReason(t, client, tc.attrs))
		})
	}
}

func TestRefusalReasonSeesNewlyServedResourceAfterExpiry(t *testing.T) {
	const ttl = 100 * time.Millisecond
	staff := &user.DefaultInfo{UID: "staff-id", Name: "staff", Groups: []string{"system:authenticated"}}
	server, client := newAggregatedDiscovery(t, ttl)
	server.set(servedGroup, "v1", servedVersion{resources: []string{"others"}})
	attrs := authorizer.AttributesRecord{User: staff, ResourceRequest: true, APIGroup: servedGroup, APIVersion: "v1", Resource: servedResource, Verb: "create"}

	require.Equal(t, reasonResourceNotServed, refusalReason(t, client, attrs))

	server.set(servedGroup, "v1", servedVersion{resources: []string{"others", servedResource}})
	require.Equal(t, reasonResourceNotServed, refusalReason(t, client, attrs), "discovery is cached until it expires")

	time.Sleep(2 * ttl)
	require.Equal(t, reasonPermissionNotRegistered, refusalReason(t, client, attrs))
}

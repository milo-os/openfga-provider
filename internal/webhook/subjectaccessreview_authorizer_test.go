package webhook_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.miloapis.com/auth-provider-openfga/internal/webhook"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/discovery"
)

// mockAttributes is a simple mock for authorizer.Attributes
type mockAttributes struct {
	authorizer.Attributes
	user       user.Info
	verb       string
	apiGroup   string
	apiVersion string
	resource   string
	name       string
	namespace  string
}

func (m *mockAttributes) GetUser() user.Info      { return m.user }
func (m *mockAttributes) GetVerb() string         { return m.verb }
func (m *mockAttributes) GetAPIGroup() string     { return m.apiGroup }
func (m *mockAttributes) GetAPIVersion() string   { return m.apiVersion }
func (m *mockAttributes) GetResource() string     { return m.resource }
func (m *mockAttributes) GetName() string         { return m.name }
func (m *mockAttributes) GetNamespace() string    { return m.namespace }
func (m *mockAttributes) IsResourceRequest() bool { return true }

// mockFGAClient is a mock of OpenFGAServiceClient for testing.
type mockFGAClient struct {
	openfgav1.OpenFGAServiceClient
	CheckFunc      func(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error)
	BatchCheckFunc func(ctx context.Context, in *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error)
	WriteFunc      func(ctx context.Context, in *openfgav1.WriteRequest, opts ...grpc.CallOption) (*openfgav1.WriteResponse, error)
}

func (m *mockFGAClient) Check(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
	if m.CheckFunc != nil {
		return m.CheckFunc(ctx, in)
	}
	return nil, errors.New("CheckFunc not implemented")
}

func (m *mockFGAClient) BatchCheck(ctx context.Context, in *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
	if m.BatchCheckFunc != nil {
		return m.BatchCheckFunc(ctx, in)
	}
	return nil, errors.New("BatchCheckFunc not implemented")
}

func (m *mockFGAClient) Write(ctx context.Context, in *openfgav1.WriteRequest, opts ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
	if m.WriteFunc != nil {
		return m.WriteFunc(ctx, in)
	}
	return &openfgav1.WriteResponse{}, nil
}

// mockDiscoveryClient is a mock of discovery.DiscoveryInterface for testing.
type mockDiscoveryClient struct {
	discovery.DiscoveryInterface
	serverResourcesForGroupVersionFunc func(groupVersion string) (*metav1.APIResourceList, error)
}

func (m *mockDiscoveryClient) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	if m.serverResourcesForGroupVersionFunc != nil {
		return m.serverResourcesForGroupVersionFunc(groupVersion)
	}
	return nil, errors.New("ServerResourcesForGroupVersion not implemented")
}

func TestSubjectAccessReviewAuthorizer_Authorize_Integration(t *testing.T) {

	testCases := []struct {
		name                    string
		attributes              authorizer.Attributes
		protectedResources      []iamv1alpha1.ProtectedResource
		fgaCheckFunc            func(*testing.T, *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error)
		fgaBatchCheckFunc       func(*testing.T, *openfgav1.BatchCheckRequest) (*openfgav1.BatchCheckResponse, error)
		expectedDecision        authorizer.Decision
		expectedErrorMsg        string
		expectFgaCheckCall      bool
		expectFgaBatchCheckCall bool
	}{
		{
			name: "allowed resource get with registered parent",
			attributes: &mockAttributes{
				apiGroup: "compute.miloapis.com",
				resource: "workloads",
				name:     "wkld-123",
				verb:     "get",
				user: &user.DefaultInfo{
					Name: "test-user",
					UID:  "user-abc",
					Extra: map[string][]string{
						iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
						iamv1alpha1.ParentKindExtraKey:     {"Project"},
						iamv1alpha1.ParentNameExtraKey:     {"proj-xyz"},
					},
				},
			},
			protectedResources: []iamv1alpha1.ProtectedResource{
				{
					Spec: iamv1alpha1.ProtectedResourceSpec{
						ServiceRef:  iamv1alpha1.ServiceReference{Name: "compute.miloapis.com"},
						Plural:      "workloads",
						Kind:        "Workload",
						Permissions: []string{"get"},
						ParentResources: []iamv1alpha1.ParentResourceRef{
							{APIGroup: "resourcemanager.miloapis.com", Kind: "Project"},
						},
					},
				},
			},
			fgaBatchCheckFunc: func(t *testing.T, req *openfgav1.BatchCheckRequest) (*openfgav1.BatchCheckResponse, error) {
				// Project-scoped get: instance check is against the project, root check
				// is against the kind-level Root object, and scope-root check covers
				// ResourceKind bindings targeting all Projects.
				require.Len(t, req.Checks, 3, "BatchCheck must have instance, root, and scope-root checks")
				checksById := make(map[string]*openfgav1.BatchCheckItem)
				for _, c := range req.Checks {
					checksById[c.CorrelationId] = c
				}
				require.Contains(t, checksById, "instance")
				require.Contains(t, checksById, "root")
				require.Contains(t, checksById, "scope-root")
				assert.Equal(t, "resourcemanager.miloapis.com/Project:proj-xyz", checksById["instance"].TupleKey.Object)
				assert.Equal(t, "iam.miloapis.com/Root:compute.miloapis.com/Workload", checksById["root"].TupleKey.Object)
				assert.Equal(t, "iam.miloapis.com/Root:resourcemanager.miloapis.com/Project", checksById["scope-root"].TupleKey.Object)
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance":   {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true}},
						"root":       {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
						"scope-root": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					},
				}, nil
			},
			expectedDecision:        authorizer.DecisionAllow,
			expectFgaBatchCheckCall: true,
		},
		{
			name: "denied collection create with project parent context",
			attributes: &mockAttributes{
				apiGroup: "compute.miloapis.com",
				resource: "workloads",
				verb:     "create",
				user: &user.DefaultInfo{
					Name: "test-user",
					UID:  "user-abc",
					Extra: map[string][]string{
						iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
						iamv1alpha1.ParentKindExtraKey:     {"Project"},
						iamv1alpha1.ParentNameExtraKey:     {"proj-xyz"},
					},
				},
			},
			protectedResources: []iamv1alpha1.ProtectedResource{
				{
					Spec: iamv1alpha1.ProtectedResourceSpec{
						ServiceRef:  iamv1alpha1.ServiceReference{Name: "compute.miloapis.com"},
						Plural:      "workloads",
						Kind:        "Workload",
						Permissions: []string{"create"},
					},
				},
			},
			fgaBatchCheckFunc: func(t *testing.T, req *openfgav1.BatchCheckRequest) (*openfgav1.BatchCheckResponse, error) {
				// Project-scoped create: instance check is against the project, root check
				// is against the kind-level Root object, scope-root covers ResourceKind
				// bindings targeting all Projects. Deny when all deny.
				require.Len(t, req.Checks, 3, "BatchCheck must have instance, root, and scope-root checks")
				checksById := make(map[string]*openfgav1.BatchCheckItem)
				for _, c := range req.Checks {
					checksById[c.CorrelationId] = c
				}
				require.Contains(t, checksById, "instance")
				require.Contains(t, checksById, "root")
				require.Contains(t, checksById, "scope-root")
				assert.Equal(t, "resourcemanager.miloapis.com/Project:proj-xyz", checksById["instance"].TupleKey.Object)
				assert.Equal(t, "iam.miloapis.com/Root:compute.miloapis.com/Workload", checksById["root"].TupleKey.Object)
				assert.Equal(t, "iam.miloapis.com/Root:resourcemanager.miloapis.com/Project", checksById["scope-root"].TupleKey.Object)
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance":   {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
						"root":       {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
						"scope-root": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					},
				}, nil
			},
			expectedDecision:        authorizer.DecisionDeny,
			expectFgaBatchCheckCall: true,
		},
		{
			name: "permission not registered",
			attributes: &mockAttributes{
				apiGroup: "foo.com",
				resource: "bars",
				verb:     "get",
				user:     &user.DefaultInfo{UID: "user-abc"},
			},
			protectedResources: []iamv1alpha1.ProtectedResource{},
			expectedDecision:   authorizer.DecisionDeny,
			expectedErrorMsg:   "permission 'foo.com/bars.get' not registered",
			expectFgaCheckCall: false,
		},
		{
			// Specific-resource cluster-scoped operations use BatchCheck to cover
			// both ResourceRef (instance-level) and ResourceKind (Root-level)
			// PolicyBindings in a single RPC. The instance check and the Root
			// check are sent together; access is allowed if either is allowed.
			name: "batch check used for specific resource at cluster scope",
			attributes: &mockAttributes{
				apiGroup: "compute.miloapis.com",
				resource: "workloads",
				name:     "wkld-123",
				verb:     "get",
				user: &user.DefaultInfo{
					Name: "test-user",
					UID:  "user-abc",
					// No project or org parent — cluster-scoped specific resource.
				},
			},
			protectedResources: []iamv1alpha1.ProtectedResource{
				{
					Spec: iamv1alpha1.ProtectedResourceSpec{
						ServiceRef:  iamv1alpha1.ServiceReference{Name: "compute.miloapis.com"},
						Plural:      "workloads",
						Kind:        "Workload",
						Permissions: []string{"get"},
					},
				},
			},
			fgaBatchCheckFunc: func(t *testing.T, req *openfgav1.BatchCheckRequest) (*openfgav1.BatchCheckResponse, error) {
				require.Len(t, req.Checks, 2, "BatchCheck must have instance and Root checks")
				checksById := make(map[string]*openfgav1.BatchCheckItem)
				for _, c := range req.Checks {
					checksById[c.CorrelationId] = c
				}
				require.Contains(t, checksById, "instance")
				require.Contains(t, checksById, "root")
				assert.Equal(t, "compute.miloapis.com/Workload:wkld-123", checksById["instance"].TupleKey.Object)
				assert.Equal(t, "iam.miloapis.com/Root:compute.miloapis.com/Workload", checksById["root"].TupleKey.Object)
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true}},
						"root":     {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					},
				}, nil
			},
			expectedDecision:        authorizer.DecisionAllow,
			expectFgaBatchCheckCall: true,
		},
		{
			name: "deny if user has no UID",
			attributes: &mockAttributes{
				user: &user.DefaultInfo{Name: "no-uid-user"},
			},
			protectedResources: []iamv1alpha1.ProtectedResource{
				{
					Spec: iamv1alpha1.ProtectedResourceSpec{
						Permissions: []string{"get"},
					},
				},
			},
			expectedDecision:   authorizer.DecisionDeny,
			expectedErrorMsg:   "user UID is required",
			expectFgaCheckCall: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fgaCheckCalled := false
			fgaBatchCheckCalled := false
			mockFGA := &mockFGAClient{
				CheckFunc: func(ctx context.Context, req *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
					fgaCheckCalled = true
					if tc.fgaCheckFunc != nil {
						return tc.fgaCheckFunc(t, req)
					}
					return nil, errors.New("FGA CheckFunc not provided")
				},
				BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
					fgaBatchCheckCalled = true
					if tc.fgaBatchCheckFunc != nil {
						return tc.fgaBatchCheckFunc(t, req)
					}
					return nil, errors.New("FGA BatchCheckFunc not provided")
				},
			}

			auth := &webhook.SubjectAccessReviewAuthorizer{
				FGAClient:              mockFGA,
				ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest(tc.protectedResources),
				FGAStoreID:             "test_store",
				DiscoveryClient:        &mockDiscoveryClient{},
			}

			decision, _, err := auth.Authorize(context.Background(), tc.attributes)

			assert.Equal(t, tc.expectedDecision, decision)
			if tc.expectedErrorMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrorMsg)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.expectFgaCheckCall, fgaCheckCalled, "Check call expectation mismatch")
			assert.Equal(t, tc.expectFgaBatchCheckCall, fgaBatchCheckCalled, "BatchCheck call expectation mismatch")
		})
	}
}

// Test our factory functions
func TestSubjectAccessReviewWebhookFactory(t *testing.T) {
	t.Run("NewSubjectAccessReviewWebhook creates webhook correctly", func(t *testing.T) {
		config := webhook.Config{
			FGAClient:              &mockFGAClient{},
			FGAStoreID:             "test-store",
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest(nil),
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		w := webhook.NewSubjectAccessReviewWebhook(config)
		assert.NotNil(t, w)
	})

	t.Run("RegisterSubjectAccessReviewWebhook registers correctly", func(t *testing.T) {
		config := webhook.Config{
			FGAClient:              &mockFGAClient{},
			FGAStoreID:             "test-store",
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest(nil),
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		registered := false
		registeredPath := ""
		mockServer := &mockWebhookServer{
			registerFunc: func(path string, handler http.Handler) {
				registered = true
				registeredPath = path
			},
		}

		webhook.RegisterSubjectAccessReviewWebhook(mockServer, config)

		assert.True(t, registered, "webhook should be registered")
		assert.Equal(t, "/apis/authorization.k8s.io/v1/subjectaccessreviews", registeredPath)
	})
}

func TestProjectScopedAuthorization(t *testing.T) {
	t.Run("project-scoped request uses project authorization logic", func(t *testing.T) {
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				// Verify that the instance check (correlation "instance") targets the project resource
				foundProjectCheck := false
				for _, check := range req.Checks {
					if check.CorrelationId == "instance" {
						assert.Contains(t, check.TupleKey.Object, "resourcemanager.miloapis.com/Project:")
						foundProjectCheck = true
					}
				}
				assert.True(t, foundProjectCheck, "expected an instance check targeting the project resource")
				results := map[string]*openfgav1.BatchCheckSingleResult{}
				for _, check := range req.Checks {
					results[check.CorrelationId] = &openfgav1.BatchCheckSingleResult{
						CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true},
					}
				}
				return &openfgav1.BatchCheckResponse{Result: results}, nil
			},
		}

		prCache := webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{
			{
				Spec: iamv1alpha1.ProtectedResourceSpec{
					ServiceRef:  iamv1alpha1.ServiceReference{Name: "core.miloapis.com"},
					Plural:      "pods",
					Kind:        "Pod",
					Permissions: []string{"get"},
				},
			},
		})

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: prCache,
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		// Create attributes with project parent extra keys
		attributes := &mockAttributes{
			apiGroup: "",
			resource: "pods",
			name:     "test-pod",
			verb:     "get",
			user: &user.DefaultInfo{
				Name: "test-user",
				UID:  "user-123",
				Extra: map[string][]string{
					iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
					iamv1alpha1.ParentKindExtraKey:     {"Project"},
					iamv1alpha1.ParentNameExtraKey:     {"test-project"},
				},
			},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		assert.NoError(t, err)
		assert.Equal(t, authorizer.DecisionAllow, decision)
	})
}

func TestOrganizationNamespaceValidation(t *testing.T) {
	t.Run("organization-scoped request with wrong namespace is denied", func(t *testing.T) {
		prCache := webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{
			{
				Spec: iamv1alpha1.ProtectedResourceSpec{
					ServiceRef:  iamv1alpha1.ServiceReference{Name: iamv1alpha1.SchemeGroupVersion.Group},
					Kind:        "Group",
					Plural:      "groups",
					Permissions: []string{"list"},
				},
			},
		})

		// FGA should not be called since validation fails before that
		mockFGA := &mockFGAClient{}

		mockDiscovery := &mockDiscoveryClient{
			serverResourcesForGroupVersionFunc: func(groupVersion string) (*metav1.APIResourceList, error) {
				if groupVersion == iamv1alpha1.SchemeGroupVersion.String() {
					return &metav1.APIResourceList{
						APIResources: []metav1.APIResource{
							{
								Name:       "groups",
								Namespaced: true, // Namespace-scoped
							},
						},
					}, nil
				}
				return nil, errors.New("group not found")
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			FGAStoreID:             "test-store",
			ProtectedResourceCache: prCache,
			DiscoveryClient:        mockDiscovery,
		}

		attributes := &mockAttributes{
			apiGroup:  iamv1alpha1.SchemeGroupVersion.Group,
			resource:  "groups",
			verb:      "list",
			namespace: "organization-wrongorg", // Wrong namespace
			user: &user.DefaultInfo{
				Name: "test-user",
				UID:  "user-123",
				Extra: map[string][]string{
					iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
					iamv1alpha1.ParentKindExtraKey:     {"Organization"},
					iamv1alpha1.ParentNameExtraKey:     {"acme"}, // Should expect organization-acme
				},
			},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "namespace mismatch")
		assert.Contains(t, err.Error(), "organization-wrongorg")
		assert.Contains(t, err.Error(), "organization-acme")
		assert.Equal(t, authorizer.DecisionDeny, decision)
	})

	t.Run("organization-scoped request with correct namespace is allowed", func(t *testing.T) {
		prCache := webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{
			{
				Spec: iamv1alpha1.ProtectedResourceSpec{
					ServiceRef:  iamv1alpha1.ServiceReference{Name: iamv1alpha1.SchemeGroupVersion.Group},
					Kind:        "Group",
					Plural:      "groups",
					Permissions: []string{"list"},
				},
			},
		})

		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				results := map[string]*openfgav1.BatchCheckSingleResult{}
				for _, check := range req.Checks {
					results[check.CorrelationId] = &openfgav1.BatchCheckSingleResult{
						CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true},
					}
				}
				return &openfgav1.BatchCheckResponse{Result: results}, nil
			},
		}

		mockDiscovery := &mockDiscoveryClient{
			serverResourcesForGroupVersionFunc: func(groupVersion string) (*metav1.APIResourceList, error) {
				if groupVersion == iamv1alpha1.SchemeGroupVersion.String() {
					return &metav1.APIResourceList{
						APIResources: []metav1.APIResource{
							{
								Name:       "groups",
								Namespaced: true, // Namespace-scoped
							},
						},
					}, nil
				}
				return nil, errors.New("group not found")
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			FGAStoreID:             "test-store",
			ProtectedResourceCache: prCache,
			DiscoveryClient:        mockDiscovery,
		}

		attributes := &mockAttributes{
			apiGroup:  iamv1alpha1.SchemeGroupVersion.Group,
			resource:  "groups",
			verb:      "list",
			namespace: "organization-acme", // Correct namespace
			user: &user.DefaultInfo{
				Name: "test-user",
				UID:  "user-123",
				Extra: map[string][]string{
					iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
					iamv1alpha1.ParentKindExtraKey:     {"Organization"},
					iamv1alpha1.ParentNameExtraKey:     {"acme"},
				},
			},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err)
		assert.Equal(t, authorizer.DecisionAllow, decision)
	})

	t.Run("non-organization request ignores namespace validation", func(t *testing.T) {
		prCache := webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{
			{
				Spec: iamv1alpha1.ProtectedResourceSpec{
					ServiceRef:  iamv1alpha1.ServiceReference{Name: iamv1alpha1.SchemeGroupVersion.Group},
					Kind:        "Group",
					Plural:      "groups",
					Permissions: []string{"list"},
				},
			},
		})

		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				results := map[string]*openfgav1.BatchCheckSingleResult{}
				for _, check := range req.Checks {
					results[check.CorrelationId] = &openfgav1.BatchCheckSingleResult{
						CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true},
					}
				}
				return &openfgav1.BatchCheckResponse{Result: results}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			FGAStoreID:             "test-store",
			ProtectedResourceCache: prCache,
			DiscoveryClient:        &mockDiscoveryClient{}, // No need for specific mock since no org context
		}

		attributes := &mockAttributes{
			apiGroup:  iamv1alpha1.SchemeGroupVersion.Group,
			resource:  "groups",
			verb:      "list",
			namespace: "organization-somethingelse", // Different org namespace
			user: &user.DefaultInfo{
				Name: "test-user",
				UID:  "user-123",
				// No parent context - treated as regular request
			},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err) // Should not validate namespace for non-org requests
		assert.Equal(t, authorizer.DecisionAllow, decision)
	})

	t.Run("organization-scoped request for cluster-scoped resource is allowed", func(t *testing.T) {
		prCache := webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{
			{
				Spec: iamv1alpha1.ProtectedResourceSpec{
					ServiceRef:  iamv1alpha1.ServiceReference{Name: "resourcemanager.miloapis.com"},
					Kind:        "Organization",
					Plural:      "organizations",
					Permissions: []string{"list"},
				},
			},
		})

		mockDiscovery := &mockDiscoveryClient{
			serverResourcesForGroupVersionFunc: func(groupVersion string) (*metav1.APIResourceList, error) {
				if groupVersion == "resourcemanager.miloapis.com/v1alpha1" {
					return &metav1.APIResourceList{
						APIResources: []metav1.APIResource{
							{
								Name:       "organizations",
								Namespaced: false, // Cluster-scoped
							},
						},
					}, nil
				}
				return nil, errors.New("group not found")
			},
		}

		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				results := map[string]*openfgav1.BatchCheckSingleResult{}
				for _, check := range req.Checks {
					results[check.CorrelationId] = &openfgav1.BatchCheckSingleResult{
						CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true},
					}
				}
				return &openfgav1.BatchCheckResponse{Result: results}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			FGAStoreID:             "test-store",
			ProtectedResourceCache: prCache,
			DiscoveryClient:        mockDiscovery,
		}

		attributes := &mockAttributes{
			apiGroup:   "resourcemanager.miloapis.com",
			apiVersion: "v1alpha1",
			resource:   "organizations",
			verb:       "list",
			namespace:  "", // No namespace for cluster-scoped resource
			user: &user.DefaultInfo{
				Name: "test-user",
				UID:  "user-123",
				Extra: map[string][]string{
					iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
					iamv1alpha1.ParentKindExtraKey:     {"Organization"},
					iamv1alpha1.ParentNameExtraKey:     {"acme"},
				},
			},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err) // Should not validate namespace for cluster-scoped resources
		assert.Equal(t, authorizer.DecisionAllow, decision)
	})

	t.Run("organization-scoped cross-namespace query is denied", func(t *testing.T) {
		prCache := webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{
			{
				Spec: iamv1alpha1.ProtectedResourceSpec{
					ServiceRef:  iamv1alpha1.ServiceReference{Name: iamv1alpha1.SchemeGroupVersion.Group},
					Kind:        "Group",
					Plural:      "groups",
					Permissions: []string{"list"},
				},
			},
		})

		mockDiscovery := &mockDiscoveryClient{
			serverResourcesForGroupVersionFunc: func(groupVersion string) (*metav1.APIResourceList, error) {
				if groupVersion == iamv1alpha1.SchemeGroupVersion.String() {
					return &metav1.APIResourceList{
						APIResources: []metav1.APIResource{
							{
								Name:       "groups",
								Namespaced: true, // Namespace-scoped
							},
						},
					}, nil
				}
				return nil, errors.New("group not found")
			},
		}

		// FGA should not be called since validation fails before that
		mockFGA := &mockFGAClient{}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			FGAStoreID:             "test-store",
			ProtectedResourceCache: prCache,
			DiscoveryClient:        mockDiscovery,
		}

		attributes := &mockAttributes{
			apiGroup:   iamv1alpha1.SchemeGroupVersion.Group,
			apiVersion: iamv1alpha1.SchemeGroupVersion.Version,
			resource:   "groups",
			verb:       "list",
			namespace:  "", // Empty namespace = cross-namespace query
			user: &user.DefaultInfo{
				Name: "test-user",
				UID:  "user-123",
				Extra: map[string][]string{
					iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
					iamv1alpha1.ParentKindExtraKey:     {"Organization"},
					iamv1alpha1.ParentNameExtraKey:     {"acme"},
				},
			},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "cross-namespace queries not allowed")
		assert.Equal(t, authorizer.DecisionDeny, decision)
	})
}

// TestResourceKindBindingResolution covers the BatchCheck approach used by
// BatchCheck to resolve ResourceKind policy bindings. When a
// user requests a named resource instance without project or org scope the
// authorizer sends a BatchCheck with two items: one for the specific instance
// and one for Root:service/Kind so that both ResourceRef and ResourceKind
// bindings are covered in a single RPC.
func TestResourceKindBindingResolution(t *testing.T) {

	computeWorkloadResource := iamv1alpha1.ProtectedResource{
		Spec: iamv1alpha1.ProtectedResourceSpec{
			ServiceRef:  iamv1alpha1.ServiceReference{Name: "compute.miloapis.com"},
			Plural:      "workloads",
			Kind:        "Workload",
			Permissions: []string{"get", "list", "create", "update", "delete"},
		},
	}

	t.Run("specific resource at cluster scope uses BatchCheck with instance and Root", func(t *testing.T) {
		// verb=get, name=instance-1, no project/org scope.
		// The authorizer must send BatchCheck with instance + Root checks.
		var capturedBatchReq *openfgav1.BatchCheckRequest
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				capturedBatchReq = req
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true}},
						"root":     {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					},
				}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		attributes := &mockAttributes{
			apiGroup: "compute.miloapis.com",
			resource: "workloads",
			name:     "instance-1",
			verb:     "get",
			user:     &user.DefaultInfo{Name: "test-user", UID: "user-abc"},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err)
		assert.Equal(t, authorizer.DecisionAllow, decision)

		require.NotNil(t, capturedBatchReq, "BatchCheck should have been called")
		require.Len(t, capturedBatchReq.Checks, 2, "BatchCheck must have instance and Root checks")
		checksById := make(map[string]*openfgav1.BatchCheckItem)
		for _, c := range capturedBatchReq.Checks {
			checksById[c.CorrelationId] = c
		}
		require.Contains(t, checksById, "instance", "instance check must be present")
		require.Contains(t, checksById, "root", "root check must be present")
		assert.Equal(t, "compute.miloapis.com/Workload:instance-1", checksById["instance"].TupleKey.Object)
		assert.Equal(t, "iam.miloapis.com/Root:compute.miloapis.com/Workload", checksById["root"].TupleKey.Object)
	})

	t.Run("collection operation uses BatchCheck with Root for both checks", func(t *testing.T) {
		// verb=list, no name. Collection operations resolve to Root for the object;
		// both the instance and root BatchCheck items target the Root resource.
		var capturedBatchReq *openfgav1.BatchCheckRequest
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				capturedBatchReq = req
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true}},
						"root":     {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					},
				}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		attributes := &mockAttributes{
			apiGroup: "compute.miloapis.com",
			resource: "workloads",
			name:     "", // no name = collection operation
			verb:     "list",
			user:     &user.DefaultInfo{Name: "test-user", UID: "user-abc"},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err)
		assert.Equal(t, authorizer.DecisionAllow, decision)
		require.NotNil(t, capturedBatchReq, "BatchCheck should have been called")
		require.Len(t, capturedBatchReq.Checks, 2, "BatchCheck must have instance and root checks")
		checksById := make(map[string]*openfgav1.BatchCheckItem)
		for _, c := range capturedBatchReq.Checks {
			checksById[c.CorrelationId] = c
		}
		require.Contains(t, checksById, "instance")
		require.Contains(t, checksById, "root")
		// For collection operations the resolved object is Root, so both checks target Root.
		assert.Equal(t, "iam.miloapis.com/Root:compute.miloapis.com/Workload", checksById["instance"].TupleKey.Object)
		assert.Equal(t, "iam.miloapis.com/Root:compute.miloapis.com/Workload", checksById["root"].TupleKey.Object)
	})

	t.Run("project-scoped request uses BatchCheck against Project, Root, and scope-root", func(t *testing.T) {
		// Project scope: BatchCheck with instance=Project, root=Root, and
		// scope-root=Root:Project; access is allowed if any allows.
		var capturedBatchReq *openfgav1.BatchCheckRequest
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				capturedBatchReq = req
				results := map[string]*openfgav1.BatchCheckSingleResult{}
				for _, check := range req.Checks {
					allowed := check.CorrelationId == "instance"
					results[check.CorrelationId] = &openfgav1.BatchCheckSingleResult{
						CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: allowed},
					}
				}
				return &openfgav1.BatchCheckResponse{Result: results}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		attributes := &mockAttributes{
			apiGroup: "compute.miloapis.com",
			resource: "workloads",
			name:     "wkld-123",
			verb:     "get",
			user: &user.DefaultInfo{
				Name: "test-user",
				UID:  "user-abc",
				Extra: map[string][]string{
					iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
					iamv1alpha1.ParentKindExtraKey:     {"Project"},
					iamv1alpha1.ParentNameExtraKey:     {"proj-xyz"},
				},
			},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err)
		assert.Equal(t, authorizer.DecisionAllow, decision)
		require.NotNil(t, capturedBatchReq, "BatchCheck should have been called")
		require.Len(t, capturedBatchReq.Checks, 3, "BatchCheck must have instance, root, and scope-root checks")
		checksById := make(map[string]*openfgav1.BatchCheckItem)
		for _, c := range capturedBatchReq.Checks {
			checksById[c.CorrelationId] = c
		}
		require.Contains(t, checksById, "instance")
		require.Contains(t, checksById, "root")
		require.Contains(t, checksById, "scope-root")
		assert.Equal(t, "resourcemanager.miloapis.com/Project:proj-xyz", checksById["instance"].TupleKey.Object)
		assert.Equal(t, "iam.miloapis.com/Root:compute.miloapis.com/Workload", checksById["root"].TupleKey.Object)
		assert.Equal(t, "iam.miloapis.com/Root:resourcemanager.miloapis.com/Project", checksById["scope-root"].TupleKey.Object)
	})

	t.Run("project-scoped request includes scope-root check for ResourceKind Project bindings", func(t *testing.T) {
		// Staff users have ResourceKind bindings targeting all Projects, which
		// write tuples to iam.miloapis.com/Root:resourcemanager.miloapis.com/Project.
		// When accessing a project-scoped resource in a project they don't own,
		// the instance check (Project:proj-xyz) and the resource root check
		// (Root:compute.miloapis.com/Workload) both deny. The scope-root
		// check (Root:resourcemanager.miloapis.com/Project) must also be
		// included so that staff bindings are evaluated.
		var capturedBatchReq *openfgav1.BatchCheckRequest
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				capturedBatchReq = req
				results := map[string]*openfgav1.BatchCheckSingleResult{}
				for _, check := range req.Checks {
					allowed := check.CorrelationId == "scope-root"
					results[check.CorrelationId] = &openfgav1.BatchCheckSingleResult{
						CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: allowed},
					}
				}
				return &openfgav1.BatchCheckResponse{Result: results}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		attributes := &mockAttributes{
			apiGroup: "compute.miloapis.com",
			resource: "workloads",
			name:     "wkld-123",
			verb:     "get",
			user: &user.DefaultInfo{
				Name: "staff-user",
				UID:  "staff-uid",
				Extra: map[string][]string{
					iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
					iamv1alpha1.ParentKindExtraKey:     {"Project"},
					iamv1alpha1.ParentNameExtraKey:     {"proj-xyz"},
				},
			},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err)
		assert.Equal(t, authorizer.DecisionAllow, decision,
			"staff user should be allowed via scope-root check (issue #90)")
		require.NotNil(t, capturedBatchReq, "BatchCheck should have been called")
		require.Len(t, capturedBatchReq.Checks, 3,
			"BatchCheck must have instance, root, and scope-root checks for project-scoped requests")
		checksById := make(map[string]*openfgav1.BatchCheckItem)
		for _, c := range capturedBatchReq.Checks {
			checksById[c.CorrelationId] = c
		}
		require.Contains(t, checksById, "instance")
		require.Contains(t, checksById, "root")
		require.Contains(t, checksById, "scope-root")
		assert.Equal(t, "resourcemanager.miloapis.com/Project:proj-xyz", checksById["instance"].TupleKey.Object)
		assert.Equal(t, "iam.miloapis.com/Root:compute.miloapis.com/Workload", checksById["root"].TupleKey.Object)
		assert.Equal(t, "iam.miloapis.com/Root:resourcemanager.miloapis.com/Project", checksById["scope-root"].TupleKey.Object)
	})

	t.Run("BatchCheck allows when instance check allows (ResourceRef binding)", func(t *testing.T) {
		// Instance check allows, Root denies — access must be granted.
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true}},
						"root":     {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					},
				}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		attributes := &mockAttributes{
			apiGroup: "compute.miloapis.com",
			resource: "workloads",
			name:     "instance-1",
			verb:     "get",
			user:     &user.DefaultInfo{Name: "test-user", UID: "user-abc"},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err)
		assert.Equal(t, authorizer.DecisionAllow, decision, "should be allowed when instance check allows")
	})

	t.Run("BatchCheck allows when Root check allows (ResourceKind binding)", func(t *testing.T) {
		// Instance denies, Root (ResourceKind binding) allows — access must be granted.
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
						"root":     {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true}},
					},
				}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		attributes := &mockAttributes{
			apiGroup: "compute.miloapis.com",
			resource: "workloads",
			name:     "instance-1",
			verb:     "get",
			user:     &user.DefaultInfo{Name: "test-user", UID: "user-abc"},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err)
		assert.Equal(t, authorizer.DecisionAllow, decision, "should be allowed via ResourceKind binding on Root")
	})

	t.Run("BatchCheck denies when both instance and Root deny", func(t *testing.T) {
		// Both deny — access must be denied.
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
						"root":     {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					},
				}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		attributes := &mockAttributes{
			apiGroup: "compute.miloapis.com",
			resource: "workloads",
			name:     "instance-1",
			verb:     "get",
			user:     &user.DefaultInfo{Name: "test-user", UID: "user-abc"},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err)
		assert.Equal(t, authorizer.DecisionDeny, decision, "should be denied when both instance and Root checks deny")
	})

	t.Run("collection operation denied when OpenFGA returns denied", func(t *testing.T) {
		// Collection op denied — both instance and root checks deny, propagate deny.
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
						"root":     {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					},
				}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		attributes := &mockAttributes{
			apiGroup: "compute.miloapis.com",
			resource: "workloads",
			verb:     "list",
			user:     &user.DefaultInfo{Name: "test-user", UID: "user-abc"},
		}

		decision, _, err := auth.Authorize(context.Background(), attributes)

		require.NoError(t, err)
		assert.Equal(t, authorizer.DecisionDeny, decision)
	})

	t.Run("collection operation uses BatchCheck not regular Check", func(t *testing.T) {
		// Verify that collection verbs (no resource name) use BatchCheck, not regular Check.
		var capturedBatchReq *openfgav1.BatchCheckRequest
		mockFGA := &mockFGAClient{
			BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
				capturedBatchReq = req
				return &openfgav1.BatchCheckResponse{
					Result: map[string]*openfgav1.BatchCheckSingleResult{
						"instance": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true}},
						"root":     {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					},
				}, nil
			},
		}

		auth := &webhook.SubjectAccessReviewAuthorizer{
			FGAClient:              mockFGA,
			ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
			FGAStoreID:             "test_store",
			DiscoveryClient:        &mockDiscoveryClient{},
		}

		for _, verb := range []string{"create"} {
			attributes := &mockAttributes{
				apiGroup: "compute.miloapis.com",
				resource: "workloads",
				verb:     verb,
				user:     &user.DefaultInfo{Name: "test-user", UID: "user-abc"},
			}

			_, _, err := auth.Authorize(context.Background(), attributes)
			require.NoError(t, err)
			require.NotNil(t, capturedBatchReq, "BatchCheck should be called for verb=%s", verb)
			capturedBatchReq = nil
		}
	})
}

// TestResourceKindGroupBindingViaBatchCheck verifies that group-based
// ResourceKind policy bindings resolve correctly via BatchCheck. The direct
// model stores group memberships as persistent tuples, and the Root fallback
// check in BatchCheck covers the ResourceKind binding path.
func TestResourceKindGroupBindingViaBatchCheck(t *testing.T) {

	computeWorkloadResource := iamv1alpha1.ProtectedResource{
		Spec: iamv1alpha1.ProtectedResourceSpec{
			ServiceRef:  iamv1alpha1.ServiceReference{Name: "compute.miloapis.com"},
			Plural:      "workloads",
			Kind:        "Workload",
			Permissions: []string{"get"},
		},
	}

	var capturedBatchReq *openfgav1.BatchCheckRequest
	mockFGA := &mockFGAClient{
		BatchCheckFunc: func(ctx context.Context, req *openfgav1.BatchCheckRequest, opts ...grpc.CallOption) (*openfgav1.BatchCheckResponse, error) {
			capturedBatchReq = req
			// Instance check denies (no direct binding), Root check allows
			// (group has ResourceKind binding on Root).
			return &openfgav1.BatchCheckResponse{
				Result: map[string]*openfgav1.BatchCheckSingleResult{
					"instance": {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: false}},
					"root":     {CheckResult: &openfgav1.BatchCheckSingleResult_Allowed{Allowed: true}},
				},
			}, nil
		},
	}

	auth := &webhook.SubjectAccessReviewAuthorizer{
		FGAClient:              mockFGA,
		ProtectedResourceCache: webhook.NewProtectedResourceCacheForTest([]iamv1alpha1.ProtectedResource{computeWorkloadResource}),
		FGAStoreID:             "test_store",
		DiscoveryClient:        &mockDiscoveryClient{},
	}

	attributes := &mockAttributes{
		apiGroup: "compute.miloapis.com",
		resource: "workloads",
		name:     "instance-1",
		verb:     "get",
		user: &user.DefaultInfo{
			Name:   "test-user",
			UID:    "user-abc",
			Groups: []string{"sales-engineers"},
		},
	}

	decision, _, err := auth.Authorize(context.Background(), attributes)

	require.NoError(t, err)
	assert.Equal(t, authorizer.DecisionAllow, decision,
		"user in group with ResourceKind binding should be allowed via Root BatchCheck")

	require.NotNil(t, capturedBatchReq)
	require.Len(t, capturedBatchReq.Checks, 2, "BatchCheck must include both instance and Root checks")

	var rootCheck *openfgav1.BatchCheckItem
	for _, c := range capturedBatchReq.Checks {
		if c.CorrelationId == "root" {
			rootCheck = c
		}
	}
	require.NotNil(t, rootCheck, "root check must be present in BatchCheck")
	assert.Equal(t, "iam.miloapis.com/Root:compute.miloapis.com/Workload", rootCheck.TupleKey.Object,
		"Root check must target the kind-level Root object for ResourceKind binding resolution")
}

// mockWebhookServer implements the WebhookServer interface for testing
type mockWebhookServer struct {
	registerFunc func(path string, handler http.Handler)
}

func (m *mockWebhookServer) Register(path string, hook http.Handler) {
	if m.registerFunc != nil {
		m.registerFunc(path, hook)
	}
}

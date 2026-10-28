package webhook_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.miloapis.com/auth-provider-openfga/internal/features"
	"go.miloapis.com/auth-provider-openfga/internal/webhook"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/discovery"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
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
	CheckFunc func(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error)
	WriteFunc func(ctx context.Context, in *openfgav1.WriteRequest, opts ...grpc.CallOption) (*openfgav1.WriteResponse, error)
}

func (m *mockFGAClient) Check(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
	if m.CheckFunc != nil {
		return m.CheckFunc(ctx, in)
	}
	return nil, errors.New("CheckFunc not implemented")
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
	// Enable the direct permission tuple model for these tests.
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.DirectPermissionTuples, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.LegacyRoleBindingModel, false)
	testCases := []struct {
		name               string
		attributes         authorizer.Attributes
		protectedResources []iamv1alpha1.ProtectedResource
		fgaCheckFunc       func(*testing.T, *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error)
		expectedDecision   authorizer.Decision
		expectedErrorMsg   string
		expectFgaCheckCall bool
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
			fgaCheckFunc: func(t *testing.T, req *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error) {
				// When project is parent, we authorize against the project itself.
				// RootBinding tuples are now stored tuples (written by the policy reconciler),
				// not contextual tuples, so there should be no contextual tuples here.
				assert.Equal(t, "resourcemanager.miloapis.com/Project:proj-xyz", req.TupleKey.Object)
				assert.Nil(t, req.ContextualTuples)
				return &openfgav1.CheckResponse{Allowed: true}, nil
			},
			expectedDecision:   authorizer.DecisionAllow,
			expectFgaCheckCall: true,
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
			fgaCheckFunc: func(t *testing.T, req *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error) {
				// RootBinding tuples are now stored tuples; no contextual tuples expected.
				assert.Equal(t, "resourcemanager.miloapis.com/Project:proj-xyz", req.TupleKey.Object)
				assert.Nil(t, req.ContextualTuples)
				return &openfgav1.CheckResponse{Allowed: false}, nil
			},
			expectedDecision:   authorizer.DecisionDeny,
			expectFgaCheckCall: true,
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
			name: "no contextual tuple for unregistered parent",
			attributes: &mockAttributes{
				apiGroup: "compute.miloapis.com",
				resource: "workloads",
				name:     "wkld-123",
				verb:     "get",
				user: &user.DefaultInfo{
					Name: "test-user",
					UID:  "user-abc",
					Extra: map[string][]string{
						iamv1alpha1.ParentAPIGroupExtraKey: {"some.other.api"},
						iamv1alpha1.ParentKindExtraKey:     {"OtherKind"},
						iamv1alpha1.ParentNameExtraKey:     {"other-123"},
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
			fgaCheckFunc: func(t *testing.T, req *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error) {
				// RootBinding tuples are now stored tuples; no contextual tuples expected.
				assert.Equal(t, "compute.miloapis.com/Workload:wkld-123", req.TupleKey.Object)
				assert.Nil(t, req.ContextualTuples)
				return &openfgav1.CheckResponse{Allowed: true}, nil
			},
			expectedDecision:   authorizer.DecisionAllow,
			expectFgaCheckCall: true,
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
			mockFGA := &mockFGAClient{
				CheckFunc: func(ctx context.Context, req *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
					fgaCheckCalled = true
					if tc.fgaCheckFunc != nil {
						return tc.fgaCheckFunc(t, req)
					}
					return nil, errors.New("FGA CheckFunc not provided")
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
			assert.Equal(t, tc.expectFgaCheckCall, fgaCheckCalled)
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
			CheckFunc: func(ctx context.Context, req *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
				// Verify that project-scoped requests target the project resource
				assert.Contains(t, req.TupleKey.Object, "resourcemanager.miloapis.com/Project:")
				return &openfgav1.CheckResponse{Allowed: true}, nil
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
			CheckFunc: func(ctx context.Context, req *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
				// Verify it uses organization resource for collection operations with org context
				assert.Equal(t, "resourcemanager.miloapis.com/Organization:acme", req.TupleKey.Object)
				return &openfgav1.CheckResponse{Allowed: true}, nil
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
			CheckFunc: func(ctx context.Context, req *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
				return &openfgav1.CheckResponse{Allowed: true}, nil
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
			CheckFunc: func(ctx context.Context, req *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
				// Should use organization resource for collection operations
				assert.Equal(t, "resourcemanager.miloapis.com/Organization:acme", req.TupleKey.Object)
				return &openfgav1.CheckResponse{Allowed: true}, nil
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

// mockWebhookServer implements the WebhookServer interface for testing
type mockWebhookServer struct {
	registerFunc func(path string, handler http.Handler)
}

func (m *mockWebhookServer) Register(path string, hook http.Handler) {
	if m.registerFunc != nil {
		m.registerFunc(path, hook)
	}
}

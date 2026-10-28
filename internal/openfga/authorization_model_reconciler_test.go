package openfga

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.miloapis.com/auth-provider-openfga/internal/features"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// MockOpenFGAServiceClient is a mock implementation of openfgav1.OpenFGAServiceClient for testing
type MockOpenFGAServiceClient struct {
	openfgav1.OpenFGAServiceClient
	ReadAuthorizationModelsFunc func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error)
	ReadAuthorizationModelFunc  func(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error)
	WriteAuthorizationModelFunc func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error)
}

func (m *MockOpenFGAServiceClient) ReadAuthorizationModels(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
	if m.ReadAuthorizationModelsFunc != nil {
		return m.ReadAuthorizationModelsFunc(ctx, in, opts...)
	}
	return &openfgav1.ReadAuthorizationModelsResponse{}, nil
}

func (m *MockOpenFGAServiceClient) ReadAuthorizationModel(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
	if m.ReadAuthorizationModelFunc != nil {
		return m.ReadAuthorizationModelFunc(ctx, in, opts...)
	}
	return &openfgav1.ReadAuthorizationModelResponse{}, nil
}

func (m *MockOpenFGAServiceClient) WriteAuthorizationModel(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
	if m.WriteAuthorizationModelFunc != nil {
		return m.WriteAuthorizationModelFunc(ctx, in, opts...)
	}
	return &openfgav1.WriteAuthorizationModelResponse{}, nil
}

// buildExpectedResourceTypeDefinition is a test helper that constructs the
// TypeDefinition the reconciler would generate for a resource with direct
// permissions (no parent). It mirrors getResourceTypeDefinition for the
// no-parent case and is used to build golden-state models in tests.
func buildExpectedResourceTypeDefinition(resourceType string, permissions []string) *openfgav1.TypeDefinition {
	node := &resourceGraphNode{
		ResourceType:    resourceType,
		ParentResources: []string{},
	}
	return getResourceTypeDefinition(permissions, node)
}

func TestAuthorizationModelReconciler_ReconcileAuthorizationModel(t *testing.T) {
	// Enable the direct permission tuple model for these tests.
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.DirectPermissionTuples, true)
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.LegacyRoleBindingModel, false)

	// Set up test logger
	logf.SetLogger(zap.New())

	testCases := []struct {
		name                            string
		protectedResources              []iamdatumapiscomv1alpha1.ProtectedResource
		currentModel                    *openfgav1.AuthorizationModel
		expectedWriteAuthorizationCalls int
		expectedError                   string
	}{
		{
			name: "should skip write when models are identical",
			protectedResources: []iamdatumapiscomv1alpha1.ProtectedResource{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-resource"},
					Spec: iamdatumapiscomv1alpha1.ProtectedResourceSpec{
						ServiceRef:  iamdatumapiscomv1alpha1.ServiceReference{Name: "test.service.com"},
						Plural:      "testresources",
						Kind:        "TestResource",
						Permissions: []string{"get", "list"},
					},
				},
			},
			currentModel: &openfgav1.AuthorizationModel{
				SchemaVersion: "1.2",
				TypeDefinitions: []*openfgav1.TypeDefinition{
					// Direct-permission model: InternalUser, InternalUserGroup, Root,
					// and the resource type definitions.
					getUserTypeDefinition(),
					getUserGroupTypeDefinition(),
					getRootTypeDefinition([]string{
						"test.service.com/testresources.get",
						"test.service.com/testresources.list",
					}),
					buildExpectedResourceTypeDefinition("test.service.com/TestResource", []string{
						"test.service.com/testresources.get",
						"test.service.com/testresources.list",
					}),
				},
			},
			expectedWriteAuthorizationCalls: 0, // Should not call WriteAuthorizationModel
		},
		{
			name: "should write when models are different",
			protectedResources: []iamdatumapiscomv1alpha1.ProtectedResource{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-resource"},
					Spec: iamdatumapiscomv1alpha1.ProtectedResourceSpec{
						ServiceRef:  iamdatumapiscomv1alpha1.ServiceReference{Name: "test.service.com"},
						Plural:      "testresources",
						Kind:        "TestResource",
						Permissions: []string{"get", "list"},
					},
				},
			},
			currentModel: &openfgav1.AuthorizationModel{
				SchemaVersion: "1.2",
				TypeDefinitions: []*openfgav1.TypeDefinition{
					// Different model - missing some expected type definitions
					getUserTypeDefinition(),
					getUserGroupTypeDefinition(),
				},
			},
			expectedWriteAuthorizationCalls: 1, // Should call WriteAuthorizationModel once
		},
		{
			name:               "should write when no current model exists",
			protectedResources: []iamdatumapiscomv1alpha1.ProtectedResource{},
			currentModel:       &openfgav1.AuthorizationModel{}, // Empty model
			// Minimal model has InternalUser + InternalUserGroup = 2 types
			expectedWriteAuthorizationCalls: 1, // Should call WriteAuthorizationModel once
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writeAuthorizationCalls := 0

			mockClient := &MockOpenFGAServiceClient{
				ReadAuthorizationModelsFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
					// Return that we have an authorization model
					return &openfgav1.ReadAuthorizationModelsResponse{
						AuthorizationModels: []*openfgav1.AuthorizationModel{
							{Id: "test-model-id"},
						},
					}, nil
				},
				ReadAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
					// Return the current model provided in test case
					return &openfgav1.ReadAuthorizationModelResponse{
						AuthorizationModel: tc.currentModel,
					}, nil
				},
				WriteAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
					writeAuthorizationCalls++
					return &openfgav1.WriteAuthorizationModelResponse{
						AuthorizationModelId: "new-model-id",
					}, nil
				},
			}

			reconciler := &AuthorizationModelReconciler{
				StoreID: "test-store",
				OpenFGA: mockClient,
			}

			ctx := logf.IntoContext(context.Background(), logf.Log)
			err := reconciler.ReconcileAuthorizationModel(ctx, tc.protectedResources)

			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tc.expectedWriteAuthorizationCalls, writeAuthorizationCalls,
				"Expected %d WriteAuthorizationModel calls, but got %d",
				tc.expectedWriteAuthorizationCalls, writeAuthorizationCalls)
		})
	}
}

func TestAuthorizationModelReconciler_ReconcileAuthorizationModel_NoCurrentModel(t *testing.T) {
	// Test case where no authorization model exists yet
	logf.SetLogger(zap.New())

	writeAuthorizationCalls := 0

	mockClient := &MockOpenFGAServiceClient{
		ReadAuthorizationModelsFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
			// Return empty list - no models exist yet
			return &openfgav1.ReadAuthorizationModelsResponse{
				AuthorizationModels: []*openfgav1.AuthorizationModel{},
			}, nil
		},
		WriteAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
			writeAuthorizationCalls++
			// Verify the request contains expected data
			assert.Equal(t, "test-store", in.StoreId)
			assert.Equal(t, "1.2", in.SchemaVersion)
			// Minimal model: InternalUser + InternalUserGroup = 2 type definitions
			assert.Len(t, in.TypeDefinitions, 2)
			return &openfgav1.WriteAuthorizationModelResponse{
				AuthorizationModelId: "new-model-id",
			}, nil
		},
	}

	reconciler := &AuthorizationModelReconciler{
		StoreID: "test-store",
		OpenFGA: mockClient,
	}

	ctx := logf.IntoContext(context.Background(), logf.Log)
	err := reconciler.ReconcileAuthorizationModel(ctx, []iamdatumapiscomv1alpha1.ProtectedResource{})

	require.NoError(t, err)
	assert.Equal(t, 1, writeAuthorizationCalls, "Should call WriteAuthorizationModel once when no current model exists")
}

func TestAuthorizationModelReconciler_ReconcileAuthorizationModel_WithConditions(t *testing.T) {
	// Test that existing conditions are preserved in the merged model
	logf.SetLogger(zap.New())

	writeAuthorizationCalls := 0
	existingConditions := map[string]*openfgav1.Condition{
		"test_condition": {
			Name:       "test_condition",
			Expression: "param.test == 'value'",
		},
	}

	mockClient := &MockOpenFGAServiceClient{
		ReadAuthorizationModelsFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
			return &openfgav1.ReadAuthorizationModelsResponse{
				AuthorizationModels: []*openfgav1.AuthorizationModel{
					{Id: "test-model-id"},
				},
			}, nil
		},
		ReadAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
			return &openfgav1.ReadAuthorizationModelResponse{
				AuthorizationModel: &openfgav1.AuthorizationModel{
					SchemaVersion:   "1.2",
					Conditions:      existingConditions,
					TypeDefinitions: []*openfgav1.TypeDefinition{}, // Different model
				},
			}, nil
		},
		WriteAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
			writeAuthorizationCalls++
			// Verify that conditions are preserved
			assert.Equal(t, existingConditions, in.Conditions)
			return &openfgav1.WriteAuthorizationModelResponse{
				AuthorizationModelId: "new-model-id",
			}, nil
		},
	}

	reconciler := &AuthorizationModelReconciler{
		StoreID: "test-store",
		OpenFGA: mockClient,
	}

	ctx := logf.IntoContext(context.Background(), logf.Log)
	err := reconciler.ReconcileAuthorizationModel(ctx, []iamdatumapiscomv1alpha1.ProtectedResource{})

	require.NoError(t, err)
	assert.Equal(t, 1, writeAuthorizationCalls, "Should call WriteAuthorizationModel once")
}

// TestAuthorizationModelReconciler_OrderingOptimization tests that models with different
// ordering but same content are correctly identified as identical
func TestAuthorizationModelReconciler_OrderingOptimization(t *testing.T) {
	// Setup logging
	logf.SetLogger(zap.New())
	ctx := logf.IntoContext(context.TODO(), logf.Log)

	// Create realistic protected resources that would generate the same model
	protectedResources := []iamdatumapiscomv1alpha1.ProtectedResource{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "network-pr"},
			Spec: iamdatumapiscomv1alpha1.ProtectedResourceSpec{
				ServiceRef:  iamdatumapiscomv1alpha1.ServiceReference{Name: "networking.miloapis.com"},
				Kind:        "Network",
				Plural:      "networks",
				Permissions: []string{"read", "write"},
			},
		},
	}

	// Create a reconciler to generate the expected model
	tempReconciler := &AuthorizationModelReconciler{
		StoreID: "test-store",
		OpenFGA: nil, // We won't call OpenFGA methods
	}

	// Generate the expected model that would be created
	expectedModel, err := tempReconciler.createExpectedAuthorizationModel(protectedResources)
	require.NoError(t, err)

	// Create the same model but simulate different ordering from OpenFGA
	// by manually reordering the TypeDefinitions
	currentModelFromOpenFGA := proto.Clone(expectedModel).(*openfgav1.AuthorizationModel)
	if len(currentModelFromOpenFGA.TypeDefinitions) > 1 {
		// Reverse the order to simulate different ordering
		typeDefs := currentModelFromOpenFGA.TypeDefinitions
		for i, j := 0, len(typeDefs)-1; i < j; i, j = i+1, j-1 {
			typeDefs[i], typeDefs[j] = typeDefs[j], typeDefs[i]
		}
	}

	// Verify that proto.Equal returns false (confirming the ordering issue)
	assert.False(t, proto.Equal(currentModelFromOpenFGA, expectedModel),
		"proto.Equal should return false for models with different ordering")

	// Verify that our go-cmp based comparison returns true despite ordering differences
	assert.True(t, authorizationModelsEqual(currentModelFromOpenFGA, expectedModel),
		"authorizationModelsEqual should return true for models with different ordering")

	writeCallCount := 0
	mockClient := &MockOpenFGAServiceClient{
		ReadAuthorizationModelsFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
			return &openfgav1.ReadAuthorizationModelsResponse{
				AuthorizationModels: []*openfgav1.AuthorizationModel{
					{Id: "model1"},
				},
			}, nil
		},
		ReadAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
			return &openfgav1.ReadAuthorizationModelResponse{
				AuthorizationModel: currentModelFromOpenFGA, // Return model with different ordering
			}, nil
		},
		WriteAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
			writeCallCount++
			return &openfgav1.WriteAuthorizationModelResponse{}, nil
		},
	}

	reconciler := &AuthorizationModelReconciler{
		StoreID: "test-store",
		OpenFGA: mockClient,
	}

	// This should NOT call WriteAuthorizationModel since models are semantically equal
	err = reconciler.ReconcileAuthorizationModel(ctx, protectedResources)
	require.NoError(t, err)

	// Verify that WriteAuthorizationModel was not called
	assert.Equal(t, 0, writeCallCount, "WriteAuthorizationModel should not be called when models are semantically equal")
}

// TestAuthorizationModelsEqual_TypeDefinitionOrdering tests that models with different
// TypeDefinition ordering but same content are correctly identified as identical
func TestAuthorizationModelsEqual_TypeDefinitionOrdering(t *testing.T) {
	// Create two identical models but with different TypeDefinition ordering
	model1 := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{Type: "iam.miloapis.com/InternalUser"},
			{Type: "networking.miloapis.com/Network"},
			{Type: "iam.miloapis.com/InternalUserGroup"},
		},
	}

	model2 := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{Type: "iam.miloapis.com/InternalUserGroup"},
			{Type: "iam.miloapis.com/InternalUser"},
			{Type: "networking.miloapis.com/Network"},
		},
	}

	// Test that our go-cmp based comparison handles ordering correctly
	assert.True(t, authorizationModelsEqual(model1, model2),
		"authorizationModelsEqual should return true for models with different TypeDefinition ordering")

	// Verify that the direct go-cmp comparison would detect differences without our sorting options
	assert.False(t, cmp.Equal(model1, model2, protocmp.Transform()), "Raw cmp.Equal should detect ordering differences")

	// Test that different schema versions are detected as different
	model3 := &openfgav1.AuthorizationModel{
		SchemaVersion:   "1.1", // Different version
		TypeDefinitions: model2.TypeDefinitions,
	}
	assert.False(t, authorizationModelsEqual(model1, model3),
		"Models with different schema versions should not be equal")
}

func TestAuthorizationModelReconciler_MapOrderingOptimization(t *testing.T) {
	// Create two identical models but with different map ordering — these should
	// be treated as equal by our comparison helper.
	hashedGet := hashPermission("test.service.com/testresources.get")

	model1 := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{
				Type: "test.service.com/TestResource",
				Relations: map[string]*openfgav1.Userset{
					hashedGet: {Userset: &openfgav1.Userset_This{}},
				},
				Metadata: &openfgav1.Metadata{
					Relations: map[string]*openfgav1.RelationMetadata{
						hashedGet: {
							DirectlyRelatedUserTypes: []*openfgav1.RelationReference{
								{Type: TypeInternalUser},
							},
						},
					},
				},
			},
		},
	}

	model2 := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{
				Type: "test.service.com/TestResource",
				Relations: map[string]*openfgav1.Userset{
					hashedGet: {Userset: &openfgav1.Userset_This{}},
				},
				Metadata: &openfgav1.Metadata{
					Relations: map[string]*openfgav1.RelationMetadata{
						hashedGet: {
							DirectlyRelatedUserTypes: []*openfgav1.RelationReference{
								{Type: TypeInternalUser},
							},
						},
					},
				},
			},
		},
	}

	assert.True(t, authorizationModelsEqual(model1, model2), "authorizationModelsEqual should handle map ordering differences")
}

func TestAuthorizationModelsEqual_IdFieldIgnored(t *testing.T) {
	// Create two identical models, but one has an id field
	modelWithId := &openfgav1.AuthorizationModel{
		Id:            "01JZ3JDMRJ99MFDMCX65ZNHBHG",
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{
				Type: "iam.miloapis.com/InternalUser",
				Metadata: &openfgav1.Metadata{
					Module: iamdatumapiscomv1alpha1.SchemeGroupVersion.Group,
				},
			},
		},
	}

	modelWithoutId := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{
				Type: "iam.miloapis.com/InternalUser",
				Metadata: &openfgav1.Metadata{
					Module: iamdatumapiscomv1alpha1.SchemeGroupVersion.Group,
				},
			},
		},
	}

	// They should be considered equal despite the id difference
	assert.True(t, authorizationModelsEqual(modelWithId, modelWithoutId))
	assert.True(t, authorizationModelsEqual(modelWithoutId, modelWithId))
}

// TestDirectPermissionModel_ResourceTypeDefinition verifies that the generated
// TypeDefinition for a resource under the direct-permission model:
//   - Has no RoleBinding or RootBinding relations
//   - Has one hashed-permission relation per permission
//   - Each relation declares InternalUser and InternalUserGroup#member as
//     directly-related user types
func TestDirectPermissionModel_ResourceTypeDefinition(t *testing.T) {
	permissions := []string{
		"resourcemanager.miloapis.com/organizations.get",
		"resourcemanager.miloapis.com/organizations.update",
	}
	node := &resourceGraphNode{
		ResourceType:    "resourcemanager.miloapis.com/Organization",
		ParentResources: []string{},
	}

	td := getResourceTypeDefinition(permissions, node)

	// No legacy RoleBinding or RootBinding relations
	assert.NotContains(t, td.Relations, RelationRoleBinding, "should not have RoleBinding relation")
	assert.NotContains(t, td.Relations, RelationRootBinding, "should not have RootBinding relation")

	// One hashed-permission relation per permission
	for _, perm := range permissions {
		hashed := hashPermission(perm)
		assert.Contains(t, td.Relations, hashed, "should have hashed relation for %s", perm)

		// The relation metadata should list InternalUser and InternalUserGroup#member
		meta, ok := td.Metadata.Relations[hashed]
		require.True(t, ok, "metadata missing for hashed relation %s", hashed)

		types := make(map[string]bool)
		for _, ref := range meta.DirectlyRelatedUserTypes {
			if ref.GetRelation() != "" {
				types[ref.Type+"#"+ref.GetRelation()] = true
			} else {
				types[ref.Type] = true
			}
		}
		assert.True(t, types[TypeInternalUser], "InternalUser should be directly related")
		assert.True(t, types[TypeInternalUserGroup+"#"+RelationMember], "InternalUserGroup#member should be directly related")
	}
}

// TestDirectPermissionModel_ParentInheritance verifies that permission relations
// on a child resource include a TupleToUserset branch that reads from the parent
// relation when the resource has registered parents.
func TestDirectPermissionModel_ParentInheritance(t *testing.T) {
	permissions := []string{"compute.miloapis.com/workloads.get"}
	node := &resourceGraphNode{
		ResourceType:    "compute.miloapis.com/Workload",
		ParentResources: []string{"resourcemanager.miloapis.com/Project"},
	}

	td := getResourceTypeDefinition(permissions, node)

	// Parent relation should exist
	assert.Contains(t, td.Relations, RelationParent, "should have parent relation")

	hashed := hashPermission(permissions[0])
	relation, ok := td.Relations[hashed]
	require.True(t, ok, "hashed permission relation should exist")

	union := relation.GetUnion()
	require.NotNil(t, union, "permission relation should be a Union when there are parents")
	assert.Len(t, union.Child, 2, "union should have 2 children: direct + parent-inherited")

	// First child: direct assignment (This)
	assert.NotNil(t, union.Child[0].GetThis(), "first child should be This (direct assignment)")

	// Second child: inherited from parent (TupleToUserset via parent relation)
	ttu := union.Child[1].GetTupleToUserset()
	require.NotNil(t, ttu, "second child should be TupleToUserset")
	assert.Equal(t, RelationParent, ttu.Tupleset.Relation)
	assert.Equal(t, hashed, ttu.ComputedUserset.Relation)
}

// TestDirectPermissionModel_MinimalModel verifies that getMinimalAuthorizationModel
// returns only InternalUser and InternalUserGroup — no RoleBinding, InternalRole,
// or Root.
func TestDirectPermissionModel_MinimalModel(t *testing.T) {
	model := getMinimalAuthorizationModel()

	require.Len(t, model.TypeDefinitions, 2, "minimal model should have exactly 2 types")

	typeNames := make(map[string]bool)
	for _, td := range model.TypeDefinitions {
		typeNames[td.Type] = true
	}

	assert.True(t, typeNames[TypeInternalUser], "minimal model should contain InternalUser")
	assert.True(t, typeNames[TypeInternalUserGroup], "minimal model should contain InternalUserGroup")
	assert.False(t, typeNames[TypeRoleBinding], "minimal model should NOT contain RoleBinding")
	assert.False(t, typeNames[TypeInternalRole], "minimal model should NOT contain InternalRole")
	assert.False(t, typeNames[TypeRoot], "minimal model should NOT contain Root")
}

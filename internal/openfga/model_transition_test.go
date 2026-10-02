package openfga

import (
	"context"
	"errors"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type transitionTestClient struct {
	openfgav1.OpenFGAServiceClient
	latestModel *openfgav1.AuthorizationModel
	writeIDs    []string
	writeErr    error
}

func (c *transitionTestClient) Write(_ context.Context, request *openfgav1.WriteRequest, _ ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
	c.writeIDs = append(c.writeIDs, request.GetAuthorizationModelId())
	if c.writeErr != nil {
		err := c.writeErr
		c.writeErr = nil
		return nil, err
	}
	return &openfgav1.WriteResponse{}, nil
}

func (c *transitionTestClient) ReadAuthorizationModels(_ context.Context, _ *openfgav1.ReadAuthorizationModelsRequest, _ ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
	return &openfgav1.ReadAuthorizationModelsResponse{
		AuthorizationModels: []*openfgav1.AuthorizationModel{{Id: c.latestModel.GetId()}},
	}, nil
}

func (c *transitionTestClient) ReadAuthorizationModel(_ context.Context, _ *openfgav1.ReadAuthorizationModelRequest, _ ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
	return &openfgav1.ReadAuthorizationModelResponse{AuthorizationModel: c.latestModel}, nil
}

type transitionTestModelID struct{ id string }

func (m *transitionTestModelID) GetModelID() string   { return m.id }
func (m *transitionTestModelID) SetModelID(id string) { m.id = id }

func TestWriteWithModelTransitionRetryUsesLatestModelWhenItDefinesRelation(t *testing.T) {
	client := &transitionTestClient{
		latestModel: &openfgav1.AuthorizationModel{
			Id: "model-new",
			TypeDefinitions: []*openfgav1.TypeDefinition{{
				Type:      "resourcemanager.miloapis.com/Organization",
				Relations: map[string]*openfgav1.Userset{"41b6cf4a": {Userset: &openfgav1.Userset_This{}}},
			}},
		},
		writeErr: errors.New("Invalid tuple: relation not found in pinned model"),
	}
	modelID := &transitionTestModelID{id: "model-old"}
	request := &openfgav1.WriteRequest{
		StoreId:              "store",
		AuthorizationModelId: "model-old",
		Writes: &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{{
			User:     "iam.miloapis.com/InternalUser:user",
			Relation: "41b6cf4a",
			Object:   "resourcemanager.miloapis.com/Organization:org",
		}}},
	}

	require.NoError(t, writeWithModelTransitionRetry(context.Background(), client, request, modelID))
	require.Equal(t, []string{"model-old", "model-new"}, client.writeIDs)
	require.Equal(t, "model-new", modelID.GetModelID())
}

func TestWriteWithModelTransitionRetryDoesNotRetryUnknownRelation(t *testing.T) {
	client := &transitionTestClient{
		latestModel: &openfgav1.AuthorizationModel{
			Id: "model-new",
			TypeDefinitions: []*openfgav1.TypeDefinition{{
				Type:      "resourcemanager.miloapis.com/Organization",
				Relations: map[string]*openfgav1.Userset{"known": {Userset: &openfgav1.Userset_This{}}},
			}},
		},
		writeErr: errors.New("Invalid tuple: relation not found in pinned model"),
	}
	modelID := &transitionTestModelID{id: "model-old"}
	request := &openfgav1.WriteRequest{
		StoreId:              "store",
		AuthorizationModelId: "model-old",
		Writes: &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{{
			Relation: "unregistered",
			Object:   "resourcemanager.miloapis.com/Organization:org",
		}}},
	}

	err := writeWithModelTransitionRetry(context.Background(), client, request, modelID)
	require.ErrorContains(t, err, "Invalid tuple")
	require.Equal(t, []string{"model-old"}, client.writeIDs)
	require.Equal(t, "model-old", modelID.GetModelID())
}

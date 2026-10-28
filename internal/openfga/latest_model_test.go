package openfga

import (
	"context"
	"errors"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// onePageModelsClient lists authorization models only one at a time. A full page is 50 models, and a store with large
// models can take longer to list them than the server's request deadline, which then ends the read with code 4004.
type onePageModelsClient struct {
	*transitionTestClient
	pageSizes []int32
}

func (c *onePageModelsClient) ReadAuthorizationModels(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
	c.pageSizes = append(c.pageSizes, in.GetPageSize().GetValue())
	if in.GetPageSize().GetValue() != 1 {
		return nil, status.Error(codes.Code(4004), "Request Deadline Exceeded")
	}
	return c.transitionTestClient.ReadAuthorizationModels(ctx, in, opts...)
}

func newModelWithOrganizationRelation(id, relation string) *openfgav1.AuthorizationModel {
	return &openfgav1.AuthorizationModel{
		Id: id,
		TypeDefinitions: []*openfgav1.TypeDefinition{{
			Type:      "resourcemanager.miloapis.com/Organization",
			Relations: map[string]*openfgav1.Userset{relation: {Userset: &openfgav1.Userset_This{}}},
		}},
	}
}

// TestWriteWithModelTransitionRetryReadsOnlyTheNewestModel checks that the retry after an invalid-tuple write reads
// the newest model alone. A read of every model can miss the deadline, and the write then fails although the newest
// model defines the relation.
func TestWriteWithModelTransitionRetryReadsOnlyTheNewestModel(t *testing.T) {
	client := &onePageModelsClient{transitionTestClient: &transitionTestClient{
		latestModel: newModelWithOrganizationRelation("model-new", "41b6cf4a"),
		writeErr:    errors.New("Invalid tuple: relation not found in pinned model"),
	}}
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
	require.Equal(t, []int32{1}, client.pageSizes)
	require.Equal(t, []string{"model-old", "model-new"}, client.writeIDs)
	require.Equal(t, "model-new", modelID.GetModelID())
}

// TestMayBeModelTransition checks which failed writes the retry considers: additions only, pinned to a model ID, and
// refused as an invalid tuple.
func TestMayBeModelTransition(t *testing.T) {
	invalid := errors.New("Invalid tuple: relation not found in pinned model")
	additions := &openfgav1.WriteRequestWrites{TupleKeys: []*openfgav1.TupleKey{{Relation: "r", Object: "t:o"}}}
	deletes := &openfgav1.WriteRequestDeletes{TupleKeys: []*openfgav1.TupleKeyWithoutCondition{{Relation: "r", Object: "t:o"}}}
	cases := []struct {
		name    string
		request *openfgav1.WriteRequest
		err     error
		want    bool
	}{
		{"pinned additions refused as invalid", &openfgav1.WriteRequest{AuthorizationModelId: "m", Writes: additions}, invalid, true},
		{"no pinned model", &openfgav1.WriteRequest{Writes: additions}, invalid, false},
		{"no additions", &openfgav1.WriteRequest{AuthorizationModelId: "m", Writes: &openfgav1.WriteRequestWrites{}}, invalid, false},
		{"deletes as well", &openfgav1.WriteRequest{AuthorizationModelId: "m", Writes: additions, Deletes: deletes}, invalid, false},
		{"another error", &openfgav1.WriteRequest{AuthorizationModelId: "m", Writes: additions}, errors.New("unavailable"), false},
	}
	for _, c := range cases {
		require.Equal(t, c.want, mayBeModelTransition(c.request, c.err), c.name)
	}
}

// TestCurrentAuthorizationModelReadsOnlyTheNewestModel checks that the model reconciler reads the newest model the
// same way.
func TestCurrentAuthorizationModelReadsOnlyTheNewestModel(t *testing.T) {
	client := &onePageModelsClient{transitionTestClient: &transitionTestClient{
		latestModel: newModelWithOrganizationRelation("model-new", "41b6cf4a"),
	}}
	reconciler := &AuthorizationModelReconciler{OpenFGA: client, StoreID: "store"}

	model, err := reconciler.getCurrentAuthorizationModel(context.Background())
	require.NoError(t, err)
	require.Equal(t, "model-new", model.GetId())
	require.Equal(t, []int32{1}, client.pageSizes)
}

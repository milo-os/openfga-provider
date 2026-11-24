package openfga

import (
	"context"
	"fmt"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/protobuf/proto"
)

type modelIDUpdater interface {
	SetModelID(string)
}

// writeWithModelTransitionRetry handles the short window where OpenFGA has
// accepted a new model but a caller still has the previous model ID cached.
// Retry only when the latest model explicitly defines every relation in the
// requested additions. Deletes do not need model validation, so a mixed
// add/remove request can remain atomic. This keeps unknown permissions
// fail-closed.
func writeWithModelTransitionRetry(
	ctx context.Context,
	client openfgav1.OpenFGAServiceClient,
	request *openfgav1.WriteRequest,
	modelIDProvider ModelIDProvider,
) error {
	_, err := client.Write(ctx, request)
	if err == nil {
		return nil
	}
	if !mayBeModelTransition(request, err) {
		return err
	}

	latestModel, readErr := latestAuthorizationModel(ctx, client, request.GetStoreId())
	if readErr != nil {
		return fmt.Errorf("failed to read the latest authorization model after a tuple write failed: %w", readErr)
	}

	latestModelID := latestModel.GetId()
	if latestModelID == "" || latestModelID == request.GetAuthorizationModelId() {
		return err
	}
	if !modelSupportsTupleWrites(latestModel, request.GetWrites().GetTupleKeys()) {
		return err
	}

	if updater, ok := modelIDProvider.(modelIDUpdater); ok &&
		modelIDProvider.GetModelID() == request.GetAuthorizationModelId() {
		updater.SetModelID(latestModelID)
	}

	retryRequest := proto.Clone(request).(*openfgav1.WriteRequest)
	retryRequest.AuthorizationModelId = latestModelID
	if _, retryErr := client.Write(ctx, retryRequest); retryErr != nil {
		return fmt.Errorf("failed to write permission tuples with latest authorization model %q: %w", latestModelID, retryErr)
	}
	return nil
}

// mayBeModelTransition reports whether a failed write can be the transition's: additions only, pinned to a model ID,
// and refused as an invalid tuple.
func mayBeModelTransition(request *openfgav1.WriteRequest, err error) bool {
	return request.GetAuthorizationModelId() != "" &&
		len(request.GetWrites().GetTupleKeys()) > 0 &&
		strings.Contains(err.Error(), "Invalid tuple")
}

func modelSupportsTupleWrites(model *openfgav1.AuthorizationModel, tupleKeys []*openfgav1.TupleKey) bool {
	if model == nil {
		return false
	}
	relationsByType := make(map[string]map[string]struct{}, len(model.GetTypeDefinitions()))
	for _, typeDefinition := range model.GetTypeDefinitions() {
		relations := make(map[string]struct{}, len(typeDefinition.GetRelations()))
		for relation := range typeDefinition.GetRelations() {
			relations[relation] = struct{}{}
		}
		relationsByType[typeDefinition.GetType()] = relations
	}

	for _, tupleKey := range tupleKeys {
		objectType, _, found := strings.Cut(tupleKey.GetObject(), ":")
		if !found {
			return false
		}
		if _, found := relationsByType[objectType][tupleKey.GetRelation()]; !found {
			return false
		}
	}
	return true
}

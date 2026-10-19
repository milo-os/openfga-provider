package openfga

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

// MaxTuplesPerWrite is OpenFGA's default limit on the tuples in one Write.
const MaxTuplesPerWrite = 100

// onMissingIgnore makes a delete skip a tuple that is already gone, so a tuple
// another writer removed first does not fail the batch. OpenFGA v1.10.0 and
// later honour it; an older server ignores the field and fails as before.
const onMissingIgnore = "ignore"

// DeleteTuples deletes the tuples in writes of at most MaxTuplesPerWrite,
// skipping any that is already gone.
func DeleteTuples(ctx context.Context, client openfgav1.OpenFGAServiceClient, storeID, modelID string, tuples []*openfgav1.TupleKey) error {
	for start := 0; start < len(tuples); start += MaxTuplesPerWrite {
		batch := tuples[start:min(start+MaxTuplesPerWrite, len(tuples))]
		if _, err := client.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			Deletes:              &openfgav1.WriteRequestDeletes{TupleKeys: convertTuplesForDelete(batch), OnMissing: onMissingIgnore},
		}); err != nil {
			return fmt.Errorf("failed to delete tuples: %w", err)
		}
	}
	return nil
}

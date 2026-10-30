package openfga

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MaxTuplesPerWrite is OpenFGA's default limit on the tuples in one Write.
const MaxTuplesPerWrite = 100

// onMissingIgnore makes a delete skip a tuple that is already gone, so a tuple
// another writer removed first does not fail the batch. OpenFGA v1.10.0 and
// later honour it; an older server ignores the field and fails as before.
const onMissingIgnore = "ignore"

// onDuplicateIgnore makes a write skip a tuple that already exists, so a tuple
// another writer added first does not fail the batch. OpenFGA v1.10.0 and
// later honour it, as they do onMissingIgnore.
const onDuplicateIgnore = "ignore"

// DeleteTuples deletes the tuples in writes of at most MaxTuplesPerWrite,
// skipping any that is already gone. A timed-out delete has an unknown outcome;
// retry it idempotently in smaller batches and retain that size for this cleanup.
func DeleteTuples(ctx context.Context, client openfgav1.OpenFGAServiceClient, storeID, modelID string, tuples []*openfgav1.TupleKey) error {
	batchSize := MaxTuplesPerWrite
	for start := 0; start < len(tuples); {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("failed to delete tuples: %w", err)
		}
		batch := tuples[start:min(start+batchSize, len(tuples))]
		if _, err := client.Write(ctx, &openfgav1.WriteRequest{
			StoreId:              storeID,
			AuthorizationModelId: modelID,
			Deletes:              &openfgav1.WriteRequestDeletes{TupleKeys: convertTuplesForDelete(batch), OnMissing: onMissingIgnore},
		}); err != nil {
			// OpenFGA returns its own deadline code as well as the standard gRPC code.
			code := status.Code(err)
			if ctx.Err() == nil && len(batch) > 1 && (code == codes.DeadlineExceeded || code == codes.Code(openfgav1.InternalErrorCode_deadline_exceeded)) {
				batchSize = len(batch) / 2
				continue
			}
			return fmt.Errorf("failed to delete tuples: %w", err)
		}
		start += len(batch)
	}
	return nil
}

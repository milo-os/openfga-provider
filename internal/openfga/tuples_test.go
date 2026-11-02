package openfga

import (
	"context"
	"fmt"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type deleteClient struct {
	openfgav1.OpenFGAServiceClient
	write func(context.Context, *openfgav1.WriteRequest) error
}

func (c deleteClient) Write(ctx context.Context, r *openfgav1.WriteRequest, _ ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
	return &openfgav1.WriteResponse{}, c.write(ctx, r)
}

func TestDeleteTuplesShrinksTimedOutBatches(t *testing.T) {
	for _, code := range []codes.Code{codes.DeadlineExceeded, codes.Code(openfgav1.InternalErrorCode_deadline_exceeded)} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			tuples := make([]*openfgav1.TupleKey, 205)
			remaining := map[string]bool{}
			for i := range tuples {
				object := fmt.Sprintf("project:%d", i)
				tuples[i] = &openfgav1.TupleKey{User: "user:alice", Relation: "owner", Object: object}
				remaining[object] = true
			}
			var sizes []int
			c := deleteClient{write: func(ctx context.Context, r *openfgav1.WriteRequest) error {
				require.Equal(t, "store", r.GetStoreId())
				require.Equal(t, "model", r.GetAuthorizationModelId())
				require.Equal(t, "ignore", r.GetDeletes().GetOnMissing())
				batch := r.GetDeletes().GetTupleKeys()
				sizes = append(sizes, len(batch))
				// Even a timed-out request may have committed. Retrying must tolerate this.
				for _, k := range batch {
					delete(remaining, k.GetObject())
				}
				if len(batch) > 25 {
					return status.Error(code, "deadline")
				}
				return nil
			}}
			require.NoError(t, DeleteTuples(context.Background(), c, "store", "model", tuples))
			require.Empty(t, remaining)
			require.Equal(t, []int{100, 50, 25, 25, 25, 25, 25, 25, 25, 25, 5}, sizes)
		})
	}
}
func TestDeleteTuplesStopsOnPermanentOrSingletonFailure(t *testing.T) {
	for _, code := range []codes.Code{codes.PermissionDenied, codes.Unavailable, codes.DeadlineExceeded} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			calls := 0
			c := deleteClient{write: func(context.Context, *openfgav1.WriteRequest) error { calls++; return status.Error(code, "failed") }}
			tuples := []*openfgav1.TupleKey{{Object: "project:one"}}
			if code != codes.DeadlineExceeded {
				tuples = append(tuples, &openfgav1.TupleKey{Object: "project:two"})
			}
			err := DeleteTuples(context.Background(), c, "store", "", tuples)
			require.Equal(t, code, status.Code(err))
			require.Equal(t, 1, calls)
		})
	}
}
func TestDeleteTuplesDoesNotRetryCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	c := deleteClient{write: func(context.Context, *openfgav1.WriteRequest) error {
		calls++
		cancel()
		return status.Error(codes.DeadlineExceeded, "deadline")
	}}
	require.Error(t, DeleteTuples(ctx, c, "store", "", []*openfgav1.TupleKey{{Object: "project:one"}, {Object: "project:two"}}))
	require.Equal(t, 1, calls)
}

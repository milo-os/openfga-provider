package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

const (
	typeInternalUser      = "iam.miloapis.com/InternalUser"
	typeInternalUserGroup = "iam.miloapis.com/InternalUserGroup"
	relationMember        = "member"
)

// SystemGroupMaterializer writes system group membership tuples to OpenFGA the first
// time a user UID is seen. Persisting these tuples rather than injecting them as
// per-request contextual tuples allows OpenFGA's check query cache to cover the full
// resolution path, since contextual tuples defeat caching.
//
// The materializer uses a sync.Map to track which UIDs have already been materialized
// so that the Write RPC is only called once per process lifetime per user.
type SystemGroupMaterializer struct {
	fgaClient openfgav1.OpenFGAServiceClient
	storeID   string
	// materialized tracks UIDs that have already had their system group tuples written.
	materialized sync.Map
}

// NewSystemGroupMaterializer creates a new SystemGroupMaterializer.
func NewSystemGroupMaterializer(fgaClient openfgav1.OpenFGAServiceClient, storeID string) *SystemGroupMaterializer {
	return &SystemGroupMaterializer{
		fgaClient: fgaClient,
		storeID:   storeID,
	}
}

// EnsureMaterialized writes member tuples for all system:* groups to OpenFGA if they
// have not already been written during this process lifetime. Subsequent calls for the
// same userUID are no-ops.
func (m *SystemGroupMaterializer) EnsureMaterialized(ctx context.Context, userUID string, groups []string) error {
	// Fast path: already materialized for this UID.
	if _, already := m.materialized.Load(userUID); already {
		return nil
	}

	// Collect system:* groups that need to be materialized.
	tuples := make([]*openfgav1.TupleKey, 0, len(groups))
	for _, group := range groups {
		if !strings.HasPrefix(group, "system:") {
			continue
		}
		// Replace colons with underscores to match the format expected by the
		// authorization model (e.g., system:authenticated → system_authenticated).
		escapedGroup := strings.ReplaceAll(group, ":", "_")
		tuples = append(tuples, &openfgav1.TupleKey{
			User:     typeInternalUser + ":" + userUID,
			Relation: relationMember,
			Object:   typeInternalUserGroup + ":" + escapedGroup,
		})
	}

	if len(tuples) == 0 {
		// Mark as materialized even when there are no system groups so we skip the
		// lookup on the next request.
		m.materialized.Store(userUID, struct{}{})
		return nil
	}

	slog.DebugContext(ctx, "materializing system group memberships",
		slog.String("userUID", userUID),
		slog.Int("groupCount", len(tuples)),
	)

	_, err := m.fgaClient.Write(ctx, &openfgav1.WriteRequest{
		StoreId: m.storeID,
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys: tuples,
		},
	})
	if err != nil {
		// A conflict error (ALREADY_EXISTS / code 6) means the tuples were previously
		// written by another replica or a prior run. Treat this as success rather than
		// a hard failure so we do not block authorization on transient duplicates.
		if isTupleConflictError(err) {
			slog.DebugContext(ctx, "system group tuples already exist in OpenFGA, skipping write",
				slog.String("userUID", userUID),
			)
		} else {
			return fmt.Errorf("failed to materialize system group memberships for user %s: %w", userUID, err)
		}
	}

	// Record the UID so future requests skip the Write call entirely.
	m.materialized.Store(userUID, struct{}{})
	return nil
}

// isTupleConflictError returns true when the OpenFGA Write error is caused by one or
// more tuples that already exist. OpenFGA returns gRPC code 6 (ALREADY_EXISTS) or
// code 2 (UNKNOWN) with a message containing "already exists" in these cases.
func isTupleConflictError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "AlreadyExists")
}

package openfga

import (
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
)

func TestTupleFingerprintIsOrderIndependent(t *testing.T) {
	one := &openfgav1.TupleKey{User: "user:one", Relation: "viewer", Object: "document:one"}
	two := &openfgav1.TupleKey{User: "user:two", Relation: "editor", Object: "document:two"}

	require.Equal(t,
		fingerprintTuples("store", []*openfgav1.TupleKey{one, two}),
		fingerprintTuples("store", []*openfgav1.TupleKey{two, one}),
	)
}

func TestTupleFingerprintIncludesStore(t *testing.T) {
	tuple := &openfgav1.TupleKey{User: "user:one", Relation: "viewer", Object: "document:one"}

	require.NotEqual(t,
		fingerprintTuples("old-store", []*openfgav1.TupleKey{tuple}),
		fingerprintTuples("new-store", []*openfgav1.TupleKey{tuple}),
	)
}

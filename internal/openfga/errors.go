package openfga

import (
	"strings"

	"google.golang.org/grpc/status"
)

// IsAlreadyExistsErr reports whether the gRPC error indicates that the tuple
// already exists in OpenFGA (code 2017).
func IsAlreadyExistsErr(err error) bool {
	if st, ok := status.FromError(err); ok {
		// OpenFGA uses gRPC application error code 2017 for "already exists".
		return st.Code() == 2017
	}
	// Fallback: check the error message for robustness across SDK versions.
	return strings.Contains(err.Error(), "already exists")
}

// IsTupleNotFoundErr reports whether the gRPC error indicates that the tuple
// does not exist in OpenFGA. OpenFGA has been observed returning code 2017
// ("cannot delete a tuple which does not exist") and code 2018; both are
// treated as "not found" so deletion is idempotent.
func IsTupleNotFoundErr(err error) bool {
	if st, ok := status.FromError(err); ok {
		return st.Code() == 2017 || st.Code() == 2018
	}
	return strings.Contains(err.Error(), "cannot delete a tuple which does not exist") ||
		strings.Contains(err.Error(), "not found")
}

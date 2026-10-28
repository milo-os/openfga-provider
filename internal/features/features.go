// Package features defines the feature gates used by auth-provider-openfga.
// Register gates by importing this package (blank import) in each binary
// entry-point before the flag parse step.
package features

import (
	"k8s.io/apimachinery/pkg/util/runtime"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/featuregate"
)

const (
	// DirectPermissionTuples enables the direct permission tuple model where
	// (user, hashed_permission, resource) tuples are written directly instead
	// of through RoleBinding/InternalRole indirection.
	//
	// When enabled: the policy reconciler writes direct (user, hash(perm),
	// resource) tuples; the webhook sends simplified Check requests without
	// contextual tuples.
	//
	// Default: false (Beta). Opt in to enable the new model.
	DirectPermissionTuples featuregate.Feature = "DirectPermissionTuples"

	// LegacyRoleBindingModel preserves the old RoleBinding/InternalRole
	// authorization model types and tuple format. This is the current
	// production model.
	//
	// During migration, enable both DirectPermissionTuples and
	// LegacyRoleBindingModel to run in dual-write mode: both the new direct
	// tuples and the old linkage tuples are written, and the authorization
	// model includes both type families. Once migration is complete, disable
	// this gate to stop writing old tuples and remove the legacy types from
	// the model.
	//
	// Default: true (Beta). Disable after migration to the direct permission
	// tuple model is complete.
	LegacyRoleBindingModel featuregate.Feature = "LegacyRoleBindingModel"
)

func init() {
	runtime.Must(utilfeature.DefaultMutableFeatureGate.Add(map[featuregate.Feature]featuregate.FeatureSpec{
		DirectPermissionTuples: {Default: false, PreRelease: featuregate.Beta},
		LegacyRoleBindingModel: {Default: true, PreRelease: featuregate.Beta},
	}))
}

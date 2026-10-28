package openfga

// IAM Type constants for OpenFGA authorization model
const (
	// IAM Types
	TypeInternalUser      = "iam.miloapis.com/InternalUser"
	TypeInternalUserGroup = "iam.miloapis.com/InternalUserGroup"

	// Legacy types retained for backward-compatibility with existing callers
	// that have not yet been updated. These types are no longer emitted in the
	// authorization model under the direct-permission prototype.
	TypeInternalRole = "iam.miloapis.com/InternalRole"
	TypeRole         = "iam.miloapis.com/Role"
	TypeRoleBinding  = "iam.miloapis.com/RoleBinding"
	TypeRoot         = "iam.miloapis.com/Root"

	// Legacy relations retained for backward-compatibility.
	RelationRoleBinding  = "iam.miloapis.com/RoleBinding"
	RelationRootBinding  = "iam.miloapis.com/RootBinding"
	RelationInternalRole = "iam.miloapis.com/InternalRole"
	RelationInternalUser = "iam.miloapis.com/InternalUser"

	// Standard relations
	RelationMember   = "member"
	RelationAssignee = "assignee"
	RelationParent   = "parent"

	// OpenFGA metadata
	SourceFile = "dynamically_managed_iam_datumapis_com.fga"
	Module     = "iam.miloapis.com"
)

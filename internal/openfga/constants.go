package openfga

// IAM Type constants for OpenFGA authorization model
const (
	TypeInternalUser      = "iam.miloapis.com/InternalUser"
	TypeInternalUserGroup = "iam.miloapis.com/InternalUserGroup"
	TypeInternalRole      = "iam.miloapis.com/InternalRole"
	TypeRole              = "iam.miloapis.com/Role"
	TypeRoleBinding       = "iam.miloapis.com/RoleBinding"
	TypeRoot              = "iam.miloapis.com/Root"

	// Standard relations
	RelationMember   = "member"
	RelationAssignee = "assignee"
	RelationParent   = "parent"

	SubjectKindUser           = "User"
	SubjectKindGroup          = "Group"
	SubjectKindServiceAccount = "ServiceAccount"

	// OpenFGA metadata
	SourceFile = "dynamically_managed_iam_datumapis_com.fga"
	Module     = "iam.miloapis.com"
)

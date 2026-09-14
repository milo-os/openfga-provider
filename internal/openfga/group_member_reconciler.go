package openfga

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type UserGroupReconciler struct {
	StoreID   string
	Client    openfgav1.OpenFGAServiceClient
	K8sClient client.Client
}

type GroupMembershipRequest struct {
	MemberUID types.UID
	GroupUID  types.UID
}

func (r *UserGroupReconciler) AddMemberToGroup(ctx context.Context, joinToGroupRequest GroupMembershipRequest) error {
	openFGAGroupObject, openFGAMemberUser := r.getOpenFGAGroupAndMember(joinToGroupRequest)

	tupleKeys := []*openfgav1.TupleKey{
		{
			User:     openFGAMemberUser,
			Relation: "member",
			Object:   openFGAGroupObject,
		},
	}

	checkResp, err := r.checkIfTupleKeyExists(ctx, tupleKeys[0])
	if err != nil {
		return fmt.Errorf("failed to check if GroupMember tuple key exists: %w", err)
	}

	// If the tuple key does not exist, write it to the OpenFGA store
	if !checkResp.Allowed {
		writeRequest := &openfgav1.WriteRequest{
			StoreId: r.StoreID,
			Writes: &openfgav1.WriteRequestWrites{
				TupleKeys: tupleKeys,
			},
		}
		_, err = r.Client.Write(ctx, writeRequest)
		if err != nil {
			// Check above can be racy; already-exists means the tuple is there, so treat as success.
			if IsAlreadyExistsErr(err) {
				return nil
			}
			return fmt.Errorf("failed to write group membership tuple: %w", err)
		}
	}

	return nil
}

func (r *UserGroupReconciler) RemoveMemberFromGroup(ctx context.Context, groupMembershipRequest GroupMembershipRequest) error {
	openFGAGroupObject, openFGAUserObject := r.getOpenFGAGroupAndMember(groupMembershipRequest)

	tupleKeys := []*openfgav1.TupleKey{
		{
			User:     openFGAUserObject,
			Relation: "member",
			Object:   openFGAGroupObject,
		},
	}

	checkResp, err := r.checkIfTupleKeyExists(ctx, tupleKeys[0])
	if err != nil {
		return fmt.Errorf("failed to check if GroupMember tuple key exists: %w", err)
	}

	// If the tuple key exists, delete it from the OpenFGA store
	if checkResp.Allowed {
		deleteRequest := &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(tupleKeys),
		}

		_, err = r.Client.Write(ctx, &openfgav1.WriteRequest{
			StoreId: r.StoreID,
			Deletes: deleteRequest,
		})
		if err != nil {
			// Check above can be racy; not-found means the tuple is gone, so treat as success.
			if IsTupleNotFoundErr(err) {
				return nil
			}
			return fmt.Errorf("failed to delete group membership: %w", err)
		}
	}

	return nil
}

// GetOpenFGAGroupAndMember returns the OpenFGA group object and member user strings for a given JoinToGroupRequest
func (r *UserGroupReconciler) getOpenFGAGroupAndMember(joinToGroupRequest GroupMembershipRequest) (openFGAGroupObject string, openFGAUserObject string) {
	openFGAGroupObject = fmt.Sprintf("%s:%s", TypeInternalUserGroup, joinToGroupRequest.GroupUID)
	openFGAUserObject = fmt.Sprintf("%s:%s", TypeInternalUser, joinToGroupRequest.MemberUID)
	return
}

// checkIfTupleKeyExists checks if the tuple key exists in the OpenFGA store
func (r *UserGroupReconciler) checkIfTupleKeyExists(ctx context.Context, tupleKey *openfgav1.TupleKey) (*openfgav1.CheckResponse, error) {
	log := logf.FromContext(ctx)

	checkRequest := &openfgav1.CheckRequest{
		StoreId: r.StoreID,
		TupleKey: &openfgav1.CheckRequestTupleKey{
			User:     tupleKey.User,
			Relation: tupleKey.Relation,
			Object:   tupleKey.Object,
		},
	}

	checkResp, err := r.Client.Check(ctx, checkRequest)
	if err != nil {
		log.Error(err, "failed to check group membership tuple in OpenFGA")
		return nil, fmt.Errorf("failed to check if GroupMember tuple key exists: %w", err)
	}

	return checkResp, nil
}

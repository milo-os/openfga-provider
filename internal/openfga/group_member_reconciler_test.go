package openfga

import (
	"context"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// groupMemberMockClient is a mock implementation of openfgav1.OpenFGAServiceClient
// for testing UserGroupReconciler's Check/Write interactions.
type groupMemberMockClient struct {
	openfgav1.OpenFGAServiceClient
	CheckFunc func(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error)
	WriteFunc func(ctx context.Context, in *openfgav1.WriteRequest, opts ...grpc.CallOption) (*openfgav1.WriteResponse, error)
}

func (m *groupMemberMockClient) Check(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
	return m.CheckFunc(ctx, in, opts...)
}

func (m *groupMemberMockClient) Write(ctx context.Context, in *openfgav1.WriteRequest, opts ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
	return m.WriteFunc(ctx, in, opts...)
}

func TestUserGroupReconciler_AddMemberToGroup(t *testing.T) {
	logf.SetLogger(zap.New())

	req := GroupMembershipRequest{GroupUID: types.UID("group-uid"), MemberUID: types.UID("member-uid")}

	testCases := []struct {
		name          string
		checkResp     *openfgav1.CheckResponse
		checkErr      error
		writeErr      error
		wantErr       bool
		wantWriteCall bool
	}{
		{
			name:          "tuple already allowed, no write needed",
			checkResp:     &openfgav1.CheckResponse{Allowed: true},
			wantWriteCall: false,
		},
		{
			name:          "tuple missing, write succeeds",
			checkResp:     &openfgav1.CheckResponse{Allowed: false},
			wantWriteCall: true,
		},
		{
			name:          "tuple missing, write races and already exists is treated as success",
			checkResp:     &openfgav1.CheckResponse{Allowed: false},
			writeErr:      status.Error(codes.Code(2017), "cannot write a tuple which already exists"),
			wantWriteCall: true,
			wantErr:       false,
		},
		{
			name:          "tuple missing, write fails with unrelated error",
			checkResp:     &openfgav1.CheckResponse{Allowed: false},
			writeErr:      status.Error(codes.Internal, "boom"),
			wantWriteCall: true,
			wantErr:       true,
		},
		{
			name:     "check fails",
			checkErr: status.Error(codes.Internal, "boom"),
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writeCalled := false
			client := &groupMemberMockClient{
				CheckFunc: func(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
					return tc.checkResp, tc.checkErr
				},
				WriteFunc: func(ctx context.Context, in *openfgav1.WriteRequest, opts ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
					writeCalled = true
					if tc.writeErr != nil {
						return nil, tc.writeErr
					}
					return &openfgav1.WriteResponse{}, nil
				},
			}

			r := &UserGroupReconciler{StoreID: "store-1", Client: client}
			err := r.AddMemberToGroup(context.Background(), req)

			if (err != nil) != tc.wantErr {
				t.Fatalf("AddMemberToGroup() error = %v, wantErr %v", err, tc.wantErr)
			}
			if writeCalled != tc.wantWriteCall {
				t.Fatalf("Write called = %v, want %v", writeCalled, tc.wantWriteCall)
			}
		})
	}
}

func TestUserGroupReconciler_RemoveMemberFromGroup(t *testing.T) {
	logf.SetLogger(zap.New())

	req := GroupMembershipRequest{GroupUID: types.UID("group-uid"), MemberUID: types.UID("member-uid")}

	testCases := []struct {
		name          string
		checkResp     *openfgav1.CheckResponse
		checkErr      error
		writeErr      error
		wantErr       bool
		wantWriteCall bool
	}{
		{
			name:          "tuple already absent, no delete needed",
			checkResp:     &openfgav1.CheckResponse{Allowed: false},
			wantWriteCall: false,
		},
		{
			name:          "tuple present, delete succeeds",
			checkResp:     &openfgav1.CheckResponse{Allowed: true},
			wantWriteCall: true,
		},
		{
			name:          "tuple present, delete races and not-found is treated as success",
			checkResp:     &openfgav1.CheckResponse{Allowed: true},
			writeErr:      status.Error(codes.Code(2017), "the tuple to be deleted did not exist"),
			wantWriteCall: true,
			wantErr:       false,
		},
		{
			name:          "tuple present, delete fails with unrelated error",
			checkResp:     &openfgav1.CheckResponse{Allowed: true},
			writeErr:      status.Error(codes.Internal, "boom"),
			wantWriteCall: true,
			wantErr:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writeCalled := false
			client := &groupMemberMockClient{
				CheckFunc: func(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
					return tc.checkResp, tc.checkErr
				},
				WriteFunc: func(ctx context.Context, in *openfgav1.WriteRequest, opts ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
					writeCalled = true
					if tc.writeErr != nil {
						return nil, tc.writeErr
					}
					return &openfgav1.WriteResponse{}, nil
				},
			}

			r := &UserGroupReconciler{StoreID: "store-1", Client: client}
			err := r.RemoveMemberFromGroup(context.Background(), req)

			if (err != nil) != tc.wantErr {
				t.Fatalf("RemoveMemberFromGroup() error = %v, wantErr %v", err, tc.wantErr)
			}
			if writeCalled != tc.wantWriteCall {
				t.Fatalf("Write called = %v, want %v", writeCalled, tc.wantWriteCall)
			}
		})
	}
}

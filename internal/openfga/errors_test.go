package openfga

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsAlreadyExistsErr(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "grpc status code 2017",
			err:  status.Error(codes.Code(2017), "cannot write a tuple which already exists"),
			want: true,
		},
		{
			name: "grpc status other code",
			err:  status.Error(codes.NotFound, "not found"),
			want: false,
		},
		{
			name: "non-status error with message fallback",
			err:  errors.New("tuple already exists"),
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("boom"),
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAlreadyExistsErr(tc.err); got != tc.want {
				t.Errorf("IsAlreadyExistsErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsTupleNotFoundErr(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "grpc status code 2017",
			err:  status.Error(codes.Code(2017), "the tuple to be deleted did not exist"),
			want: true,
		},
		{
			name: "grpc status code 2018",
			err:  status.Error(codes.Code(2018), "cannot delete a tuple which does not exist"),
			want: true,
		},
		{
			name: "grpc status other code",
			err:  status.Error(codes.Internal, "boom"),
			want: false,
		},
		{
			name: "non-status error with message fallback",
			err:  errors.New("cannot delete a tuple which does not exist"),
			want: true,
		},
		{
			name: "unrelated error",
			err:  errors.New("boom"),
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTupleNotFoundErr(tc.err); got != tc.want {
				t.Errorf("IsTupleNotFoundErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

package controller

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// objectTuples finds and deletes the tuples that name one object: the tuples on
// the object itself, and those in which it is the user. The authorization model
// admits a resource as a user only as the parent of its child types, which the
// ProtectedResources declare.
type objectTuples struct {
	reader  client.Reader
	fga     openfgav1.OpenFGAServiceClient
	storeID string
}

// naming returns every tuple that names the object of objectType called name.
func (o objectTuples) naming(ctx context.Context, objectType, name string) ([]*openfgav1.TupleKey, error) {
	object := objectType + ":" + name
	found, err := fetchOpenFGATuples(ctx, o.fga, o.storeID, &openfgav1.ReadRequestTupleKey{Object: object})
	if err != nil {
		return nil, err
	}
	children, err := o.childTypes(ctx, objectType)
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		asUser, err := fetchOpenFGATuples(ctx, o.fga, o.storeID, &openfgav1.ReadRequestTupleKey{Object: child + ":", User: object})
		if err != nil {
			return nil, err
		}
		found = append(found, asUser...)
	}
	return found, nil
}

// childTypes returns, once each, the resource types that declare parentType as a
// parent; two ProtectedResources may register one type. A type is never its own
// child, as in the model, so the tuples naming an object as the object and as
// the user never overlap, and no tuple is read or deleted twice.
func (o objectTuples) childTypes(ctx context.Context, parentType string) ([]string, error) {
	var resources iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := o.reader.List(ctx, &resources); err != nil {
		return nil, fmt.Errorf("failed to list ProtectedResources: %w", err)
	}
	listed := map[string]bool{}
	var children []string
	for _, pr := range resources.Items {
		child := pr.Spec.ServiceRef.Name + "/" + pr.Spec.Kind
		if child != parentType && !listed[child] && declaresParent(pr, parentType) {
			listed[child] = true
			children = append(children, child)
		}
	}
	return children, nil
}

func declaresParent(pr iamdatumapiscomv1alpha1.ProtectedResource, parentType string) bool {
	for _, parent := range pr.Spec.ParentResources {
		if parent.APIGroup+"/"+parent.Kind == parentType {
			return true
		}
	}
	return false
}

// clear deletes every tuple that names the object, then reads again, and fails
// while any tuple still names it. It returns how many tuples it deleted.
func (o objectTuples) clear(ctx context.Context, objectType, name string) (int, error) {
	found, err := o.naming(ctx, objectType, name)
	if err != nil {
		return 0, err
	}
	if err := openfga.DeleteTuples(ctx, o.fga, o.storeID, "", found); err != nil {
		return 0, err
	}
	left, err := o.naming(ctx, objectType, name)
	if err != nil {
		return 0, err
	}
	if len(left) > 0 {
		return 0, fmt.Errorf("%d tuples still name %s:%s", len(left), objectType, name)
	}
	return len(found), nil
}

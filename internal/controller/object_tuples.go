package controller

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
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

// naming returns every tuple that names the object of kind gk called name.
func (o objectTuples) naming(ctx context.Context, gk schema.GroupKind, name string) ([]*openfgav1.TupleKey, error) {
	object := openfga.ObjectName(gk.Group, gk.Kind, name)
	found, err := fetchOpenFGATuples(ctx, o.fga, o.storeID, &openfgav1.ReadRequestTupleKey{Object: object})
	if err != nil {
		return nil, err
	}
	children, err := o.childTypes(ctx, gk.Group+"/"+gk.Kind)
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

// clear deletes every tuple that names the object and returns how many it
// deleted. It runs without the object's lock, so a slow clear holds up no
// other writer; remaining, under the lock, finds any tuple written meanwhile.
func (o objectTuples) clear(ctx context.Context, gk schema.GroupKind, name string) (int, error) {
	found, err := o.naming(ctx, gk, name)
	if err != nil {
		return 0, err
	}
	return len(found), openfga.DeleteTuples(ctx, o.fga, o.storeID, "", found)
}

// remaining fails while any tuple still names the object.
func (o objectTuples) remaining(ctx context.Context, gk schema.GroupKind, name string) error {
	left, err := o.naming(ctx, gk, name)
	if err != nil {
		return err
	}
	if len(left) > 0 {
		return fmt.Errorf("%d tuples still name %s", len(left), openfga.ObjectName(gk.Group, gk.Kind, name))
	}
	return nil
}

// finalizeWhenClear clears the tuples that name obj without obj's lock, then,
// under the lock, runs the finalizers, whose read must find none left, and
// updates obj when they release it. A tuple a binding wrote during the clear
// fails that read, and the reconcile's retry clears again. The lock covers one
// read and the release, never the deletes.
func finalizeWhenClear(ctx context.Context, locks *ObjectLocks, logic *ResourceOwnerHierarchyFinalizerLogic, fins finalizer.Finalizers, obj client.Object) error {
	object, err := logic.objectName(obj)
	if err != nil {
		return err
	}
	if err := logic.Clear(ctx, obj); err != nil {
		return err
	}
	defer locks.Lock(object)()
	res, err := fins.Finalize(ctx, obj)
	if err != nil || !res.Updated {
		return err
	}
	return logic.Update(ctx, obj)
}

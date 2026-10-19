package controller

import (
	"context"
	"errors"
	"fmt"

	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/keymutex"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// The kinds our finalizer holds.
const (
	projectKind      = "Project"
	organizationKind = "Organization"
)

// miloFinalizers are Milo's own finalizers on the objects ours holds. Ours
// clears an object only after Milo's has left it: a Project once Milo has
// drained its resources, an Organization once its namespace carries the owner
// reference. Neither waits for ours, so waiting for them cannot deadlock.
var miloFinalizers = []string{
	"resourcemanager.miloapis.com/project-controller",
	"resourcemanager.miloapis.com/organization-namespace",
}

// ObjectLocks serialises, per OpenFGA object, every "check the object's hold,
// then write a tuple naming it" with the object's finalizer's "read again,
// release". Whichever runs first, no tuple outlives the object: a write that
// runs first is found by the read, and a check that runs second sees the
// deletion. One leader runs every controller, so one pool, shared by the
// reconcilers given it, is enough. Objects that hash to one lock share it, so
// no goroutine holds two keys.
type ObjectLocks struct {
	keys keymutex.KeyMutex
}

// NewObjectLocks returns a pool of n locks, one per CPU when n <= 0.
func NewObjectLocks(n int) *ObjectLocks {
	return &ObjectLocks{keys: keymutex.NewHashed(n)}
}

// Lock locks the OpenFGA object until the returned function runs.
func (l *ObjectLocks) Lock(object string) func() {
	l.keys.LockKey(object)
	return func() { _ = l.keys.UnlockKey(object) }
}

// errNoLocks is a reconciler's setup error when it is given no lock pool.
var errNoLocks = errors.New("the reconciler needs the object locks it shares with the other reconcilers")

// hold says how our finalizer holds an object that tuples name.
type hold int

const (
	// holdHeld: the object exists under the named UID, is not being deleted,
	// and carries our finalizer.
	holdHeld hold = iota
	// holdNotYet: as held, but our finalizer is not on it yet.
	holdNotYet
	// holdDeleting: its deletion has started.
	holdDeleting
	// holdReplaced: another object now holds the name.
	holdReplaced
	// holdMissing: not found.
	holdMissing
)

// holdOf says how our finalizer holds obj, against the UID a binding or an
// owner reference names.
func holdOf(obj client.Object, uid types.UID) hold {
	switch {
	case obj.GetUID() != uid:
		return holdReplaced
	case !obj.GetDeletionTimestamp().IsZero():
		return holdDeleting
	case controllerutil.ContainsFinalizer(obj, resourceOwnerHierarchyFinalizer):
		return holdHeld
	default:
		return holdNotYet
	}
}

// drained says whether Milo's own finalizer has left obj, so ours may clear it.
func drained(obj client.Object) bool {
	for _, f := range miloFinalizers {
		if controllerutil.ContainsFinalizer(obj, f) {
			return false
		}
	}
	return true
}

// holdTarget says how our finalizer holds obj, read live, and adds the
// finalizer when a live obj lacks it, so a writer never waits on another
// controller's queue for it.
func holdTarget(ctx context.Context, c client.Client, obj *unstructured.Unstructured, uid types.UID) (hold, error) {
	h := holdOf(obj, uid)
	if h != holdNotYet {
		return h, nil
	}
	if err := holdWithFinalizer(ctx, c, obj); err != nil {
		return h, err
	}
	return holdOf(obj, uid), nil
}

// isHeldKind says whether our finalizer holds objects of this kind.
func isHeldKind(group, kind string) bool {
	return group == resourcemanagerv1alpha1.GroupVersion.Group && (kind == projectKind || kind == organizationKind)
}

// whyNotHeld says, in plain words, why the object cannot take new tuples, or
// "" when it can.
func (h hold) whyNotHeld(kind, name string) string {
	switch h {
	case holdHeld:
		return ""
	case holdNotYet:
		return fmt.Sprintf("the %s %s is not ready for new permissions yet", kind, name)
	case holdDeleting:
		return fmt.Sprintf("the %s %s is being deleted", kind, name)
	case holdReplaced:
		return fmt.Sprintf("the %s %s is no longer the object this binding names", kind, name)
	default:
		return fmt.Sprintf("the %s %s does not exist", kind, name)
	}
}

// holdWithFinalizer adds our finalizer to obj, read live, with an Update that
// carries the read's resourceVersion: a concurrent change fails it and the
// reconcile retries, and the API server refuses a new finalizer on an object
// being deleted. On success obj is the stored object.
func holdWithFinalizer(ctx context.Context, c client.Client, obj client.Object) error {
	controllerutil.AddFinalizer(obj, resourceOwnerHierarchyFinalizer)
	if err := c.Update(ctx, obj); err != nil {
		return fmt.Errorf("failed to add our finalizer to %s %s: %w", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName(), err)
	}
	return nil
}

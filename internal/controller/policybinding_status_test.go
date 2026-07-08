package controller

import (
	"context"
	"sync/atomic"
	"testing"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func policyBinding(namespace, name string) *iamv1alpha1.PolicyBinding {
	return &iamv1alpha1.PolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
	}
}

func readyPolicyBinding(namespace, name string) *iamv1alpha1.PolicyBinding {
	pb := policyBinding(namespace, name)
	pb.Status.Conditions = []metav1.Condition{{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "ReconciliationSuccessful",
		Message:            "PolicyBinding reconciled successfully.",
		LastTransitionTime: metav1.Now(),
	}}
	return pb
}

// The status write is a merge patch on the status subresource, so it persists
// the computed conditions and observedGeneration in a single call.
func TestUpdatePolicyBindingStatus_PatchesStatus(t *testing.T) {
	s := degradationScheme(t)
	stored := policyBinding("org-1", "binding-1")

	var patches int32
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(stored).
		WithStatusSubresource(&iamv1alpha1.PolicyBinding{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(
				ctx context.Context,
				cl client.Client,
				subResourceName string,
				obj client.Object,
				patch client.Patch,
				opts ...client.SubResourcePatchOption,
			) error {
				atomic.AddInt32(&patches, 1)
				return cl.Status().Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	r := &PolicyBindingReconciler{Client: c, Scheme: s}

	current := policyBinding("org-1", "binding-1")
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(stored), current); err != nil {
		t.Fatalf("get stored binding: %v", err)
	}
	oldStatus := current.Status.DeepCopy()
	current.Status = readyPolicyBinding("org-1", "binding-1").Status

	if err := r.updatePolicyBindingStatus(context.Background(), current, oldStatus, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := atomic.LoadInt32(&patches); got != 1 {
		t.Fatalf("expected exactly 1 status patch, got %d", got)
	}

	persisted := &iamv1alpha1.PolicyBinding{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(stored), persisted); err != nil {
		t.Fatalf("get persisted binding: %v", err)
	}
	if len(persisted.Status.Conditions) != 1 || persisted.Status.Conditions[0].Type != "Ready" {
		t.Fatalf("expected Ready condition persisted, got %+v", persisted.Status.Conditions)
	}
	if persisted.Status.ObservedGeneration != 1 {
		t.Fatalf("expected observedGeneration=1, got %d", persisted.Status.ObservedGeneration)
	}
}

// A merge patch carries no resourceVersion, so a status write computed from a
// stale (lagging-cache) read must still succeed rather than conflict.
func TestUpdatePolicyBindingStatus_ConflictFreeOnStaleObject(t *testing.T) {
	s := degradationScheme(t)
	stored := policyBinding("org-1", "binding-1")

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(stored).
		WithStatusSubresource(&iamv1alpha1.PolicyBinding{}).
		Build()

	r := &PolicyBindingReconciler{Client: c, Scheme: s}

	current := policyBinding("org-1", "binding-1")
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(stored), current); err != nil {
		t.Fatalf("get stored binding: %v", err)
	}

	// Simulate an informer read that is behind the API server: pin an old
	// resourceVersion onto the in-memory object before writing status.
	current.ResourceVersion = "1"
	oldStatus := current.Status.DeepCopy()
	current.Status = readyPolicyBinding("org-1", "binding-1").Status

	if err := r.updatePolicyBindingStatus(context.Background(), current, oldStatus, 1); err != nil {
		t.Fatalf("stale-read status write must not conflict, got: %v", err)
	}
}

// When the status has not changed the reconciler must not issue a write at all,
// avoiding needless API traffic and resourceVersion churn.
func TestUpdatePolicyBindingStatus_SkipsWhenUnchanged(t *testing.T) {
	s := degradationScheme(t)
	stored := readyPolicyBinding("org-1", "binding-1")
	stored.Status.ObservedGeneration = 1

	var patches int32
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(stored).
		WithStatusSubresource(&iamv1alpha1.PolicyBinding{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(
				ctx context.Context,
				cl client.Client,
				subResourceName string,
				obj client.Object,
				patch client.Patch,
				opts ...client.SubResourcePatchOption,
			) error {
				atomic.AddInt32(&patches, 1)
				return cl.Status().Patch(ctx, obj, patch, opts...)
			},
		}).
		Build()

	r := &PolicyBindingReconciler{Client: c, Scheme: s}

	current := readyPolicyBinding("org-1", "binding-1")
	current.Status.ObservedGeneration = 1
	oldStatus := current.Status.DeepCopy()

	if err := r.updatePolicyBindingStatus(context.Background(), current, oldStatus, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := atomic.LoadInt32(&patches); got != 0 {
		t.Fatalf("expected no status writes when unchanged, got %d", got)
	}
}

// The primary-watch predicate must ignore status-only updates (the source of
// the self-inflicted reconcile storm) while still reconciling on spec,
// finalizer, and deletion changes.
func TestPolicyBindingReconcilePredicate(t *testing.T) {
	p := policyBindingReconcilePredicate()

	base := func() *iamv1alpha1.PolicyBinding {
		pb := policyBinding("org-1", "binding-1")
		pb.Generation = 1
		pb.Finalizers = []string{policyBindingFinalizerKey}
		return pb
	}

	statusOnly := base()
	statusOnly.Status.Conditions = []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}
	statusOnly.ResourceVersion = "2"
	if p.Update(event.UpdateEvent{ObjectOld: base(), ObjectNew: statusOnly}) {
		t.Fatalf("status-only update should be ignored")
	}

	specChange := base()
	specChange.Generation = 2
	if !p.Update(event.UpdateEvent{ObjectOld: base(), ObjectNew: specChange}) {
		t.Fatalf("generation change should trigger reconcile")
	}

	finalizerChange := base()
	finalizerChange.Finalizers = nil
	if !p.Update(event.UpdateEvent{ObjectOld: base(), ObjectNew: finalizerChange}) {
		t.Fatalf("finalizer change should trigger reconcile")
	}

	deleting := base()
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	if !p.Update(event.UpdateEvent{ObjectOld: base(), ObjectNew: deleting}) {
		t.Fatalf("deletion should trigger reconcile")
	}

	if !p.Update(event.UpdateEvent{ObjectOld: nil, ObjectNew: nil}) {
		t.Fatalf("nil objects should default to reconcile")
	}
}

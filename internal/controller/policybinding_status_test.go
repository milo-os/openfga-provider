package controller

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

// A single conflict on the status subresource must not drop the update: the
// reconciler re-reads the latest object and re-applies the computed status, so
// the binding still ends up with its Ready condition persisted.
func TestUpdatePolicyBindingStatus_RetriesOnConflict(t *testing.T) {
	s := degradationScheme(t)
	stored := policyBinding("org-1", "binding-1")

	var updates int32
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(stored).
		WithStatusSubresource(&iamv1alpha1.PolicyBinding{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(
				ctx context.Context,
				cl client.Client,
				subResourceName string,
				obj client.Object,
				opts ...client.SubResourceUpdateOption,
			) error {
				if atomic.AddInt32(&updates, 1) == 1 {
					return apierrors.NewConflict(
						schema.GroupResource{Group: iamv1alpha1.SchemeGroupVersion.Group, Resource: "policybindings"},
						obj.GetName(),
						fmt.Errorf("the object has been modified"),
					)
				}
				return cl.Status().Update(ctx, obj, opts...)
			},
		}).
		Build()

	r := &PolicyBindingReconciler{Client: c, Scheme: s}

	desired := readyPolicyBinding("org-1", "binding-1")
	oldStatus := &iamv1alpha1.PolicyBindingStatus{}

	if err := r.updatePolicyBindingStatus(context.Background(), desired, oldStatus, 1); err != nil {
		t.Fatalf("expected conflict to be retried, got error: %v", err)
	}

	if got := atomic.LoadInt32(&updates); got < 2 {
		t.Fatalf("expected at least 2 status update attempts (1 conflict + 1 success), got %d", got)
	}

	persisted := &iamv1alpha1.PolicyBinding{}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(stored), persisted); err != nil {
		t.Fatalf("get persisted binding: %v", err)
	}
	if len(persisted.Status.Conditions) != 1 || persisted.Status.Conditions[0].Type != "Ready" {
		t.Fatalf("expected Ready condition persisted after retry, got %+v", persisted.Status.Conditions)
	}
	if persisted.Status.ObservedGeneration != 1 {
		t.Fatalf("expected observedGeneration=1, got %d", persisted.Status.ObservedGeneration)
	}
}

// When the status has not changed the reconciler must not issue a write at all,
// avoiding needless API traffic and resourceVersion churn.
func TestUpdatePolicyBindingStatus_SkipsWhenUnchanged(t *testing.T) {
	s := degradationScheme(t)
	stored := readyPolicyBinding("org-1", "binding-1")
	stored.Status.ObservedGeneration = 1

	var updates int32
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(stored).
		WithStatusSubresource(&iamv1alpha1.PolicyBinding{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(
				ctx context.Context,
				cl client.Client,
				subResourceName string,
				obj client.Object,
				opts ...client.SubResourceUpdateOption,
			) error {
				atomic.AddInt32(&updates, 1)
				return cl.Status().Update(ctx, obj, opts...)
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

	if got := atomic.LoadInt32(&updates); got != 0 {
		t.Fatalf("expected no status writes when unchanged, got %d", got)
	}
}

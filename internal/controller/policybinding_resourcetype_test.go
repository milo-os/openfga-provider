package controller

import (
	"context"
	"testing"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func protectedResourceScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatalf("add client-go scheme: %v", err)
	}
	if err := iamdatumapiscomv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add iam scheme: %v", err)
	}
	return s
}

func protectedResource(serviceRefName, kind string) *iamdatumapiscomv1alpha1.ProtectedResource {
	return &iamdatumapiscomv1alpha1.ProtectedResource{
		ObjectMeta: metav1.ObjectMeta{Name: serviceRefName + "-" + kind},
		Spec: iamdatumapiscomv1alpha1.ProtectedResourceSpec{
			ServiceRef: iamdatumapiscomv1alpha1.ServiceReference{Name: serviceRefName},
			Kind:       kind,
			Plural:     kind + "s",
		},
	}
}

func newPolicyBindingReconciler(t *testing.T, objs ...client.Object) *PolicyBindingReconciler {
	t.Helper()
	s := protectedResourceScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithIndex(&iamdatumapiscomv1alpha1.ProtectedResource{}, protectedResourceServiceKindIndexField, func(rawObj client.Object) []string {
			pr, ok := rawObj.(*iamdatumapiscomv1alpha1.ProtectedResource)
			if !ok {
				return nil
			}
			if pr.Spec.ServiceRef.Name == "" || pr.Spec.Kind == "" {
				return nil
			}
			return []string{pr.Spec.ServiceRef.Name + "/" + pr.Spec.Kind}
		}).
		WithObjects(objs...).
		Build()
	return &PolicyBindingReconciler{Client: c}
}

// validateResourceType looks up ProtectedResources via the indexed
// service/kind lookup instead of listing and scanning every ProtectedResource
// in the cluster. Verify the indexed lookup actually finds a registered type,
// correctly reports an unregistered one, and rejects an empty apiGroup/kind
// without touching the index at all.
func TestValidateResourceType(t *testing.T) {
	registered := protectedResource("compute.miloapis.com", "Workload")
	other := protectedResource("networking.miloapis.com", "Network")

	r := newPolicyBindingReconciler(t, registered, other)

	t.Run("registered type is found via the index", func(t *testing.T) {
		isValid, reason, err := r.validateResourceType(context.Background(), "compute.miloapis.com", "Workload")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isValid {
			t.Fatalf("expected registered type to validate, got reason: %s", reason)
		}
	})

	t.Run("unregistered type is rejected", func(t *testing.T) {
		isValid, reason, err := r.validateResourceType(context.Background(), "compute.miloapis.com", "NoSuchKind")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isValid {
			t.Fatalf("expected unregistered type to be invalid")
		}
		if reason == "" {
			t.Fatalf("expected a non-empty reason for an invalid type")
		}
	})

	t.Run("empty apiGroup or kind is rejected without listing", func(t *testing.T) {
		isValid, _, err := r.validateResourceType(context.Background(), "", "Workload")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isValid {
			t.Fatalf("expected empty apiGroup to be invalid")
		}
	})
}

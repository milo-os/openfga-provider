package controller

import (
	"context"
	"testing"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

func userSelfManageBinding(userName, userUID string) *iamdatumapiscomv1alpha1.PolicyBinding {
	return &iamdatumapiscomv1alpha1.PolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "user-self-manage-" + userName, Namespace: "milo-system"},
		Spec: iamdatumapiscomv1alpha1.PolicyBindingSpec{
			RoleRef:  iamdatumapiscomv1alpha1.RoleReference{Name: "iam-user-self-manage", Namespace: "milo-system"},
			Subjects: []iamdatumapiscomv1alpha1.Subject{{Kind: "User", Name: userName, UID: userUID}},
			ResourceSelector: iamdatumapiscomv1alpha1.ResourceSelector{
				ResourceRef: &iamdatumapiscomv1alpha1.ResourceReference{
					APIGroup: iamdatumapiscomv1alpha1.SchemeGroupVersion.Group,
					Kind:     "User",
					Name:     userName,
					UID:      userUID,
				},
			},
		},
	}
}

func newUserAwareReconciler(t *testing.T, users ...*iamdatumapiscomv1alpha1.User) *PolicyBindingReconciler {
	t.Helper()
	r := newPolicyBindingReconciler(t, protectedResource(iamdatumapiscomv1alpha1.SchemeGroupVersion.Group, "User"))
	for _, u := range users {
		if err := r.Create(context.Background(), u); err != nil {
			t.Fatalf("create user: %v", err)
		}
	}
	mapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{iamdatumapiscomv1alpha1.SchemeGroupVersion})
	mapper.Add(iamdatumapiscomv1alpha1.SchemeGroupVersion.WithKind("User"), meta.RESTScopeRoot)
	r.RESTMapper = mapper
	return r
}

// Milo creates a User's self-manage PolicyBinding from the User admission
// webhook, so the binding can be reconciled before the User exists. Nothing
// watches Users, so a missing target or subject must be reported as retryable
// or the binding stays invalid forever.
func TestMissingReferencesAreRetryable(t *testing.T) {
	const userName, userUID = "392172446142175298", "a037382e-958a-47d1-835d-7a9b8537eaa3"

	t.Run("missing target is retryable", func(t *testing.T) {
		r := newUserAwareReconciler(t)
		pb := userSelfManageBinding(userName, userUID)

		isValid, targetMissing, err := r.validateResourceRef(context.Background(), pb, pb.Status.DeepCopy(), pb.Generation)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isValid || !targetMissing {
			t.Fatalf("expected an invalid, retryable target; got isValid=%v targetMissing=%v", isValid, targetMissing)
		}
	})

	t.Run("missing subject is retryable", func(t *testing.T) {
		r := newUserAwareReconciler(t)
		pb := userSelfManageBinding(userName, userUID)

		isValid, subjectMissing, _, err := r.validatePolicyBindingSubjects(context.Background(), pb, pb.Status.DeepCopy(), pb.Generation)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isValid || !subjectMissing {
			t.Fatalf("expected an invalid, retryable subject; got isValid=%v subjectMissing=%v", isValid, subjectMissing)
		}
	})

	t.Run("UID mismatch is not retried", func(t *testing.T) {
		user := &iamdatumapiscomv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: userName, UID: userUID}}
		r := newUserAwareReconciler(t, user)
		if err := r.Get(context.Background(), types.NamespacedName{Name: userName}, user); err != nil {
			t.Fatalf("get user: %v", err)
		}
		pb := userSelfManageBinding(userName, "not-"+string(user.UID))

		isValid, targetMissing, err := r.validateResourceRef(context.Background(), pb, pb.Status.DeepCopy(), pb.Generation)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isValid || targetMissing {
			t.Fatalf("expected an invalid, non-retryable target; got isValid=%v targetMissing=%v", isValid, targetMissing)
		}

		isValid, subjectMissing, _, err := r.validatePolicyBindingSubjects(context.Background(), pb, pb.Status.DeepCopy(), pb.Generation)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isValid || subjectMissing {
			t.Fatalf("expected an invalid, non-retryable subject; got isValid=%v subjectMissing=%v", isValid, subjectMissing)
		}
	})

	t.Run("existing user validates", func(t *testing.T) {
		user := &iamdatumapiscomv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: userName, UID: userUID}}
		r := newUserAwareReconciler(t, user)
		if err := r.Get(context.Background(), types.NamespacedName{Name: userName}, user); err != nil {
			t.Fatalf("get user: %v", err)
		}
		pb := userSelfManageBinding(userName, string(user.UID))

		isValid, targetMissing, err := r.validateResourceRef(context.Background(), pb, pb.Status.DeepCopy(), pb.Generation)
		if err != nil || !isValid || targetMissing {
			t.Fatalf("expected a valid target; got isValid=%v targetMissing=%v err=%v", isValid, targetMissing, err)
		}

		isValid, subjectMissing, _, err := r.validatePolicyBindingSubjects(context.Background(), pb, pb.Status.DeepCopy(), pb.Generation)
		if err != nil || !isValid || subjectMissing {
			t.Fatalf("expected valid subjects; got isValid=%v subjectMissing=%v err=%v", isValid, subjectMissing, err)
		}
	})
}

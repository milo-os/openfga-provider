package openfga

import (
	"context"
	"fmt"
	"strings"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (r *PolicyReconciler) subjectMismatch(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) (string, error) {
	for _, subject := range binding.Spec.Subjects {
		if subject.Kind == SubjectKindGroup && strings.HasPrefix(subject.Name, "system:") {
			continue
		}
		if subject.UID == "" {
			return fmt.Sprintf("%s/%s (UIDMissing)", subject.Kind, subject.Name), nil
		}

		var obj client.Object
		key := client.ObjectKey{Name: subject.Name}
		switch subject.Kind {
		case SubjectKindUser:
			obj = &iamdatumapiscomv1alpha1.User{}
		case SubjectKindServiceAccount:
			obj = &iamdatumapiscomv1alpha1.ServiceAccount{}
		case SubjectKindGroup:
			if subject.Namespace == "" {
				return fmt.Sprintf("%s/%s (NamespaceMissing)", subject.Kind, subject.Name), nil
			}
			obj = &iamdatumapiscomv1alpha1.Group{}
			key.Namespace = subject.Namespace
		default:
			return fmt.Sprintf("%s/%s (KindNotRecognized)", subject.Kind, subject.Name), nil
		}

		if err := r.K8sClient.Get(ctx, key, obj); err != nil {
			if !apierrors.IsNotFound(err) {
				return "", fmt.Errorf("failed to get subject %s/%s: %w", subject.Kind, subject.Name, err)
			}
			if subject.Kind == SubjectKindServiceAccount {
				continue
			}
			return fmt.Sprintf("%s/%s (NotFound)", subject.Kind, subject.Name), nil
		}
		if string(obj.GetUID()) != subject.UID {
			return fmt.Sprintf("%s/%s (UIDMismatch)", subject.Kind, subject.Name), nil
		}
	}
	return "", nil
}

func (r *PolicyReconciler) markSiblingNotReady(ctx context.Context, sibling iamdatumapiscomv1alpha1.PolicyBinding, mismatch string) {
	log := logf.FromContext(ctx).WithValues("sibling", sibling.Namespace+"/"+sibling.Name)
	msg := "Validation failed: The following subject issues were found: " + mismatch
	updated := sibling.DeepCopy()
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:    "SubjectValid",
		Status:  metav1.ConditionFalse,
		Reason:  "ValidationFailed",
		Message: msg,
	})
	meta.SetStatusCondition(&updated.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionFalse,
		Reason:  "SubjectValidationFailed",
		Message: "Subject validation failed. See SubjectValid condition for details.",
	})
	if err := r.K8sClient.Status().Update(ctx, updated); err != nil {
		log.Info("Could not mark sibling PolicyBinding not Ready", "error", err.Error())
		return
	}
	log.Info("Excluded sibling PolicyBinding whose subjects failed validation", "subjects", mismatch)
}

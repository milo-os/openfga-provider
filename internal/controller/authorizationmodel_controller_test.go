package controller

import (
	"testing"
	"time"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func protectedResourceFixture(generation, observedGeneration int64, deleting bool, hasFinalizer bool) *iamdatumapiscomv1alpha1.ProtectedResource {
	pr := &iamdatumapiscomv1alpha1.ProtectedResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "widgets",
			Generation: generation,
		},
		Status: iamdatumapiscomv1alpha1.ProtectedResourceStatus{
			ObservedGeneration: observedGeneration,
		},
	}
	if hasFinalizer {
		pr.Finalizers = []string{protectedResourceFinalizerKey}
	}
	if deleting {
		now := metav1.NewTime(time.Now())
		pr.DeletionTimestamp = &now
		// A DeletionTimestamp requires a finalizer to remain persisted; keep it
		// consistent with the fake object even though these are pure in-memory
		// fixtures never sent to an apiserver.
		if !hasFinalizer {
			pr.Finalizers = nil
		}
	}
	return pr
}

// TestProtectedResourceEventPredicate_Create covers the CreateFunc branch: a
// real create must always pass; a replayed (bootstrap) create only passes
// when there's still something for Reconcile to do.
func TestProtectedResourceEventPredicate_Create(t *testing.T) {
	pred := protectedResourceEventPredicate()

	tests := []struct {
		name            string
		isInInitialList bool
		pr              *iamdatumapiscomv1alpha1.ProtectedResource
		want            bool
	}{
		{
			name:            "real create always reconciles, even if it looks synced",
			isInInitialList: false,
			pr:              protectedResourceFixture(1, 1, false, true),
			want:            true,
		},
		{
			name:            "replay of a fully synced object is skipped",
			isInInitialList: true,
			pr:              protectedResourceFixture(2, 2, false, true),
			want:            false,
		},
		{
			name:            "replay with stale ObservedGeneration reconciles",
			isInInitialList: true,
			pr:              protectedResourceFixture(2, 1, false, true),
			want:            true,
		},
		{
			name:            "replay of an object already being deleted reconciles",
			isInInitialList: true,
			pr:              protectedResourceFixture(2, 2, true, true),
			want:            true,
		},
		{
			name:            "replay of a synced object missing its finalizer reconciles",
			isInInitialList: true,
			pr:              protectedResourceFixture(2, 2, false, false),
			want:            true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pred.Create(event.CreateEvent{Object: tc.pr, IsInInitialList: tc.isInInitialList})
			if got != tc.want {
				t.Fatalf("Create() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestProtectedResourceEventPredicate_Update covers the UpdateFunc branch. A
// generation change always reconciles; a metadata-only change (no generation
// bump) still needs to reconcile if deletion just started or the finalizer
// was stripped, since neither bumps generation.
func TestProtectedResourceEventPredicate_Update(t *testing.T) {
	pred := protectedResourceEventPredicate()

	tests := []struct {
		name  string
		oldPR *iamdatumapiscomv1alpha1.ProtectedResource
		newPR *iamdatumapiscomv1alpha1.ProtectedResource
		want  bool
	}{
		{
			name:  "generation changed reconciles",
			oldPR: protectedResourceFixture(1, 1, false, true),
			newPR: protectedResourceFixture(2, 1, false, true),
			want:  true,
		},
		{
			name:  "status-only update with unchanged generation is skipped",
			oldPR: protectedResourceFixture(2, 1, false, true),
			newPR: protectedResourceFixture(2, 2, false, true),
			want:  false,
		},
		{
			name:  "deletion just starting reconciles despite unchanged generation",
			oldPR: protectedResourceFixture(2, 2, false, true),
			newPR: protectedResourceFixture(2, 2, true, true),
			want:  true,
		},
		{
			name:  "finalizer stripped externally reconciles despite unchanged generation",
			oldPR: protectedResourceFixture(2, 2, false, true),
			newPR: protectedResourceFixture(2, 2, false, false),
			want:  true,
		},
		{
			name:  "already deleting with finalizer present and generation unchanged is skipped",
			oldPR: protectedResourceFixture(2, 2, true, true),
			newPR: protectedResourceFixture(2, 2, true, true),
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pred.Update(event.UpdateEvent{ObjectOld: tc.oldPR, ObjectNew: tc.newPR})
			if got != tc.want {
				t.Fatalf("Update() = %v, want %v", got, tc.want)
			}
		})
	}
}

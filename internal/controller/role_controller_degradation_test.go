package controller

import (
	"context"
	"sort"
	"testing"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func degradationScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := scheme.AddToScheme(s); err != nil {
		t.Fatalf("add client-go scheme: %v", err)
	}
	if err := iamv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add iam scheme: %v", err)
	}
	return s
}

func role(namespace, name string, included []string, inherited ...iamv1alpha1.ScopedRoleReference) *iamv1alpha1.Role {
	return &iamv1alpha1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: iamv1alpha1.RoleSpec{
			IncludedPermissions: included,
			InheritedRoles:      inherited,
		},
	}
}

func newRoleReconciler(t *testing.T, objs ...client.Object) *RoleReconciler {
	t.Helper()
	s := degradationScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	return &RoleReconciler{Client: c, Scheme: s}
}

// One unresolvable inheritedRoles entry must not zero out the rest: the
// resolvable inherited permissions plus the role's own permissions are still
// returned, and the dangling reference is reported.
func TestGetAllEffectivePermissions_DegradesGracefully(t *testing.T) {
	resolvable := role("org-x", "viewer", []string{"svc.miloapis.com/widgets.get"})
	owner := role("org-x", "owner",
		[]string{"svc.miloapis.com/widgets.create"},
		iamv1alpha1.ScopedRoleReference{Name: "viewer"},
		iamv1alpha1.ScopedRoleReference{Name: "missing-role"},
	)

	r := newRoleReconciler(t, resolvable, owner)

	perms, unresolved, err := r.getAllEffectivePermissions(context.Background(), owner, nil)
	if err != nil {
		t.Fatalf("expected no error for missing inherited role, got %v", err)
	}

	sort.Strings(perms)
	want := []string{"svc.miloapis.com/widgets.create", "svc.miloapis.com/widgets.get"}
	if len(perms) != len(want) || perms[0] != want[0] || perms[1] != want[1] {
		t.Fatalf("expected resolvable permissions %v, got %v", want, perms)
	}

	if len(unresolved) != 1 {
		t.Fatalf("expected 1 unresolved reference, got %d: %v", len(unresolved), unresolved)
	}
	if unresolved[0].Name != "missing-role" || unresolved[0].Namespace != "org-x" {
		t.Fatalf("expected unresolved org-x/missing-role, got %s", unresolved[0].String())
	}
}

// When every inherited role resolves, no unresolved references are reported.
func TestGetAllEffectivePermissions_FullyResolved(t *testing.T) {
	base := role("org-x", "viewer", []string{"svc.miloapis.com/widgets.get"})
	owner := role("org-x", "owner", nil, iamv1alpha1.ScopedRoleReference{Name: "viewer"})

	r := newRoleReconciler(t, base, owner)

	perms, unresolved, err := r.getAllEffectivePermissions(context.Background(), owner, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(unresolved) != 0 {
		t.Fatalf("expected no unresolved references, got %v", unresolved)
	}
	if len(perms) != 1 || perms[0] != "svc.miloapis.com/widgets.get" {
		t.Fatalf("expected inherited permission applied, got %v", perms)
	}
}

// dedupeUnresolved collapses a dangling reference reachable via multiple
// inheritance paths into a single, deterministically ordered entry.
func TestDedupeUnresolved(t *testing.T) {
	got := dedupeUnresolved([]unresolvedInheritedRole{
		{Namespace: "b", Name: "two"},
		{Namespace: "a", Name: "one"},
		{Namespace: "b", Name: "two"},
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 unique references, got %d: %v", len(got), got)
	}
	if got[0].String() != "a/one" || got[1].String() != "b/two" {
		t.Fatalf("expected sorted [a/one b/two], got %v", got)
	}
}

// setDegradedCondition surfaces a Degraded=True condition naming the unresolved
// reference, and clears it once references resolve.
func TestSetDegradedCondition(t *testing.T) {
	r := &RoleReconciler{}
	rl := role("org-x", "owner", nil)

	r.setDegradedCondition(context.Background(), rl, []unresolvedInheritedRole{{Namespace: "org-x", Name: "missing-role"}}, 1)
	cond := findCondition(rl, "Degraded")
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Degraded=True, got %+v", cond)
	}
	if cond.Reason != "UnresolvedInheritedRoles" {
		t.Fatalf("expected reason UnresolvedInheritedRoles, got %s", cond.Reason)
	}

	r.setDegradedCondition(context.Background(), rl, nil, 2)
	cond = findCondition(rl, "Degraded")
	if cond == nil || cond.Status != metav1.ConditionFalse {
		t.Fatalf("expected Degraded=False after resolution, got %+v", cond)
	}
}

// enqueueRequestsForInheritedRoleChange enqueues dependents that inherit a
// changed role (so a newly-created missing role triggers convergence) while
// excluding the changed role itself and unrelated roles.
func TestEnqueueRequestsForInheritedRoleChange(t *testing.T) {
	changed := role("org-x", "entitlement-admin", nil)
	dependent := role("org-x", "owner", nil, iamv1alpha1.ScopedRoleReference{Name: "entitlement-admin"})
	unrelated := role("org-x", "billing", nil, iamv1alpha1.ScopedRoleReference{Name: "something-else"})

	r := newRoleReconciler(t, changed, dependent, unrelated)

	reqs := r.enqueueRequestsForInheritedRoleChange(context.Background(), changed)
	if len(reqs) != 1 {
		t.Fatalf("expected 1 enqueued dependent, got %d: %v", len(reqs), reqs)
	}
	if reqs[0].Name != "owner" || reqs[0].Namespace != "org-x" {
		t.Fatalf("expected org-x/owner enqueued, got %s/%s", reqs[0].Namespace, reqs[0].Name)
	}
}

func findCondition(role *iamv1alpha1.Role, condType string) *metav1.Condition {
	for i := range role.Status.Conditions {
		if role.Status.Conditions[i].Type == condType {
			return &role.Status.Conditions[i]
		}
	}
	return nil
}

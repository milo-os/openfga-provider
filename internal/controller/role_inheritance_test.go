package controller

import (
	"context"
	"sort"
	"testing"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func role(namespace, name string, inherited ...iamdatumapiscomv1alpha1.ScopedRoleReference) *iamdatumapiscomv1alpha1.Role {
	return &iamdatumapiscomv1alpha1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       iamdatumapiscomv1alpha1.RoleSpec{InheritedRoles: inherited},
	}
}

func inherits(name, namespace string) iamdatumapiscomv1alpha1.ScopedRoleReference {
	return iamdatumapiscomv1alpha1.ScopedRoleReference{Name: name, Namespace: namespace}
}

func keys(set map[client.ObjectKey]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k.Namespace+"/"+k.Name)
	}
	sort.Strings(out)
	return out
}

func TestRolesDependentOnRole(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := iamdatumapiscomv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	tests := []struct {
		name    string
		roles   []*iamdatumapiscomv1alpha1.Role
		changed client.ObjectKey
		want    []string
	}{
		{
			name: "transitive chain across namespaces resolves full closure",
			roles: []*iamdatumapiscomv1alpha1.Role{
				// viewer (datum-cloud) -> networking-viewer (milo-system) -> gateway-viewer (milo-system)
				role("datum-cloud", "viewer", inherits("networking-viewer", "milo-system")),
				role("milo-system", "networking-viewer", inherits("gateway-viewer", "")),
				role("milo-system", "gateway-viewer"),
			},
			changed: client.ObjectKey{Namespace: "milo-system", Name: "gateway-viewer"},
			want: []string{
				"datum-cloud/viewer",
				"milo-system/gateway-viewer", // the changed role itself is included
				"milo-system/networking-viewer",
			},
		},
		{
			name: "empty inherited namespace defaults to the referencing role namespace",
			roles: []*iamdatumapiscomv1alpha1.Role{
				role("ns-a", "child", inherits("parent", "")),
				role("ns-a", "parent"),
				// Same-named parent in another namespace must NOT be matched.
				role("ns-b", "parent"),
			},
			changed: client.ObjectKey{Namespace: "ns-a", Name: "parent"},
			want:    []string{"ns-a/child", "ns-a/parent"},
		},
		{
			name: "cycle does not loop forever",
			roles: []*iamdatumapiscomv1alpha1.Role{
				role("ns", "a", inherits("b", "ns")),
				role("ns", "b", inherits("a", "ns")),
			},
			changed: client.ObjectKey{Namespace: "ns", Name: "a"},
			want:    []string{"ns/a", "ns/b"},
		},
		{
			name: "role with no dependents returns only itself",
			roles: []*iamdatumapiscomv1alpha1.Role{
				role("ns", "lonely"),
				role("ns", "unrelated", inherits("something-else", "ns")),
			},
			changed: client.ObjectKey{Namespace: "ns", Name: "lonely"},
			want:    []string{"ns/lonely"},
		},
		{
			name: "diamond inheritance is de-duplicated",
			roles: []*iamdatumapiscomv1alpha1.Role{
				role("ns", "top"),
				role("ns", "left", inherits("top", "ns")),
				role("ns", "right", inherits("top", "ns")),
				role("ns", "bottom", inherits("left", "ns"), inherits("right", "ns")),
			},
			changed: client.ObjectKey{Namespace: "ns", Name: "top"},
			want:    []string{"ns/bottom", "ns/left", "ns/right", "ns/top"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]client.Object, 0, len(tt.roles))
			for _, r := range tt.roles {
				objs = append(objs, r)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

			got, err := rolesDependentOnRole(context.Background(), c, tt.changed)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			gotKeys := keys(got)
			if len(gotKeys) != len(tt.want) {
				t.Fatalf("got %v, want %v", gotKeys, tt.want)
			}
			for i := range tt.want {
				if gotKeys[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", gotKeys, tt.want)
				}
			}
		})
	}
}

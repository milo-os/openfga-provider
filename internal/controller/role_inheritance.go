package controller

import (
	"context"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// rolesDependentOnRole returns the set of Roles whose effective permissions
// depend on the given (changed) Role: the changed Role itself plus every Role
// that transitively inherits it via spec.inheritedRoles.
//
// It performs a single List of all Roles and walks the reverse inheritance
// graph breadth-first, guarding against cycles. An inherited role reference
// with an empty namespace defaults to the referencing Role's namespace,
// mirroring getAllEffectivePermissions.
//
// This is the basis for propagating an inherited (ancestor) Role's permission
// changes down to the descendant Roles that inherit it and to the
// PolicyBindings bound to those descendants.
func rolesDependentOnRole(ctx context.Context, c client.Client, changed client.ObjectKey) (map[client.ObjectKey]struct{}, error) {
	roleList := &iamdatumapiscomv1alpha1.RoleList{}
	if err := c.List(ctx, roleList); err != nil {
		return nil, err
	}

	// reverse[parent] holds the Roles that directly inherit parent.
	reverse := make(map[client.ObjectKey][]client.ObjectKey, len(roleList.Items))
	for i := range roleList.Items {
		child := &roleList.Items[i]
		childKey := client.ObjectKey{Namespace: child.Namespace, Name: child.Name}
		for _, ref := range child.Spec.InheritedRoles {
			namespace := ref.Namespace
			if namespace == "" {
				namespace = child.Namespace
			}
			parentKey := client.ObjectKey{Namespace: namespace, Name: ref.Name}
			reverse[parentKey] = append(reverse[parentKey], childKey)
		}
	}

	dependents := map[client.ObjectKey]struct{}{changed: {}}
	queue := []client.ObjectKey{changed}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, childKey := range reverse[current] {
			if _, seen := dependents[childKey]; !seen {
				dependents[childKey] = struct{}{}
				queue = append(queue, childKey)
			}
		}
	}

	return dependents, nil
}

package openfga

import (
	"fmt"
	"sort"
	"strings"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

type resourceGraphNode struct {
	// The fully qualified Kind of the resource registered in the system. This
	// will always be in the format `<service_apigroup>/<Kind>` (e.g.
	// compute.miloapis.com/Workload).
	ResourceType string // This will store "serviceAPIGroup/Kind"

	// A list of permissions that are supported directly against this resource.
	// This will not contain a list of inherited permissions.
	DirectPermissions []string

	// A list of resources that can be a parent of the current resource in the
	// graph. These should be fully qualified names or special identifiers.
	ParentResources []string

	// A list of child resources that are direct child resources of the parent
	// resource.
	ChildResources []*resourceGraphNode
}

// Create a new graph of resources and the permissions that may be granted to
// each resource based on their parent / child relationships defined in the
// resource hierarchy.
//
// Each node in the graph represents a single resource and any permissions that
// may be granted to that resource. A parent resource may be granted any
// permission defined by a child resource to support permission inheritance.
//
// An error will be returned if no root resources were found in the hierarchy. A
// root resource is defined as a resource with no parent resources.
func getResourceGraph(protectedResources []iamdatumapiscomv1alpha1.ProtectedResource) (*resourceGraphNode, error) {
	if len(protectedResources) == 0 {
		return &resourceGraphNode{ResourceType: TypeRoot}, nil // Return a root node even if no protected resources
	}

	rootResourceIdentifiers := []string{} // Stores "serviceAPIGroup/Kind"
	// Contains a mapping of parent FQNs to their direct children FQNs.
	directChildren := map[string][]string{}
	// resources map key is "serviceAPIGroup/Kind", value is the original ProtectedResourceSpec + its serviceAPIGroup
	resources := map[string]struct {
		res             iamdatumapiscomv1alpha1.ProtectedResourceSpec
		serviceAPIGroup string // This is the ServiceRef.Name
	}{}

	for _, pr := range protectedResources {
		if pr.Spec.ServiceRef.Name == "" {
			fmt.Printf("Warning: ProtectedResource %s has empty ServiceRef.Name, cannot be added to graph\n", pr.Name)
			continue
		}

		if pr.Spec.Kind == "" { // Ensure Kind is not empty
			fmt.Printf("Warning: ProtectedResource %s (service %s) has an empty Kind, skipping\n", pr.Name, pr.Spec.ServiceRef.Name)
			continue
		}
		fqResourceType := pr.Spec.ServiceRef.Name + "/" + pr.Spec.Kind

		resources[fqResourceType] = struct {
			res             iamdatumapiscomv1alpha1.ProtectedResourceSpec
			serviceAPIGroup string
		}{res: pr.Spec, serviceAPIGroup: pr.Spec.ServiceRef.Name}

		if len(pr.Spec.ParentResources) == 0 {
			isAlreadyRoot := false
			for _, rootID := range rootResourceIdentifiers {
				if rootID == fqResourceType {
					isAlreadyRoot = true
					break
				}
			}
			if !isAlreadyRoot {
				rootResourceIdentifiers = append(rootResourceIdentifiers, fqResourceType)
			}
		}

		// All resources have the root resource as its parent so permissions can
		// be bound to the root resource to grant permissions across all
		// resources.
		effectiveParentResources := []string{}
		for _, parentRef := range pr.Spec.ParentResources {
			if parentRef.APIGroup == "" || parentRef.Kind == "" {
				fmt.Printf("Warning: ProtectedResource %s (service %s) has a ParentResource with empty APIGroup or Kind, skipping parent ref\n", pr.Name, pr.Spec.ServiceRef.Name)
				continue
			}
			effectiveParentResources = append(effectiveParentResources, parentRef.APIGroup+"/"+parentRef.Kind)
		}
		hasRootParent := false
		for _, p := range effectiveParentResources {
			if p == TypeRoot {
				hasRootParent = true
				break
			}
		}
		if !hasRootParent {
			effectiveParentResources = append(effectiveParentResources, TypeRoot)
		}

		for _, parentFQN := range effectiveParentResources {
			if parentFQN == "" { // Skip empty parent FQNs
				continue
			}
			if parentFQN != fqResourceType {
				// Ensure directChildren[parentFQN] doesn't get duplicate fqResourceType
				isChildAlreadyListed := false
				for _, childEntry := range directChildren[parentFQN] {
					if childEntry == fqResourceType {
						isChildAlreadyListed = true
						break
					}
				}
				if !isChildAlreadyListed {
					directChildren[parentFQN] = append(directChildren[parentFQN], fqResourceType)
				}
			}
		}
	}
	sort.Strings(rootResourceIdentifiers)
	for parent := range directChildren {
		sort.Strings(directChildren[parent])
	}

	nodes := []*resourceGraphNode{}
	processedRootNodes := make(map[string]bool) // To avoid processing the same root node multiple times if listed
	for _, fqResourceType := range rootResourceIdentifiers {
		if processedRootNodes[fqResourceType] {
			continue
		}
		resourceData, ok := resources[fqResourceType]
		if !ok {
			return nil, fmt.Errorf("root resource %s not found in processed map during graph construction", fqResourceType)
		}
		node, err := getResourceGraphNode(fqResourceType, resourceData.res, resources, directChildren, make(map[string]bool))
		if err != nil {
			return nil, fmt.Errorf("could not get root graph node for %s: %v", fqResourceType, err)
		}
		nodes = append(nodes, node)
		processedRootNodes[fqResourceType] = true
	}

	return &resourceGraphNode{
		ResourceType:   TypeRoot,
		ChildResources: nodes,
	}, nil
}

func getResourceGraphNode(
	fqResourceType string,
	resourceSpec iamdatumapiscomv1alpha1.ProtectedResourceSpec,
	allResources map[string]struct {
		res             iamdatumapiscomv1alpha1.ProtectedResourceSpec
		serviceAPIGroup string
	},
	directChildren map[string][]string,
	visited map[string]bool, // To detect cycles during recursion
) (*resourceGraphNode, error) {
	if visited[fqResourceType] {
		return nil, fmt.Errorf("cycle detected: resource %s already visited in current path", fqResourceType)
	}
	visited[fqResourceType] = true
	defer delete(visited, fqResourceType) // Clean up for other paths

	childNodes := []*resourceGraphNode{}
	for _, childFQN := range directChildren[fqResourceType] {
		if childFQN == "" { // Skip empty child FQNs
			continue
		}
		childData, found := allResources[childFQN]
		if !found {
			return nil, fmt.Errorf("did not find child resource data of type '%s' for parent '%s'", childFQN, fqResourceType)
		}

		// Create a new visited map for the recursive call to allow diamonds in graph but prevent cycles in path
		newVisited := make(map[string]bool)
		for k, v := range visited {
			newVisited[k] = v
		}

		childNode, err := getResourceGraphNode(childFQN, childData.res, allResources, directChildren, newVisited)
		if err != nil {
			// If cycle detected for a child, it might be an issue with graph structure.
			// For now, we report error. Depending on requirements, might skip child or handle differently.
			return nil, fmt.Errorf("failed to create graph node for child resource '%s' of '%s': %w", childFQN, fqResourceType, err)
		}
		if childNode != nil { // childNode could be nil if a cycle involving it was detected and handled by returning nil earlier
			childNodes = append(childNodes, childNode)
		}
	}

	node := &resourceGraphNode{
		ResourceType:    fqResourceType,
		ParentResources: []string{}, // This will be populated by iterating over resource.ParentResources
		ChildResources:  childNodes,
	}

	for _, pr := range resourceSpec.ParentResources {
		if pr.APIGroup == "" || pr.Kind == "" {
			// This should ideally not happen if validated upstream or if ParentResourceRef fields are required
			fmt.Printf("Warning: Node %s has a ParentResource with empty APIGroup or Kind, skipping parent ref\n", fqResourceType)
			continue
		}
		node.ParentResources = append(node.ParentResources, pr.APIGroup+"/"+pr.Kind)
	}
	sort.Strings(node.ParentResources)

	resourceTypeParts := strings.Split(fqResourceType, "/")
	if len(resourceTypeParts) != 2 {
		return nil, fmt.Errorf("invalid fully qualified type for resource, expected format `<service_apigroup>/<Kind>`: type %s", fqResourceType)
	}

	serviceSpecificAPIGroupFromFQN := resourceTypeParts[0]
	for _, permission := range resourceSpec.Permissions {
		if resourceSpec.Plural == "" { // Guard against empty Plural name
			fmt.Printf("Warning: Resource %s has an empty Plural name, skipping permission '%s'\n", fqResourceType, permission)
			continue
		}
		node.DirectPermissions = append(node.DirectPermissions, fmt.Sprintf("%s/%s.%s", serviceSpecificAPIGroupFromFQN, resourceSpec.Plural, permission))
	}
	sort.Strings(node.DirectPermissions)

	return node, nil
}

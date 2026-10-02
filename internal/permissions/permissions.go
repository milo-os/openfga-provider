// Package permissions defines the canonical IAM permission identity shared by
// authorization checks, registration validation, and OpenFGA model generation.
package permissions

import (
	"strings"

	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

type Permission struct {
	APIGroup    string
	Resource    string
	Subresource string
	Verb        string
}

func (p Permission) String() string {
	resource := p.Resource
	if p.Subresource != "" {
		resource += "/" + p.Subresource
	}
	return p.APIGroup + "/" + resource + "." + p.Verb
}

// Parse accepts group/resource.verb and group/resource/subresource.verb.
func Parse(value string) (Permission, bool) {
	slash := strings.IndexByte(value, '/')
	dot := -1
	if slash >= 0 {
		if offset := strings.IndexByte(value[slash+1:], '.'); offset >= 0 {
			dot = slash + 1 + offset
		}
	}
	if slash <= 0 || dot <= slash+1 || dot == len(value)-1 {
		return Permission{}, false
	}
	path := strings.Split(value[slash+1:dot], "/")
	if len(path) < 1 || len(path) > 2 {
		return Permission{}, false
	}
	for _, part := range path {
		if part == "" || strings.Contains(part, ".") {
			return Permission{}, false
		}
	}
	verb := value[dot+1:]
	p := Permission{APIGroup: value[:slash], Resource: path[0], Verb: verb}
	if len(path) == 2 {
		p.Subresource = path[1]
	}
	return p, true
}

func Defined(spec iam.ProtectedResourceSpec, p Permission, enableSubresources bool) bool {
	if p.APIGroup != spec.ServiceRef.Name || p.Resource != spec.Plural {
		return false
	}
	verbs := spec.Permissions
	if p.Subresource != "" {
		if !enableSubresources {
			return false
		}
		verbs = nil
		for _, sub := range spec.Subresources {
			if sub.Name == p.Subresource {
				verbs = sub.Permissions
				break
			}
		}
	}
	for _, verb := range verbs {
		if verb == p.Verb {
			return true
		}
	}
	return false
}

func Enumerate(spec iam.ProtectedResourceSpec, enableSubresources bool) []string {
	if spec.Plural == "" {
		return nil
	}
	out := make([]string, 0, len(spec.Permissions))
	for _, verb := range spec.Permissions {
		out = append(out, (Permission{APIGroup: spec.ServiceRef.Name, Resource: spec.Plural, Verb: verb}).String())
	}
	if enableSubresources {
		for _, sub := range spec.Subresources {
			for _, verb := range sub.Permissions {
				out = append(out, (Permission{APIGroup: spec.ServiceRef.Name, Resource: spec.Plural, Subresource: sub.Name, Verb: verb}).String())
			}
		}
	}
	return out
}

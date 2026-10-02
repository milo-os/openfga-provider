package permissions

import (
	"testing"

	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

func TestPermissionIdentity(t *testing.T) {
	for _, value := range []string{"test.example/widgets.patch", "test.example/widgets/status.patch", "core.miloapis.com/pods/log.get", "test.example/widgets.custom.verb", "test.example/widgets.custom/action"} {
		p, ok := Parse(value)
		require.True(t, ok, value)
		require.Equal(t, value, p.String())
	}
	for _, value := range []string{"widgets", "test.example/widgets/status/deeper.patch", "test.example/widgets/.patch"} {
		_, ok := Parse(value)
		require.False(t, ok, value)
	}
	spec := iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "widgets", Permissions: []string{"patch"}, Subresources: []iam.SubresourceDefinition{{Name: "status", Permissions: []string{"update"}}}}
	p, _ := Parse("test.example/widgets/status.update")
	require.False(t, Defined(spec, p, false))
	require.True(t, Defined(spec, p, true))
	p.Verb = "patch"
	require.False(t, Defined(spec, p, true), "base patch must not authorize status patch")
	require.Equal(t, []string{"test.example/widgets.patch"}, Enumerate(spec, false))
	require.Equal(t, []string{"test.example/widgets.patch", "test.example/widgets/status.update"}, Enumerate(spec, true))
}

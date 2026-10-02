package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	iam "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestSubresourceRegistrationAndCacheRevocation(t *testing.T) {
	ctx := context.Background()
	pr := iam.ProtectedResource{Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "widgets", Kind: "Widget", Permissions: []string{"patch", "custom.verb"}, Subresources: []iam.SubresourceDefinition{{Name: "status", Permissions: []string{"update"}}}}}
	cache := newProtectedResourceCacheFromItems([]iam.ProtectedResource{pr})
	auth := &SubjectAccessReviewAuthorizer{ProtectedResourceCache: cache}
	attrs := authorizer.AttributesRecord{APIGroup: "test.example", Resource: "widgets", Subresource: "status", Verb: "patch"}
	valid, err := auth.validatePermissionWithServiceDefaulting(ctx, attrs)
	require.NoError(t, err)
	require.True(t, valid, "default flag preserves legacy authorization")
	require.Equal(t, "test.example/widgets.patch", auth.buildPermissionString(attrs))
	attrs.Verb = "custom.verb"
	valid, err = auth.validatePermissionWithServiceDefaulting(ctx, attrs)
	require.NoError(t, err)
	require.True(t, valid, "legacy custom verbs remain valid")
	attrs.Verb = "patch"
	auth.EnableSubresourceAuthorization = true
	valid, err = auth.validatePermissionWithServiceDefaulting(ctx, attrs)
	require.NoError(t, err)
	require.False(t, valid, "status.update does not allow patch")
	require.Equal(t, "test.example/widgets/status.patch", auth.buildPermissionString(attrs))
	updated := pr.DeepCopy()
	updated.Spec.Subresources[0].Permissions = append(updated.Spec.Subresources[0].Permissions, "patch")
	cache.upsert(updated)
	valid, err = auth.validatePermissionWithServiceDefaulting(ctx, attrs)
	require.NoError(t, err)
	require.True(t, valid)
	attrs.Subresource = "scale"
	valid, err = auth.validatePermissionWithServiceDefaulting(ctx, attrs)
	require.NoError(t, err)
	require.False(t, valid, "unknown subresource must not fall back")
	attrs.Subresource = "status"
	updated = updated.DeepCopy()
	updated.Spec.Subresources = nil
	cache.upsert(updated)
	valid, err = auth.validatePermissionWithServiceDefaulting(ctx, attrs)
	require.NoError(t, err)
	require.False(t, valid, "registration removal revokes authorization")
	attrs.Subresource = ""
	valid, err = auth.validatePermissionWithServiceDefaulting(ctx, attrs)
	require.NoError(t, err)
	require.True(t, valid, "base grant remains independent")
	cache.delete(updated)
	valid, err = auth.validatePermissionWithServiceDefaulting(ctx, attrs)
	require.NoError(t, err)
	require.False(t, valid)
}

// Exercise the actual SAR adapter so an unregistered permission produces a
// normal deny rather than EvaluationError, which API servers can treat as 500.
func TestSubresourceSARUnknownPermissionDeniesCleanly(t *testing.T) {
	pr := iam.ProtectedResource{Spec: iam.ProtectedResourceSpec{ServiceRef: iam.ServiceReference{Name: "test.example"}, Plural: "widgets", Kind: "Widget", Permissions: []string{"patch"}}}
	hook := NewSubjectAccessReviewWebhook(Config{EnableSubresourceAuthorization: true, ProtectedResourceCache: newProtectedResourceCacheFromItems([]iam.ProtectedResource{pr})})
	req := Request{SubjectAccessReview: authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{User: "alice", UID: "alice-id", ResourceAttributes: &authorizationv1.ResourceAttributes{Group: "test.example", Resource: "widgets", Subresource: "status", Name: "one", Verb: "patch"}}}}
	resp := hook.Handle(context.Background(), req)
	require.False(t, resp.Status.Allowed)
	require.True(t, resp.Status.Denied)
	require.Empty(t, resp.Status.EvaluationError)
	require.Contains(t, resp.Status.Reason, "widgets/status.patch")
}

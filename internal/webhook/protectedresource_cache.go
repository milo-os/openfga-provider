package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// ProtectedResourceCache maintains an in-memory index of ProtectedResource objects,
// populated and kept up to date by a controller-runtime informer. This eliminates
// per-request K8s API List calls by serving lookups directly from memory.
//
// The index key is "{apiGroup}/{plural}" matching the lookup pattern used in
// validatePermissionWithServiceDefaulting and getProtectedResource.
type ProtectedResourceCache struct {
	mu    sync.RWMutex
	index map[string]*iamv1alpha1.ProtectedResource
}

// NewProtectedResourceCache creates a ProtectedResourceCache and registers event
// handlers on the manager's informer for ProtectedResource. The cache starts
// empty and is populated once the manager's cache syncs — callers must ensure
// the manager is started before serving requests.
func NewProtectedResourceCache(ctx context.Context, mgr ctrl.Manager) (*ProtectedResourceCache, error) {
	c := &ProtectedResourceCache{
		index: make(map[string]*iamv1alpha1.ProtectedResource),
	}

	informer, err := mgr.GetCache().GetInformer(ctx, &iamv1alpha1.ProtectedResource{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ProtectedResource informer: %w", err)
	}

	if _, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pr, ok := obj.(*iamv1alpha1.ProtectedResource)
			if !ok {
				return
			}
			c.upsert(pr)
		},
		UpdateFunc: func(_, newObj interface{}) {
			pr, ok := newObj.(*iamv1alpha1.ProtectedResource)
			if !ok {
				return
			}
			c.upsert(pr)
		},
		DeleteFunc: func(obj interface{}) {
			pr, ok := obj.(*iamv1alpha1.ProtectedResource)
			if !ok {
				// Handle tombstone objects that the informer emits when an item is
				// deleted but only the key is available.
				tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown)
				if !ok {
					slog.Warn("protectedresource_cache: unexpected object type in DeleteFunc",
						slog.String("type", fmt.Sprintf("%T", obj)))
					return
				}
				pr, ok = tombstone.Obj.(*iamv1alpha1.ProtectedResource)
				if !ok {
					slog.Warn("protectedresource_cache: unexpected tombstone object type",
						slog.String("type", fmt.Sprintf("%T", tombstone.Obj)))
					return
				}
			}
			c.delete(pr)
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to ProtectedResource informer: %w", err)
	}

	return c, nil
}

// WaitForCacheSync blocks until the informer cache has synced. It should be
// called after the manager has started and before the cache is used to serve
// requests. The provided cache.Cache is the manager's cache.
func (c *ProtectedResourceCache) WaitForCacheSync(ctx context.Context, mgrCache cache.Cache) error {
	if !mgrCache.WaitForCacheSync(ctx) {
		return fmt.Errorf("timed out waiting for ProtectedResource cache to sync")
	}
	return nil
}

// GetByAPIGroupAndResource returns the ProtectedResource matching the given API
// group and plural resource name. The second return value is false when no
// matching entry exists.
func (c *ProtectedResourceCache) GetByAPIGroupAndResource(apiGroup, resource string) (*iamv1alpha1.ProtectedResource, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := cacheKey(apiGroup, resource)
	pr, ok := c.index[key]
	return pr, ok
}

func (c *ProtectedResourceCache) upsert(pr *iamv1alpha1.ProtectedResource) {
	key := cacheKey(pr.Spec.ServiceRef.Name, pr.Spec.Plural)
	c.mu.Lock()
	c.index[key] = pr
	c.mu.Unlock()
	slog.Debug("protectedresource_cache: upserted entry",
		slog.String("key", key),
		slog.String("name", pr.Name),
	)
}

func (c *ProtectedResourceCache) delete(pr *iamv1alpha1.ProtectedResource) {
	key := cacheKey(pr.Spec.ServiceRef.Name, pr.Spec.Plural)
	c.mu.Lock()
	delete(c.index, key)
	c.mu.Unlock()
	slog.Debug("protectedresource_cache: deleted entry",
		slog.String("key", key),
		slog.String("name", pr.Name),
	)
}

func cacheKey(apiGroup, plural string) string {
	return apiGroup + "/" + plural
}

// newProtectedResourceCacheFromItems creates a ProtectedResourceCache pre-populated
// with the provided items. This is intended for use in tests only.
func newProtectedResourceCacheFromItems(items []iamv1alpha1.ProtectedResource) *ProtectedResourceCache {
	c := &ProtectedResourceCache{
		index: make(map[string]*iamv1alpha1.ProtectedResource, len(items)),
	}
	for i := range items {
		c.upsert(&items[i])
	}
	return c
}

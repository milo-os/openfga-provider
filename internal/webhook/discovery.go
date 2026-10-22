package webhook

import (
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
)

// ExpiringDiscoveryClient drops everything the wrapped client has cached once
// the TTL has passed, so a resource the API server starts serving is seen
// without restarting the webhook.
type ExpiringDiscoveryClient struct {
	discovery.CachedDiscoveryInterface

	ttl      time.Duration
	mu       sync.Mutex
	loadedAt time.Time
}

// NewExpiringDiscoveryClient wraps a cached discovery client, such as
// memory.NewMemCacheClient, and invalidates it every ttl.
func NewExpiringDiscoveryClient(cached discovery.CachedDiscoveryInterface, ttl time.Duration) *ExpiringDiscoveryClient {
	return &ExpiringDiscoveryClient{CachedDiscoveryInterface: cached, ttl: ttl}
}

func (c *ExpiringDiscoveryClient) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.loadedAt.IsZero() {
		c.loadedAt = now
		return
	}
	if now.Sub(c.loadedAt) >= c.ttl {
		c.Invalidate()
		c.loadedAt = now
	}
}

func (c *ExpiringDiscoveryClient) ServerGroups() (*metav1.APIGroupList, error) {
	c.expire()
	return c.CachedDiscoveryInterface.ServerGroups()
}

func (c *ExpiringDiscoveryClient) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	c.expire()
	return c.CachedDiscoveryInterface.ServerResourcesForGroupVersion(groupVersion)
}

func (c *ExpiringDiscoveryClient) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	c.expire()
	return c.CachedDiscoveryInterface.ServerGroupsAndResources()
}

func (c *ExpiringDiscoveryClient) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	c.expire()
	return c.CachedDiscoveryInterface.ServerPreferredResources()
}

func (c *ExpiringDiscoveryClient) ServerPreferredNamespacedResources() ([]*metav1.APIResourceList, error) {
	c.expire()
	return c.CachedDiscoveryInterface.ServerPreferredNamespacedResources()
}

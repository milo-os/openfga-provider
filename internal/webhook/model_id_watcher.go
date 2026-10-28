package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
)

// AuthorizationModelIDWatcher watches the openfga-authorization-model ConfigMap
// and keeps an up-to-date copy of the model ID in memory. The stored value is
// updated atomically so reads on the authorization hot-path never block.
//
// The watcher is backed by a Kubernetes informer scoped to the ConfigMap with
// the configured name in the given namespace. When the ConfigMap is created or
// updated the new model ID is stored immediately; the previous value is
// discarded.
type AuthorizationModelIDWatcher struct {
	// modelID holds the current authorization model ID as a string. atomic.Value
	// is used so GetModelID can be called from multiple goroutines without a
	// mutex.
	modelID atomic.Value
	// configMapName is the name of the ConfigMap to watch for model ID updates.
	configMapName string
	// stopCh is used to stop a standalone informer when one was created via
	// NewAuthorizationModelIDWatcherWithConfig. It is nil when using the
	// manager-backed constructor.
	stopCh chan struct{}
}

// NewAuthorizationModelIDWatcher creates an AuthorizationModelIDWatcher and
// registers event handlers on the manager's informer for ConfigMap objects in
// the given namespace. The watcher starts empty; it will be populated once the
// manager's informer cache syncs.
//
// An optional seedModelID can be supplied to pre-populate the watcher before
// the informer cache syncs. This is useful when the caller already knows the
// current model ID (e.g. read at startup) and wants to avoid a window where
// GetModelID returns an empty string.
func NewAuthorizationModelIDWatcher(ctx context.Context, mgr ctrl.Manager, namespace, configMapName, seedModelID string) (*AuthorizationModelIDWatcher, error) {
	if configMapName == "" {
		return nil, fmt.Errorf("configMapName is required")
	}
	w := &AuthorizationModelIDWatcher{
		configMapName: configMapName,
	}

	if seedModelID != "" {
		w.modelID.Store(seedModelID)
	}

	informer, err := mgr.GetCache().GetInformer(ctx, &corev1.ConfigMap{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap informer: %w", err)
	}

	w.addEventHandler(informer)

	return w, nil
}

// NewAuthorizationModelIDWatcherWithConfig creates an AuthorizationModelIDWatcher
// using a dedicated rest.Config instead of the manager's cache. This is useful
// when the manager's KUBECONFIG points to a remote cluster (e.g. a control
// plane) but the ConfigMap resides on the local workload cluster.
//
// The informer is started in a background goroutine and stopped when ctx is
// cancelled.
func NewAuthorizationModelIDWatcherWithConfig(ctx context.Context, cfg *rest.Config, namespace, configMapName, seedModelID string) (*AuthorizationModelIDWatcher, error) {
	if configMapName == "" {
		return nil, fmt.Errorf("configMapName is required")
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset for ConfigMap watcher: %w", err)
	}

	// Create a namespace-scoped informer factory filtered to just the target
	// ConfigMap to minimise memory and API load.
	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset,
		30*time.Second,
		informers.WithNamespace(namespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.OneTermEqualSelector("metadata.name", configMapName).String()
		}),
	)

	w := &AuthorizationModelIDWatcher{
		configMapName: configMapName,
		stopCh:        make(chan struct{}),
	}

	if seedModelID != "" {
		w.modelID.Store(seedModelID)
	}

	informer := factory.Core().V1().ConfigMaps().Informer()
	w.addEventHandler(informer)

	// Start the informer in the background.
	go factory.Start(w.stopCh)

	// Stop the informer when the context is cancelled.
	go func() {
		<-ctx.Done()
		close(w.stopCh)
	}()

	return w, nil
}

// informerWithEventHandler is the subset of informer interfaces needed to
// register event handlers. Both controller-runtime cache.Informer and
// client-go cache.SharedIndexInformer satisfy this interface.
type informerWithEventHandler interface {
	AddEventHandler(handler toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error)
}

// addEventHandler registers the ConfigMap event handlers on the given informer.
func (w *AuthorizationModelIDWatcher) addEventHandler(informer informerWithEventHandler) {
	informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{ //nolint:errcheck
		AddFunc: func(obj interface{}) {
			w.handleConfigMap(obj)
		},
		UpdateFunc: func(_, newObj interface{}) {
			w.handleConfigMap(newObj)
		},
		// Deletions are intentionally ignored: the model ID remains in memory
		// so that in-flight requests can still be pinned to a model ID even if
		// the ConfigMap is transiently absent.
	})
}

// GetModelID returns the most recently observed authorization model ID, or an
// empty string if no ConfigMap has been observed yet.
func (w *AuthorizationModelIDWatcher) GetModelID() string {
	v := w.modelID.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// handleConfigMap inspects a raw informer event object. If it is the
// openfga-authorization-model ConfigMap it extracts the model ID and stores it.
func (w *AuthorizationModelIDWatcher) handleConfigMap(obj interface{}) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		// Handle tombstone objects emitted on cache re-sync.
		tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		cm, ok = tombstone.Obj.(*corev1.ConfigMap)
		if !ok {
			return
		}
	}

	if cm.Name != w.configMapName {
		return
	}

	modelID, ok := cm.Data[openfga.AuthorizationModelIDKey]
	if !ok || modelID == "" {
		slog.Warn("model_id_watcher: ConfigMap present but model-id key is missing or empty",
			slog.String("configmap", cm.Name),
			slog.String("namespace", cm.Namespace),
		)
		return
	}

	previous := w.GetModelID()
	if previous == modelID {
		return
	}

	w.modelID.Store(modelID)
	slog.Info("model_id_watcher: authorization model ID updated",
		slog.String("model_id", modelID),
		slog.String("namespace", cm.Namespace),
	)
}

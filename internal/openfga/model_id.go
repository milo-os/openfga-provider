package openfga

// ModelIDProvider supplies the authorization model ID that OpenFGA calls should
// be pinned to.
//
// When a Write omits the model ID, OpenFGA resolves the store's latest model on
// every call. That resolution reads the whole authorization_model table, which
// for a large model costs seconds per write. Pinning the ID skips it, the same
// way the authorization webhook already pins it on Check.
//
// The interface is declared here rather than taken from internal/webhook
// (whose AuthorizationModelIDWatcher satisfies it) because that package imports
// this one.
type ModelIDProvider interface {
	GetModelID() string
}

// ModelIDFrom returns the provider's current model ID, or an empty string when
// no provider is configured or its cache has not populated yet. An empty ID is
// safe: OpenFGA falls back to resolving the latest model, which is the
// behaviour callers had before pinning was introduced.
func ModelIDFrom(p ModelIDProvider) string {
	if p == nil {
		return ""
	}
	return p.GetModelID()
}

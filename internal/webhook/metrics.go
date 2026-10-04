package webhook

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// authzRequestDuration measures the end-to-end duration of SubjectAccessReview
	// authorization requests, labeled by decision outcome, authorization scope, and
	// the API group of the resource being authorized.
	authzRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "authz_request_duration_seconds",
			Help:    "Duration of SubjectAccessReview authorization requests in seconds.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5},
		},
		[]string{"decision", "scope", "resource_group"},
	)

	// authzDecisionsTotal counts authorization decisions by outcome, scope, and
	// resource group. Use this to track decision distribution and error rates.
	// reason names the recording path; only the authorizer records permission_not_registered.
	authzDecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authz_decisions_total",
			Help: "Total number of authorization decisions by outcome.",
		},
		[]string{"decision", "scope", "resource_group", "reason"},
	)

	// authzStepDuration measures the duration of individual steps within the
	// authorization pipeline. Steps include: build_context, validate_namespace,
	// k8s_discovery, validate_permission, k8s_list_protectedresources,
	// build_openfga_request, openfga_check.
	authzStepDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "authz_step_duration_seconds",
			Help:    "Duration of individual steps within the authorization request pipeline.",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5},
		},
		[]string{"step"},
	)

	// authzK8sAPICallsTotal counts Kubernetes API calls made during authorization
	// request processing, labeled by resource type, verb, and call result.
	authzK8sAPICallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authz_k8s_api_calls_total",
			Help: "Total Kubernetes API calls made during authorization request processing.",
		},
		[]string{"resource", "verb", "result"},
	)

	// openfgaCheckTotal counts OpenFGA Check RPC calls by outcome.
	openfgaCheckTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "openfga_check_requests_total",
			Help: "Total OpenFGA Check requests by outcome.",
		},
		[]string{"allowed", "error"},
	)
)

const (
	reasonHTTPRequest             = "http_request"
	reasonOpenFGACheck            = "openfga_check"
	reasonPermissionNotRegistered = "permission_not_registered"
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		authzRequestDuration,
		authzDecisionsTotal,
		authzStepDuration,
		authzK8sAPICallsTotal,
		openfgaCheckTotal,
	)
}

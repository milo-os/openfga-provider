// Package telemetry provides OpenTelemetry tracer provider initialization for
// the auth-provider-openfga services. Tracing is opt-in: when no OTLP endpoint
// is configured the SDK installs a no-op tracer so call-sites pay zero overhead.
package telemetry

import (
	"context"
	"fmt"
	"net/url"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// ShutdownFunc is a function that flushes and shuts down the tracer provider.
// It should be called before the process exits.
type ShutdownFunc func(context.Context) error

// SetupTracer initialises the global OpenTelemetry tracer provider. When
// otlpEndpoint is empty a no-op provider is installed (zero overhead). The
// returned ShutdownFunc must be called on process exit to flush spans.
//
// serviceName should be the canonical service identifier, e.g.
// "auth-provider-openfga-webhook".
func SetupTracer(ctx context.Context, serviceName, serviceVersion, otlpEndpoint string) (trace.TracerProvider, ShutdownFunc, error) {
	if otlpEndpoint == "" {
		// Tracing disabled — install no-op provider so call-sites compile and
		// run without any changes.
		noopProvider := noop.NewTracerProvider()
		otel.SetTracerProvider(noopProvider)
		return noopProvider, func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(serviceVersion),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTEL resource: %w", err)
	}

	endpointURL, err := tracesEndpointURL(otlpEndpoint)
	if err != nil {
		return nil, nil, err
	}

	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(endpointURL),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP HTTP exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	shutdown := func(ctx context.Context) error {
		return tp.Shutdown(ctx)
	}

	return tp, shutdown, nil
}

func tracesEndpointURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse OTLP endpoint %q: %w", endpoint, err)
	}
	if u.Path != "" && u.Path != "/" {
		return endpoint, nil
	}
	return url.JoinPath(endpoint, "/v1/traces")
}

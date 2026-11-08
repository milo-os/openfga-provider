package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTracesEndpointURL(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name:     "bare host and port gets the traces path",
			endpoint: "http://otel-collector.telemetry-system.svc.cluster.local:4318",
			want:     "http://otel-collector.telemetry-system.svc.cluster.local:4318/v1/traces",
		},
		{
			name:     "root path gets the traces path",
			endpoint: "http://localhost:4318/",
			want:     "http://localhost:4318/v1/traces",
		},
		{
			name:     "explicit traces path is unchanged",
			endpoint: "https://collector.example.com:4318/v1/traces",
			want:     "https://collector.example.com:4318/v1/traces",
		},
		{
			name:     "custom path is unchanged",
			endpoint: "https://collector.example.com/otlp/ingest",
			want:     "https://collector.example.com/otlp/ingest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tracesEndpointURL(tt.endpoint)
			if err != nil {
				t.Fatalf("tracesEndpointURL(%q) returned error: %v", tt.endpoint, err)
			}
			if got != tt.want {
				t.Errorf("tracesEndpointURL(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestTracesEndpointURLRejectsInvalidURL(t *testing.T) {
	if _, err := tracesEndpointURL("http://[::1"); err == nil {
		t.Fatal("expected an error for an unparseable endpoint")
	}
}

func TestSetupTracerExportsToPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantPath string
	}{
		{name: "bare host and port", path: "", wantPath: "/v1/traces"},
		{name: "custom path", path: "/custom/traces", wantPath: "/custom/traces"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case paths <- r.URL.Path:
				default:
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			ctx := context.Background()
			tp, shutdown, err := SetupTracer(ctx, "test-service", "test", srv.URL+tt.path)
			if err != nil {
				t.Fatalf("SetupTracer returned error: %v", err)
			}

			_, span := tp.Tracer("test").Start(ctx, "span")
			span.End()

			if err := shutdown(ctx); err != nil {
				t.Fatalf("shutdown returned error: %v", err)
			}

			select {
			case got := <-paths:
				if got != tt.wantPath {
					t.Errorf("exporter posted to %q, want %q", got, tt.wantPath)
				}
			default:
				t.Fatal("exporter sent no request to the collector")
			}
		})
	}
}

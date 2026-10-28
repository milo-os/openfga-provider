package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

const decisionError = "error"

var authorizationScheme = runtime.NewScheme()
var authorizationCodecs = serializer.NewCodecFactory(authorizationScheme)

func init() {
	utilruntime.Must(authorizationv1.AddToScheme(authorizationScheme))
}

// Request defines the input for an authorization handler.
// It contains information to identify the object in
// question (group, version, kind, resource, subresource,
// name, namespace), as well as the operation in question
// (e.g. Get, Create, etc), and the object itself.
type Request struct {
	authorizationv1.SubjectAccessReview
}

// Response is the output of an authorization handler.
// It contains a response indicating if a given
// operation is allowed.
type Response struct {
	authorizationv1.SubjectAccessReview
}

// HandlerFunc implements Handler interface using a single function.
type HandlerFunc func(context.Context, Request) Response

// Handler can handle an SubjectAccessReview.
type Handler interface {
	// Handle yields a response to a SubjectAccessReview.
	//
	// The supplied context is extracted from the received http.Request, allowing wrapping
	// http.Handlers to inject values into and control cancelation of downstream request processing.
	Handle(context.Context, Request) Response
}

var _ Handler = HandlerFunc(nil)

// Handle process the SubjectAccessReview by invoking the underlying function.
func (f HandlerFunc) Handle(ctx context.Context, req Request) Response {
	return f(ctx, req)
}

var _ http.Handler = &Webhook{}

// ServeHTTP implements http.Handler.
func (wh *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Extract incoming trace context (e.g. from API server if it ever injects
	// W3C trace-context headers) and create a root span for the full request.
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	tracer := otel.GetTracerProvider().Tracer("authz-webhook")
	ctx, span := tracer.Start(ctx, "SubjectAccessReview.authorize",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(r.Method),
			semconv.HTTPRouteKey.String(r.URL.Path),
		),
	)
	defer span.End()

	// Attach request correlation ID to context. Prefer trace ID from the active
	// span when tracing is enabled so that Loki's traceID derived field links
	// log lines to Tempo automatically.
	requestID := traceIDFromSpan(span)
	if requestID == "" {
		requestID = generateRequestID(r.Header.Get("X-Request-ID"))
	}
	ctx = contextWithRequestID(ctx, requestID)

	if wh.WithContextFunc != nil {
		ctx = wh.WithContextFunc(ctx, r)
	}

	var body []byte
	var err error
	var reviewResponse Response
	var decision string
	var resourceGroup string
	var scope string

	// Record end-to-end metrics regardless of how the handler exits.
	defer func() {
		authzRequestDuration.WithLabelValues(decision, scope, resourceGroup).Observe(time.Since(start).Seconds())
		authzDecisionsTotal.WithLabelValues(decision, scope, resourceGroup).Inc()
	}()

	if r.Body == nil {
		err = errors.New("request body is empty")
		reviewResponse = Errored(err)
		decision = decisionError
		wh.writeResponse(w, nil, reviewResponse)
		return
	}
	defer func() {
		if closeErr := r.Body.Close(); closeErr != nil {
			slog.ErrorContext(ctx, "failed to close request body", slog.String("error", closeErr.Error()))
		}
	}()

	if body, err = io.ReadAll(r.Body); err != nil {
		reviewResponse = Errored(err)
		decision = decisionError
		wh.writeResponse(w, nil, reviewResponse)
		return
	}

	// verify the content type is accurate
	if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
		reviewResponse = Errored(fmt.Errorf("contentType=%s, expected application/json", contentType))
		decision = decisionError
		wh.writeResponse(w, nil, reviewResponse)
		return
	}

	req := Request{}
	_, _, err = authorizationCodecs.UniversalDeserializer().Decode(body, nil, &req.SubjectAccessReview)
	if err != nil {
		reviewResponse = Errored(err)
		decision = decisionError
		wh.writeResponse(w, &req, reviewResponse)
		return
	}

	// Populate span and metric dimensions from the parsed request before
	// forwarding to the handler so they are available even if the handler
	// panics or returns early.
	if req.Spec.ResourceAttributes != nil {
		resourceGroup = req.Spec.ResourceAttributes.Group
	}
	span.SetAttributes(
		attribute.String("authz.user", req.Spec.User),
		attribute.String("authz.resource_group", resourceGroup),
	)

	reviewResponse = wh.Handle(ctx, req)
	decision = decisionFromResponse(reviewResponse)
	scope = scopeFromResponse(reviewResponse)

	// Attach final decision and scope dimensions to the span.
	span.SetAttributes(
		attribute.String("authz.decision", decision),
		attribute.String("authz.scope", scope),
	)

	if reviewResponse.Status.EvaluationError != "" {
		slog.ErrorContext(ctx, "evaluation error in webhook", slog.String("error", reviewResponse.Status.EvaluationError))
	}

	slog.InfoContext(
		ctx,
		"handled SubjectAccessReview webhook request",
		slog.Bool("allowed", reviewResponse.Status.Allowed),
		slog.Bool("denied", reviewResponse.Status.Denied),
		slog.String("user", req.Spec.User),
		slog.String("request_id", requestID),
		slog.String("traceID", traceIDFromSpan(span)),
		slog.Duration("duration", time.Since(start)),
	)
	wh.writeResponse(w, &req, reviewResponse)
}

// writeResponse writes response resp to w. req is optional (can be nil) and adds
// context for the logger.
func (wh *Webhook) writeResponse(w io.Writer, req *Request, resp Response) {
	_ = req

	resp.SetGroupVersionKind(authorizationv1.SchemeGroupVersion.WithKind("SubjectAccessReview"))

	if err := json.NewEncoder(w).Encode(resp.SubjectAccessReview); err != nil {
		panic(err)
	}
}

// decisionFromResponse converts the webhook response status into a metric label
// value: "allowed", "denied", or "error".
func decisionFromResponse(resp Response) string {
	if resp.Status.EvaluationError != "" {
		return decisionError
	}
	if resp.Status.Allowed {
		return "allowed"
	}
	if resp.Status.Denied {
		return "denied"
	}
	return "no_opinion"
}

// scopeFromResponse infers the authorization scope label from context stored in
// the response. Because the response does not carry scope metadata directly, we
// return "unknown" here; the Authorize method sets scope on the context which
// flows back through the handler and could be threaded through if needed. For
// the HTTP layer we keep this as a best-effort label populated by the defer.
//
// Scope is more accurately recorded by the authorizer; this default prevents
// missing label values in the metrics.
func scopeFromResponse(_ Response) string {
	return "unknown"
}

// traceIDFromSpan returns the hex trace ID from a span's context, or an empty
// string when the span is a no-op (tracing disabled).
func traceIDFromSpan(span trace.Span) string {
	sc := span.SpanContext()
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

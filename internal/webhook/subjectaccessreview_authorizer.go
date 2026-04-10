package webhook

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/discovery"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	SubjectAccessReviewWebhookPath = "/apis/authorization.k8s.io/v1/subjectaccessreviews"
)

// WebhookServer interface abstracts the webhook server registration
type WebhookServer interface {
	Register(path string, hook http.Handler)
}

// Contains a mapping of Kubernetes APIGroups to the service name that should be
// used by the webhook to perform authorization checks.
var serviceNameMapping = map[string]string{
	// An empty APIGroup is used for the core/v1 Kubernetes API Group.
	"": "core.miloapis.com",
}

var _ authorizer.Authorizer = &SubjectAccessReviewAuthorizer{}

type SubjectAccessReviewAuthorizer struct {
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
	// ModelIDWatcher provides the current authorization model ID. When the
	// returned ID is non-empty OpenFGA skips its internal model lookup (one DB
	// read saved per Check call). If the watcher returns an empty string
	// OpenFGA resolves the latest model on each call (safe but slower).
	ModelIDWatcher         *AuthorizationModelIDWatcher
	ProtectedResourceCache *ProtectedResourceCache
	DiscoveryClient        discovery.DiscoveryInterface
}

// Config holds the configuration for creating a SubjectAccessReview webhook
type Config struct {
	FGAClient              openfgav1.OpenFGAServiceClient
	FGAStoreID             string
	ModelIDWatcher         *AuthorizationModelIDWatcher
	ProtectedResourceCache *ProtectedResourceCache
	DiscoveryClient        discovery.DiscoveryInterface
}

// NewSubjectAccessReviewWebhook creates a new SubjectAccessReview authorization webhook
func NewSubjectAccessReviewWebhook(config Config) *Webhook {
	authorizer := &SubjectAccessReviewAuthorizer{
		FGAClient:              config.FGAClient,
		FGAStoreID:             config.FGAStoreID,
		ModelIDWatcher:         config.ModelIDWatcher,
		ProtectedResourceCache: config.ProtectedResourceCache,
		DiscoveryClient:        config.DiscoveryClient,
	}
	return NewAuthorizerWebhook(authorizer)
}

// RegisterSubjectAccessReviewWebhook registers a SubjectAccessReview webhook with the provided server
// This fully encapsulates the webhook registration details within the webhook package
func RegisterSubjectAccessReviewWebhook(server WebhookServer, config Config) {
	webhook := NewSubjectAccessReviewWebhook(config)
	server.Register(SubjectAccessReviewWebhookPath, webhook)
}

// parentContext represents the parent resource context from user extra data
type parentContext struct {
	apiGroup string
	kind     string
	name     string
}

// authorizationContext holds the essential information needed for authorization
type authorizationContext struct {
	userUID       string
	permission    string
	parentContext *parentContext
	namespace     string
}

// isProjectScope checks if the parent context is a Project resource
func (ctx *authorizationContext) isProjectScope() bool {
	return ctx.parentContext != nil &&
		ctx.parentContext.apiGroup == "resourcemanager.miloapis.com" &&
		ctx.parentContext.kind == "Project"
}

// isOrganizationScope checks if the parent context is an Organization resource
func (ctx *authorizationContext) isOrganizationScope() bool {
	return ctx.parentContext != nil &&
		ctx.parentContext.apiGroup == "resourcemanager.miloapis.com" &&
		ctx.parentContext.kind == "Organization"
}

// getProjectName returns the project name if in project scope
func (ctx *authorizationContext) getProjectName() string {
	if ctx.isProjectScope() {
		return ctx.parentContext.name
	}
	return ""
}

// getOrganizationName returns the organization name if in organization scope
func (ctx *authorizationContext) getOrganizationName() string {
	if ctx.isOrganizationScope() {
		return ctx.parentContext.name
	}
	return ""
}

// scopeLabel returns the metric scope label for an authorization context.
func scopeLabel(authCtx *authorizationContext) string {
	if authCtx == nil {
		return "unknown"
	}
	if authCtx.isProjectScope() {
		return "project"
	}
	if authCtx.isOrganizationScope() {
		return "organization"
	}
	return "cluster"
}

// extractParentContext extracts parent resource information from user extra data
func (o *SubjectAccessReviewAuthorizer) extractParentContext(attributes authorizer.Attributes) *parentContext {
	extra := attributes.GetUser().GetExtra()

	parentAPIGroup, apiGroupOK := extra[iamv1alpha1.ParentAPIGroupExtraKey]
	parentKind, kindOK := extra[iamv1alpha1.ParentKindExtraKey]
	parentName, nameOK := extra[iamv1alpha1.ParentNameExtraKey]

	if !apiGroupOK || !kindOK || !nameOK {
		return nil
	}

	if len(parentAPIGroup) == 1 && len(parentKind) == 1 && len(parentName) == 1 {
		return &parentContext{
			apiGroup: parentAPIGroup[0],
			kind:     parentKind[0],
			name:     parentName[0],
		}
	}

	return nil
}

// Authorize implements authorizer.Authorizer.
func (o *SubjectAccessReviewAuthorizer) Authorize(ctx context.Context, attributes authorizer.Attributes) (authorizer.Decision, string, error) {
	start := time.Now()
	requestID := requestIDFromContext(ctx)
	tracer := otel.GetTracerProvider().Tracer("authz-webhook")

	ctx, span := tracer.Start(ctx, "authorize")
	defer span.End()

	span.SetAttributes(
		attribute.String("authz.user", attributes.GetUser().GetName()),
		attribute.String("authz.resource", attributes.GetResource()),
		attribute.String("authz.verb", attributes.GetVerb()),
		attribute.String("authz.resource_group", attributes.GetAPIGroup()),
	)

	// Step 1: Build authorization context
	stepStart := time.Now()
	ctx, buildCtxSpan := tracer.Start(ctx, "build_authorization_context")
	authCtx, err := o.buildAuthorizationContext(attributes)
	buildCtxSpan.End()
	authzStepDuration.WithLabelValues("build_context").Observe(time.Since(stepStart).Seconds())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return authorizer.DecisionDeny, "", err
	}

	scope := scopeLabel(authCtx)
	span.SetAttributes(attribute.String("authz.scope", scope))

	// Step 2: Validate organization namespace if organization-scoped
	stepStart = time.Now()
	ctx, validateNsSpan := tracer.Start(ctx, "validate_organization_namespace")
	validateNsErr := o.validateOrganizationNamespace(ctx, authCtx, attributes)
	validateNsSpan.End()
	authzStepDuration.WithLabelValues("validate_namespace").Observe(time.Since(stepStart).Seconds())
	if validateNsErr != nil {
		logf.FromContext(ctx).Info("organization namespace validation failed",
			"error", validateNsErr.Error(),
			"request_id", requestID,
		)
		span.RecordError(validateNsErr)
		span.SetStatus(codes.Error, validateNsErr.Error())
		return authorizer.DecisionDeny, "", validateNsErr
	}

	// Step 5: Validate permission exists
	stepStart = time.Now()
	ctx, validatePermSpan := tracer.Start(ctx, "validate_permission")
	permExists, validatePermErr := o.validatePermissionWithServiceDefaulting(ctx, attributes)
	validatePermSpan.End()
	authzStepDuration.WithLabelValues("validate_permission").Observe(time.Since(stepStart).Seconds())
	if validatePermErr != nil {
		span.RecordError(validatePermErr)
		span.SetStatus(codes.Error, validatePermErr.Error())
		return authorizer.DecisionDeny, "", validatePermErr
	}
	if !permExists {
		permission := o.buildPermissionString(attributes)
		logf.FromContext(ctx).Info("permission not found", "attributes", attributes, "permission", permission)
		return authorizer.DecisionDeny, "", fmt.Errorf("permission '%s' not registered", permission)
	}

	// Step 6: Build OpenFGA check request
	stepStart = time.Now()
	ctx, buildReqSpan := tracer.Start(ctx, "build_openfga_request")
	checkReq, err := o.buildOpenFGARequest(ctx, attributes, authCtx)
	buildReqSpan.End()
	authzStepDuration.WithLabelValues("build_openfga_request").Observe(time.Since(stepStart).Seconds())
	if err != nil {
		buildErr := fmt.Errorf("failed to build OpenFGA request: %w", err)
		span.RecordError(buildErr)
		span.SetStatus(codes.Error, buildErr.Error())
		return authorizer.DecisionDeny, "", buildErr
	}

	// Step 7: Execute OpenFGA BatchCheck. Each request checks both the
	// resolved object (instance, project, or organization) and the
	// kind-level Root object in a single RPC. This ensures ResourceKind
	// PolicyBindings are evaluated regardless of request scope.
	stepStart = time.Now()
	var decision authorizer.Decision
	var reason string
	var checkErr error

	protectedResource, prErr := o.getProtectedResource(ctx, attributes)
	if prErr != nil {
		buildErr := fmt.Errorf("failed to get protected resource for batch check: %w", prErr)
		span.RecordError(buildErr)
		span.SetStatus(codes.Error, buildErr.Error())
		return authorizer.DecisionDeny, "", buildErr
	}
	rootResource := o.buildRootResource(protectedResource)

	// For scoped requests (project or organization), also check the scope-level
	// root object. This covers ResourceKind PolicyBindings targeting all instances
	// of the scope type (e.g. staff bindings on all Projects or all Organizations).
	var extraChecks []*openfgav1.BatchCheckItem
	if authCtx.parentContext != nil {
		scopeRoot := fmt.Sprintf("iam.miloapis.com/Root:%s/%s", authCtx.parentContext.apiGroup, authCtx.parentContext.kind)
		extraChecks = append(extraChecks, &openfgav1.BatchCheckItem{
			TupleKey: &openfgav1.CheckRequestTupleKey{
				User:     checkReq.TupleKey.User,
				Relation: checkReq.TupleKey.Relation,
				Object:   scopeRoot,
			},
			CorrelationId: "scope-root",
		})
	}
	decision, reason, checkErr = o.executeBatchCheck(ctx, checkReq, rootResource, extraChecks...)
	authzStepDuration.WithLabelValues("openfga_batch_check").Observe(time.Since(stepStart).Seconds())

	// Record total end-to-end duration at the authorizer level as well, labeled
	// with the decision and scope so it can be used independently of the HTTP
	// handler metrics.
	totalDuration := time.Since(start)
	decisionStr := decisionLabel(decision, checkErr)
	resourceGroup := attributes.GetAPIGroup()

	authzRequestDuration.WithLabelValues(decisionStr, scope, resourceGroup).Observe(totalDuration.Seconds())
	authzDecisionsTotal.WithLabelValues(decisionStr, scope, resourceGroup).Inc()

	span.SetAttributes(attribute.String("authz.decision", decisionStr))
	if checkErr != nil {
		span.RecordError(checkErr)
		span.SetStatus(codes.Error, checkErr.Error())
	}

	logf.FromContext(ctx).Info("authorization completed",
		"request_id", requestID,
		"traceID", traceIDFromSpan(span),
		"duration", totalDuration,
		"decision", decisionStr,
		"scope", scope,
		"resource_group", resourceGroup,
		"resource", attributes.GetResource(),
		"verb", attributes.GetVerb(),
		"user", attributes.GetUser().GetName(),
	)

	return decision, reason, checkErr
}

// decisionLabel maps an authorizer.Decision and optional error to the metric
// label used on authz_request_duration_seconds and authz_decisions_total.
func decisionLabel(decision authorizer.Decision, err error) string {
	if err != nil {
		return "error"
	}
	switch decision {
	case authorizer.DecisionAllow:
		return "allowed"
	case authorizer.DecisionDeny:
		return "denied"
	default:
		return "no_opinion"
	}
}

// buildAuthorizationContext extracts and validates the essential information needed for authorization
func (o *SubjectAccessReviewAuthorizer) buildAuthorizationContext(attributes authorizer.Attributes) (*authorizationContext, error) {
	userUID := attributes.GetUser().GetUID()
	if userUID == "" {
		return nil, fmt.Errorf("user UID is required by SubjectAccessReview authorizer")
	}

	permission := o.buildPermissionString(attributes)
	parentContext := o.extractParentContext(attributes)
	namespace := attributes.GetNamespace()

	return &authorizationContext{
		userUID:       userUID,
		permission:    permission,
		parentContext: parentContext,
		namespace:     namespace,
	}, nil
}

// isResourceNamespaced determines if a given resource type is namespace-scoped using Kubernetes API discovery
// Uses a TTL-based cached discovery client that automatically refreshes stale cache entries
func (o *SubjectAccessReviewAuthorizer) isResourceNamespaced(ctx context.Context, apiGroup, apiVersion, resource string) (bool, error) {
	// Build the full group version string for discovery
	var groupVersion string
	if apiGroup == "" {
		// Core API group - use version directly
		groupVersion = apiVersion
	} else {
		// Named API group - combine group and version
		groupVersion = fmt.Sprintf("%s/%s", apiGroup, apiVersion)
	}

	tracer := otel.GetTracerProvider().Tracer("authz-webhook")
	ctx, discoverySpan := tracer.Start(ctx, "k8s.discovery.ServerResourcesForGroupVersion")
	discoverySpan.SetAttributes(attribute.String("api.group_version", groupVersion))

	// Get server resources for the API group version
	// The cached discovery client handles TTL-based refresh automatically
	stepStart := time.Now()
	resourceList, err := o.DiscoveryClient.ServerResourcesForGroupVersion(groupVersion)
	discoveryDuration := time.Since(stepStart)
	discoverySpan.End()

	authzStepDuration.WithLabelValues("k8s_discovery").Observe(discoveryDuration.Seconds())

	if err != nil {
		authzK8sAPICallsTotal.WithLabelValues("discovery", "get", "error").Inc()
		logf.FromContext(ctx).Info("failed to get server resources",
			"apiGroup", apiGroup,
			"apiVersion", apiVersion,
			"groupVersion", groupVersion,
			"error", err.Error())
		return false, fmt.Errorf("failed to get server resources for group version %s: %w", groupVersion, err)
	}
	authzK8sAPICallsTotal.WithLabelValues("discovery", "get", "success").Inc()

	logf.FromContext(ctx).V(1).Info("k8s discovery completed",
		"group_version", groupVersion,
		"duration", discoveryDuration,
	)

	// Find the resource in the list
	for _, apiResource := range resourceList.APIResources {
		if apiResource.Name == resource {
			logf.FromContext(ctx).V(1).Info("found resource in discovery cache",
				"apiGroup", apiGroup,
				"apiVersion", apiVersion,
				"resource", resource,
				"namespaced", apiResource.Namespaced)
			return apiResource.Namespaced, nil
		}
	}

	// Resource not found - this could indicate a new resource that hasn't been cached yet
	logf.FromContext(ctx).Info("resource not found in API group version, this may indicate a newly registered resource",
		"apiGroup", apiGroup,
		"apiVersion", apiVersion,
		"groupVersion", groupVersion,
		"resource", resource)
	return false, fmt.Errorf("resource %s not found in API group version %s", resource, groupVersion)
}

// validateOrganizationNamespace ensures the request namespace matches the organization's namespace
func (o *SubjectAccessReviewAuthorizer) validateOrganizationNamespace(ctx context.Context, authCtx *authorizationContext, attributes authorizer.Attributes) error {
	if !authCtx.isOrganizationScope() {
		return nil // Not organization-scoped, skip validation
	}

	requestNamespace := attributes.GetNamespace()
	expectedNamespace := fmt.Sprintf("organization-%s", authCtx.getOrganizationName())

	// If no namespace specified in request, check if resource is cluster-scoped
	if requestNamespace == "" {
		isNamespaced, err := o.isResourceNamespaced(ctx, attributes.GetAPIGroup(), attributes.GetAPIVersion(), attributes.GetResource())
		if err != nil {
			return fmt.Errorf("failed to determine if resource is namespaced: %w", err)
		}

		if !isNamespaced {
			// Cluster-scoped resource - no namespace validation needed
			return nil
		}

		// Namespace-scoped resource with empty namespace = cross-namespace query
		// Deny for organization-scoped requests
		return fmt.Errorf("cross-namespace queries not allowed for organization-scoped requests")
	}

	// Namespace specified - validate it matches organization's namespace
	if requestNamespace != expectedNamespace {
		return fmt.Errorf("namespace mismatch: request namespace '%s' does not match organization namespace '%s'",
			requestNamespace, expectedNamespace)
	}

	return nil
}

// buildOpenFGARequest creates the OpenFGA Check request for a given
// authorization context:
//
//	Check(InternalUser:<uid>, hash(svc/resource.verb), <resource-object>)
func (o *SubjectAccessReviewAuthorizer) buildOpenFGARequest(ctx context.Context, attributes authorizer.Attributes, authCtx *authorizationContext) (*openfgav1.CheckRequest, error) {
	return o.buildCheckRequest(ctx, attributes, authCtx)
}

// buildCheckRequest builds the Check request. All relationships are stored
// as persistent tuples written at PolicyBinding reconciliation time.
func (o *SubjectAccessReviewAuthorizer) buildCheckRequest(ctx context.Context, attributes authorizer.Attributes, authCtx *authorizationContext) (*openfgav1.CheckRequest, error) {
	user := fmt.Sprintf("iam.miloapis.com/InternalUser:%s", authCtx.userUID)
	relation := o.buildHashedPermissionRelation(attributes)

	resource, err := o.buildResourceObject(ctx, attributes, authCtx)
	if err != nil {
		return nil, err
	}

	var modelID string
	if o.ModelIDWatcher != nil {
		modelID = o.ModelIDWatcher.GetModelID()
	}

	return &openfgav1.CheckRequest{
		StoreId:              o.FGAStoreID,
		AuthorizationModelId: modelID,
		TupleKey: &openfgav1.CheckRequestTupleKey{
			User:     user,
			Relation: relation,
			Object:   resource,
		},
		// No contextual tuples — all relationships are stored tuples written at
		// PolicyBinding reconciliation time, making them eligible for OpenFGA's
		// check query cache.
	}, nil
}

// executeBatchCheck executes an OpenFGA BatchCheck for a specific-resource
// operation that may be covered by either a ResourceRef (instance-level) or
// ResourceKind (Root-level) PolicyBinding. It sends both checks in a single
// RPC and allows access if either result is allowed. Additional check items
// (e.g. project-root for staff bindings) can be passed via extraChecks.
func (o *SubjectAccessReviewAuthorizer) executeBatchCheck(
	ctx context.Context,
	checkReq *openfgav1.CheckRequest,
	rootResource string,
	extraChecks ...*openfgav1.BatchCheckItem,
) (authorizer.Decision, string, error) {
	tracer := otel.GetTracerProvider().Tracer("authz-webhook")
	ctx, batchSpan := tracer.Start(ctx, "openfga.batch_check")
	batchSpan.SetAttributes(
		attribute.String("openfga.store_id", o.FGAStoreID),
		attribute.String("openfga.user", checkReq.TupleKey.User),
		attribute.String("openfga.relation", checkReq.TupleKey.Relation),
		attribute.String("openfga.object_instance", checkReq.TupleKey.Object),
		attribute.String("openfga.object_root", rootResource),
	)
	defer batchSpan.End()

	logf.FromContext(ctx).Info("batch checking OpenFGA authorization",
		"user", checkReq.TupleKey.User,
		"relation", checkReq.TupleKey.Relation,
		"instance", checkReq.TupleKey.Object,
		"root", rootResource,
	)

	checks := make([]*openfgav1.BatchCheckItem, 0, 2+len(extraChecks))
	checks = append(checks,
		&openfgav1.BatchCheckItem{
			TupleKey: &openfgav1.CheckRequestTupleKey{
				User:     checkReq.TupleKey.User,
				Relation: checkReq.TupleKey.Relation,
				Object:   checkReq.TupleKey.Object,
			},
			CorrelationId: "instance",
		},
		&openfgav1.BatchCheckItem{
			TupleKey: &openfgav1.CheckRequestTupleKey{
				User:     checkReq.TupleKey.User,
				Relation: checkReq.TupleKey.Relation,
				Object:   rootResource,
			},
			CorrelationId: "root",
		},
	)
	checks = append(checks, extraChecks...)

	batchResp, err := o.FGAClient.BatchCheck(ctx, &openfgav1.BatchCheckRequest{
		StoreId:              o.FGAStoreID,
		AuthorizationModelId: checkReq.AuthorizationModelId,
		Checks:               checks,
	})
	if err != nil {
		openfgaCheckTotal.WithLabelValues("false", "true").Inc()
		batchSpan.RecordError(err)
		batchSpan.SetStatus(codes.Error, err.Error())
		logf.FromContext(ctx).Error(err, "failed to batch check authorization in OpenFGA")
		return authorizer.DecisionNoOpinion, "", err
	}

	// Allow if either the instance check or the Root (ResourceKind) check allows.
	allowed := false
	for _, result := range batchResp.GetResult() {
		if result.GetAllowed() {
			allowed = true
			break
		}
	}

	openfgaCheckTotal.WithLabelValues(strconv.FormatBool(allowed), "false").Inc()
	batchSpan.SetAttributes(attribute.Bool("openfga.allowed", allowed))

	if allowed {
		logf.FromContext(ctx).V(1).Info("subject was granted access through OpenFGA batch check")
		return authorizer.DecisionAllow, "", nil
	}

	return authorizer.DecisionDeny, "", nil
}

// buildResourceObject determines the OpenFGA object string for the request.
//
// The lookup priority is:
//  1. Project-scoped requests → authorize against the project object.
//  2. Requests with a specific resource name → authorize against that instance.
//  3. Collection operations with a parent context → authorize against the parent.
//  4. Collection operations without a parent → authorize against the kind-level
//     root object (TypeRoot:<apiGroup/Kind>).
func (o *SubjectAccessReviewAuthorizer) buildResourceObject(ctx context.Context, attributes authorizer.Attributes, authCtx *authorizationContext) (string, error) {
	// Project-scoped requests are resolved against the project.
	if authCtx.isProjectScope() {
		return fmt.Sprintf("resourcemanager.miloapis.com/Project:%s", authCtx.getProjectName()), nil
	}

	// Organization-scoped requests are resolved against the organization.
	if authCtx.isOrganizationScope() {
		return fmt.Sprintf("resourcemanager.miloapis.com/Organization:%s", authCtx.getOrganizationName()), nil
	}

	protectedResource, err := o.getProtectedResource(ctx, attributes)
	if err != nil {
		return "", fmt.Errorf("failed to get protected resource: %w", err)
	}

	// Specific resource operations — resolve to the named instance.
	isCollectionOp := slices.Contains([]string{"list", "create", "watch"}, attributes.GetVerb()) || attributes.GetName() == ""
	if !isCollectionOp {
		return fmt.Sprintf("%s/%s:%s", protectedResource.Spec.ServiceRef.Name, protectedResource.Spec.Kind, attributes.GetName()), nil
	}

	// Collection operations — use parent if available, else kind-level root.
	parentResource, err := o.buildParentResource(attributes)
	if err == nil {
		return parentResource, nil
	}

	// Fallback: kind-level root for ResourceKind policy bindings.
	return o.buildRootResource(protectedResource), nil
}

// validatePermissionWithServiceDefaulting validates permissions with consistent service name defaulting.
// It uses the in-memory ProtectedResourceCache for O(1) lookups instead of a K8s API List call.
func (o *SubjectAccessReviewAuthorizer) validatePermissionWithServiceDefaulting(ctx context.Context, attributes authorizer.Attributes) (bool, error) {
	tracer := otel.GetTracerProvider().Tracer("authz-webhook")
	ctx, cacheSpan := tracer.Start(ctx, "cache.get.ProtectedResource/validatePermission")
	defer cacheSpan.End()

	apiGroup := o.getEffectiveAPIGroup(attributes)
	resource := attributes.GetResource()
	verb := attributes.GetVerb()

	stepStart := time.Now()
	pr, ok := o.ProtectedResourceCache.GetByAPIGroupAndResource(apiGroup, resource)
	duration := time.Since(stepStart)

	authzStepDuration.WithLabelValues("protectedresource_cache_lookup").Observe(duration.Seconds())

	if ok {
		authzK8sAPICallsTotal.WithLabelValues("protectedresources", "cache_get", "hit").Inc()
		logf.FromContext(ctx).V(1).Info("protectedresource cache hit (validatePermission)",
			"apiGroup", apiGroup,
			"resource", resource,
			"duration", duration,
		)
		return slices.Contains(pr.Spec.Permissions, verb), nil
	}

	authzK8sAPICallsTotal.WithLabelValues("protectedresources", "cache_get", "miss").Inc()
	logf.FromContext(ctx).V(1).Info("protectedresource cache miss (validatePermission)",
		"apiGroup", apiGroup,
		"resource", resource,
		"duration", duration,
	)
	return false, nil
}

// getEffectiveAPIGroup returns the API group with service name mapping applied consistently
func (o *SubjectAccessReviewAuthorizer) getEffectiveAPIGroup(attributes authorizer.Attributes) string {
	apiGroup := attributes.GetAPIGroup()

	// Apply service name mapping for any api groups that need adjusting before
	// building the permission string.
	if override, exists := serviceNameMapping[apiGroup]; exists {
		return override
	}

	return apiGroup
}

// buildPermissionString constructs the permission string in the format: service/resource.verb
func (o *SubjectAccessReviewAuthorizer) buildPermissionString(attributes authorizer.Attributes) string {
	apiGroup := o.getEffectiveAPIGroup(attributes)
	resource := attributes.GetResource()
	verb := attributes.GetVerb()
	return fmt.Sprintf("%s/%s.%s", apiGroup, resource, verb)
}

func (o *SubjectAccessReviewAuthorizer) buildParentResource(attributes authorizer.Attributes) (string, error) {
	extra := attributes.GetUser().GetExtra()

	// If a parent is in the context, add a tuple for its parent relationship
	parentAPIGroup, parentAPIGroupOK := extra[iamv1alpha1.ParentAPIGroupExtraKey]
	parentKind, parentKindOK := extra[iamv1alpha1.ParentKindExtraKey]
	parentName, parentNameOK := extra[iamv1alpha1.ParentNameExtraKey]

	if parentAPIGroupOK && parentKindOK && parentNameOK {
		if len(parentAPIGroup) == 1 && len(parentKind) == 1 && len(parentName) == 1 {
			return fmt.Sprintf("%s/%s:%s", parentAPIGroup[0], parentKind[0], parentName[0]), nil
		}
	}

	return "", fmt.Errorf("parent resource not found in extra data")
}

// buildRootResource constructs a root resource string for ResourceKind policy bindings
// when no parent resource is available in the request context
func (o *SubjectAccessReviewAuthorizer) buildRootResource(protectedResource *iamv1alpha1.ProtectedResource) string {
	// Root resource format: "iam.miloapis.com/Root:{resource_type}"
	// where resource_type is "{APIGroup}/{Kind}" format used by the authorization model
	resourceType := fmt.Sprintf("%s/%s", protectedResource.Spec.ServiceRef.Name, protectedResource.Spec.Kind)
	return fmt.Sprintf("iam.miloapis.com/Root:%s", resourceType)
}

// buildHashedPermissionRelation builds a hashed permission relation for OpenFGA
func (o *SubjectAccessReviewAuthorizer) buildHashedPermissionRelation(attributes authorizer.Attributes) string {
	// Build permission in the format expected by OpenFGA: service/resource.verb
	permission := o.buildPermissionString(attributes)

	// Hash the permission to match the OpenFGA model
	hashedPermission := openfga.HashPermission(permission)
	logf.Log.V(1).Info("buildRelation",
		"permission", permission,
		"hashedPermission", hashedPermission,
		"apiGroup", attributes.GetAPIGroup(),
		"resource", attributes.GetResource(),
		"verb", attributes.GetVerb(),
	)
	return hashedPermission
}

// getProtectedResource retrieves the ProtectedResource for the given attributes.
// It uses the in-memory ProtectedResourceCache for O(1) lookups instead of a K8s API List call.
func (o *SubjectAccessReviewAuthorizer) getProtectedResource(ctx context.Context, attributes authorizer.Attributes) (*iamv1alpha1.ProtectedResource, error) {
	tracer := otel.GetTracerProvider().Tracer("authz-webhook")
	ctx, cacheSpan := tracer.Start(ctx, "cache.get.ProtectedResource/buildRequest")
	defer cacheSpan.End()

	apiGroup := o.getEffectiveAPIGroup(attributes)
	resource := attributes.GetResource()

	stepStart := time.Now()
	pr, ok := o.ProtectedResourceCache.GetByAPIGroupAndResource(apiGroup, resource)
	duration := time.Since(stepStart)

	authzStepDuration.WithLabelValues("protectedresource_cache_lookup").Observe(duration.Seconds())

	if ok {
		authzK8sAPICallsTotal.WithLabelValues("protectedresources", "cache_get", "hit").Inc()
		logf.FromContext(ctx).V(1).Info("protectedresource cache hit (buildRequest)",
			"apiGroup", apiGroup,
			"resource", resource,
			"duration", duration,
		)
		return pr, nil
	}

	authzK8sAPICallsTotal.WithLabelValues("protectedresources", "cache_get", "miss").Inc()
	logf.FromContext(ctx).V(1).Info("protectedresource cache miss (buildRequest)",
		"apiGroup", apiGroup,
		"resource", resource,
		"duration", duration,
	)
	return nil, fmt.Errorf("no ProtectedResource found for APIGroup=%s, Resource=%s", apiGroup, resource)
}

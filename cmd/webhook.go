package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/spf13/cobra"
	_ "go.miloapis.com/auth-provider-openfga/internal/features" // register feature gates
	"go.miloapis.com/auth-provider-openfga/internal/telemetry"
	"go.miloapis.com/auth-provider-openfga/internal/webhook"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/api/authentication/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/discovery/cached/disk"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
)

func createWebhookCommand() *cobra.Command {
	var certDir, certFile, keyFile string
	var openfgaAPIURL string
	var openfgaStoreID string
	var openfgaScheme string
	var webhookPort int
	var metricsBindAddress string
	var discoveryCacheTTL time.Duration
	var otlpEndpoint string
	var configmapNamespace string
	var configmapName string

	cmd := &cobra.Command{
		Use:   "authz-webhook",
		Short: "Start the OpenFGA authorization webhook server",
		Long:  "Start the authorization webhook server that validates SubjectAccessReview requests using OpenFGA.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runWebhookServer(
				certDir,
				certFile,
				keyFile,
				openfgaAPIURL,
				openfgaStoreID,
				openfgaScheme,
				webhookPort,
				metricsBindAddress,
				discoveryCacheTTL,
				otlpEndpoint,
				configmapNamespace,
				configmapName,
			)
		},
	}

	cmd.Flags().StringVar(&certDir, "cert-dir", "/etc/certs",
		"Directory that contains the TLS certs to use for serving the webhook")
	cmd.Flags().StringVar(&certFile, "cert-file", "tls.crt", "Filename in the directory that contains the TLS cert")
	cmd.Flags().StringVar(&keyFile, "key-file", "tls.key", "Filename in the directory that contains the TLS private key")
	cmd.Flags().StringVar(&openfgaAPIURL, "openfga-api-url", "",
		"OpenFGA API URL (e.g. localhost:8080 or api.us1.fga.dev)")
	cmd.Flags().StringVar(&openfgaStoreID, "openfga-store-id", "", "OpenFGA Store ID")
	cmd.Flags().StringVar(&openfgaScheme, "openfga-scheme", "http", "OpenFGA Scheme (http or https)")
	cmd.Flags().IntVar(&webhookPort, "webhook-port", 9443, "Port for the webhook server")
	cmd.Flags().StringVar(&metricsBindAddress, "metrics-bind-address", ":8080", "Address for the metrics server")
	cmd.Flags().DurationVar(&discoveryCacheTTL, "discovery-cache-ttl", 5*time.Minute,
		"TTL for Kubernetes API discovery cache (enables automatic detection of new resources)")
	cmd.Flags().StringVar(&otlpEndpoint, "otlp-endpoint", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		"OTLP HTTP endpoint for OpenTelemetry trace export (e.g. tempo:4318). Leave empty to disable tracing.")
	cmd.Flags().StringVar(&configmapNamespace, "configmap-namespace", os.Getenv("POD_NAMESPACE"),
		"Namespace to watch for the authorization model ConfigMap. Defaults to the POD_NAMESPACE environment variable.")
	cmd.Flags().StringVar(&configmapName, "configmap-name", "openfga-authorization-model",
		"Name of the ConfigMap that stores the current authorization model ID.")

	utilfeature.DefaultMutableFeatureGate.AddFlag(cmd.Flags())

	// Mark required flags
	if err := cmd.MarkFlagRequired("openfga-api-url"); err != nil {
		panic(fmt.Sprintf("failed to mark openfga-api-url as required: %v", err))
	}
	if err := cmd.MarkFlagRequired("openfga-store-id"); err != nil {
		panic(fmt.Sprintf("failed to mark openfga-store-id as required: %v", err))
	}

	return cmd
}

func runWebhookServer(
	certDir string,
	certFile string,
	keyFile string,
	openfgaAPIURL string,
	openfgaStoreID string,
	openfgaScheme string,
	webhookPort int,
	metricsBindAddress string,
	discoveryCacheTTL time.Duration,
	otlpEndpoint string,
	configmapNamespace string,
	configmapName string,
) error {
	log.SetLogger(zap.New(zap.JSONEncoder()))
	entryLog := log.Log.WithName("webhook-server")

	// Initialise OpenTelemetry tracing. When otlpEndpoint is empty a no-op
	// provider is installed and this is effectively free at runtime.
	ctx := context.Background()
	_, tracerShutdown, err := telemetry.SetupTracer(ctx, "auth-provider-openfga-webhook", "dev", otlpEndpoint)
	if err != nil {
		return fmt.Errorf("failed to setup tracer: %w", err)
	}
	defer func() {
		if shutdownErr := tracerShutdown(ctx); shutdownErr != nil {
			entryLog.Error(shutdownErr, "failed to shutdown tracer provider")
		}
	}()

	// Create OpenFGA client
	var creds credentials.TransportCredentials
	if strings.ToLower(openfgaScheme) == "https" {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(openfgaAPIURL,
		grpc.WithTransportCredentials(creds),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	)
	if err != nil {
		return fmt.Errorf("unable to create gRPC connection to OpenFGA: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			entryLog.Error(closeErr, "failed to close gRPC connection")
		}
	}()

	fgaClient := openfgav1.NewOpenFGAServiceClient(conn)

	// Setup Kubernetes client config
	restConfig, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get rest config: %w", err)
	}

	runtimeScheme := runtime.NewScheme()
	if err := corev1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add corev1 to scheme: %w", err)
	}
	if err := v1beta1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add v1beta1 to scheme: %w", err)
	}
	if err := resourcemanagerv1alpha1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add resourcemanagerv1alpha1 to scheme: %w", err)
	}
	if err := iamv1alpha1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add iamv1alpha1 to scheme: %w", err)
	}

	// Create temporary directory for discovery cache (will be cleaned up on process exit)
	tempDir, err := os.MkdirTemp("", "auth-provider-discovery-cache-")
	if err != nil {
		return fmt.Errorf("failed to create temporary cache directory: %w", err)
	}

	// Create TTL-aware cached discovery client using native disk cache
	discoveryClient, err := disk.NewCachedDiscoveryClientForConfig(restConfig, tempDir, "", discoveryCacheTTL)
	if err != nil {
		return fmt.Errorf("failed to create cached discovery client: %w", err)
	}

	// Setup Manager
	entryLog.Info("setting up manager")
	mgr, err := manager.New(restConfig, manager.Options{
		Scheme: runtimeScheme,
		Metrics: server.Options{
			BindAddress: metricsBindAddress,
		},
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			CertDir:  certDir,
			CertName: certFile,
			KeyName:  keyFile,
			Port:     webhookPort,
		}),
	})
	if err != nil {
		return fmt.Errorf("failed to setup manager: %w", err)
	}

	// Build the ProtectedResource informer cache. The cache is backed by the
	// manager's informer and starts empty; it will be populated once the
	// manager's cache syncs (i.e. after mgr.Start is called).
	prCache, err := webhook.NewProtectedResourceCache(ctx, mgr)
	if err != nil {
		return fmt.Errorf("failed to create ProtectedResource cache: %w", err)
	}

	// Build the authorization model ID watcher. It watches the
	// openfga-authorization-model ConfigMap and updates its cached model ID
	// whenever the controller-manager writes a new model. The watcher starts
	// with an empty seed — the first informer event after cache sync will
	// populate it.
	//
	// When running in-cluster the ConfigMap lives on the local workload cluster
	// (not the remote control plane pointed to by KUBECONFIG), so we prefer an
	// in-cluster informer when available.
	var modelIDWatcher *webhook.AuthorizationModelIDWatcher
	if inClusterCfg, inClusterErr := rest.InClusterConfig(); inClusterErr == nil {
		modelIDWatcher, err = webhook.NewAuthorizationModelIDWatcherWithConfig(ctx, inClusterCfg, configmapNamespace, configmapName, "")
	} else {
		modelIDWatcher, err = webhook.NewAuthorizationModelIDWatcher(ctx, mgr, configmapNamespace, configmapName, "")
	}
	if err != nil {
		return fmt.Errorf("failed to create authorization model ID watcher: %w", err)
	}

	// Setup webhooks
	entryLog.Info("setting up webhook server")
	hookServer := mgr.GetWebhookServer()

	entryLog.Info("registering webhooks to the webhook server")

	// Use the manager's cached client so ProtectedResource List calls are served
	// from the in-memory informer cache instead of making a network round-trip on
	// every SubjectAccessReview.
	webhook.RegisterSubjectAccessReviewWebhook(hookServer, webhook.Config{
		FGAClient:              fgaClient,
		FGAStoreID:             openfgaStoreID,
		ModelIDWatcher:         modelIDWatcher,
		ProtectedResourceCache: prCache,
		DiscoveryClient:        discoveryClient,
	})

	entryLog.Info("starting webhook server", "port", webhookPort, "metrics-port", metricsBindAddress)
	return mgr.Start(context.Background())
}

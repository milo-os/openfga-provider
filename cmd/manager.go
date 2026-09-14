package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/spf13/cobra"
	"go.miloapis.com/auth-provider-openfga/internal/controller"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	mcmanager "sigs.k8s.io/multicluster-runtime/pkg/manager"
	"sigs.k8s.io/multicluster-runtime/pkg/multicluster"
	mcsingle "sigs.k8s.io/multicluster-runtime/providers/single"

	"go.miloapis.com/auth-provider-openfga/internal/config"
	milomulticluster "go.miloapis.com/milo/pkg/multicluster-runtime"
	miloprovider "go.miloapis.com/milo/pkg/multicluster-runtime/milo"
)

func createManagerCommand() *cobra.Command {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var openfgaAPIURL string
	var openfgaStoreID string
	var openfgaScheme string

	// Leader election configuration options
	var leaderElectionID string
	var leaderElectionNamespace string
	var leaderElectionResourceLock string
	var leaseDuration time.Duration
	var renewDeadline time.Duration
	var retryPeriod time.Duration

	var configmapNamespace string
	var configmapName string

	var serverConfigFile string
	var upstreamClusterKubeconfig string
	var coreControlPlaneKubeconfig string
	var policyBindingMaxConcurrentReconciles int
	var openfgaTimeout time.Duration
	var openfgaKeepaliveTime time.Duration
	var openfgaKeepaliveTimeout time.Duration

	cmd := &cobra.Command{
		Use:   "manager",
		Short: "Start the controller manager",
		Long:  "Start the Kubernetes controller manager that reconciles IAM resources with OpenFGA.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runManager(
				metricsAddr,
				enableLeaderElection,
				probeAddr,
				openfgaAPIURL,
				openfgaStoreID,
				openfgaScheme,
				leaderElectionID,
				leaderElectionNamespace,
				leaderElectionResourceLock,
				leaseDuration,
				renewDeadline,
				retryPeriod,
				configmapNamespace,
				configmapName,
				serverConfigFile,
				upstreamClusterKubeconfig,
				coreControlPlaneKubeconfig,
				policyBindingMaxConcurrentReconciles,
				openfgaTimeout,
				openfgaKeepaliveTime,
				openfgaKeepaliveTimeout,
			)
		},
	}

	cmd.Flags().StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	cmd.Flags().StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	cmd.Flags().BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Ensuring that only one instance of the controller manager runs.")

	// Leader election configuration flags
	cmd.Flags().StringVar(&leaderElectionID, "leader-election-id", "4b85f171.miloapis.com", "The name of the resource that leader election will use for holding the leader lock.")
	cmd.Flags().StringVar(&leaderElectionNamespace, "leader-election-namespace", "", "Namespace to use for leader election. If empty, the controller will discover the namespace it is running in.")
	cmd.Flags().StringVar(&leaderElectionResourceLock, "leader-election-resource-lock", "leases", "The type of resource object that is used for locking during leader election. Supported options are 'leases', 'endpointsleases' and 'configmapsleases'.")
	cmd.Flags().DurationVar(&leaseDuration, "leader-election-lease-duration", 15*time.Second, "The duration that non-leader candidates will wait after observing a leadership renewal until attempting to acquire leadership of a led but unrenewed leader slot.")
	cmd.Flags().DurationVar(&renewDeadline, "leader-election-renew-deadline", 10*time.Second, "The interval between attempts by the acting master to renew a leadership slot before it stops leading.")
	cmd.Flags().DurationVar(&retryPeriod, "leader-election-retry-period", 2*time.Second, "The duration the clients should wait between attempting acquisition and renewal of a leadership.")

	cmd.Flags().StringVar(&openfgaAPIURL, "openfga-api-url", "",
		"OpenFGA API URL (e.g. localhost:8080 or api.us1.fga.dev)")
	cmd.Flags().StringVar(&openfgaStoreID, "openfga-store-id", "", "OpenFGA Store ID")
	cmd.Flags().StringVar(&openfgaScheme, "openfga-scheme", "http", "OpenFGA Scheme (http or https)")
	cmd.Flags().StringVar(&configmapNamespace, "configmap-namespace", os.Getenv("POD_NAMESPACE"),
		"Namespace in which to create/update the authorization model ConfigMap. Defaults to the POD_NAMESPACE environment variable.")
	cmd.Flags().StringVar(&configmapName, "configmap-name", "openfga-authorization-model",
		"Name of the ConfigMap used to store the current authorization model ID.")
	cmd.Flags().StringVar(&serverConfigFile, "server-config", "", "path to the server config file")
	cmd.Flags().StringVar(&upstreamClusterKubeconfig, "upstream-kubeconfig", "", "Path to the kubeconfig file for the upstream cluster")
	cmd.Flags().StringVar(&coreControlPlaneKubeconfig, "core-control-plane-kubeconfig", "", "Path to the kubeconfig file for the core control plane cluster")
	cmd.Flags().IntVar(&policyBindingMaxConcurrentReconciles, "policybinding-max-concurrent-reconciles", 8,
		"Maximum number of concurrent PolicyBinding reconciles.")
	cmd.Flags().DurationVar(&openfgaTimeout, "openfga-timeout", 15*time.Second,
		"The timeout duration for OpenFGA API calls.")
	cmd.Flags().DurationVar(&openfgaKeepaliveTime, "openfga-keepalive-time", 30*time.Second,
		"The interval duration between keepalive pings to the OpenFGA server.")
	cmd.Flags().DurationVar(&openfgaKeepaliveTimeout, "openfga-keepalive-timeout", 10*time.Second,
		"The timeout duration to wait for a keepalive ping response from the OpenFGA server.")

	// Mark required flags
	if err := cmd.MarkFlagRequired("openfga-api-url"); err != nil {
		panic(fmt.Sprintf("failed to mark openfga-api-url as required: %v", err))
	}
	if err := cmd.MarkFlagRequired("openfga-store-id"); err != nil {
		panic(fmt.Sprintf("failed to mark openfga-store-id as required: %v", err))
	}

	return cmd
}

//nolint:gocyclo
func runManager(
	metricsAddr string,
	enableLeaderElection bool,
	probeAddr string,
	openfgaAPIURL string,
	openfgaStoreID string,
	openfgaScheme string,
	leaderElectionID string,
	leaderElectionNamespace string,
	leaderElectionResourceLock string,
	leaseDuration time.Duration,
	renewDeadline time.Duration,
	retryPeriod time.Duration,
	configmapNamespace string,
	configmapName string,
	serverConfigFile string,
	upstreamClusterKubeconfig string,
	coreControlPlaneKubeconfig string,
	policyBindingMaxConcurrentReconciles int,
	openfgaTimeout time.Duration,
	openfgaKeepaliveTime time.Duration,
	openfgaKeepaliveTimeout time.Duration,
) error {
	opts := zap.Options{
		Development: true,
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	codecs := serializer.NewCodecFactory(scheme, serializer.EnableStrict)
	var serverConfig config.AuthProviderOpenFGA
	if serverConfigFile == "" {
		setupLog.Info("No --server-config provided, defaulting to single cluster discovery mode")
		serverConfig.Discovery.Mode = milomulticluster.ProviderSingle
	} else {
		data, err := os.ReadFile(serverConfigFile)
		if err != nil {
			return fmt.Errorf("unable to read server config from %q", serverConfigFile)
		}
		if err := runtime.DecodeInto(codecs.UniversalDecoder(), data, &serverConfig); err != nil {
			return fmt.Errorf("unable to decode server config: %w", err)
		}
	}

	var err error
	var upstreamClusterConfig *rest.Config
	if upstreamClusterKubeconfig != "" {
		upstreamClusterConfig, err = clientcmd.BuildConfigFromFlags("", upstreamClusterKubeconfig)
		if err != nil {
			return fmt.Errorf("unable to load upstream kubeconfig: %w", err)
		}
	} else {
		upstreamClusterConfig = ctrl.GetConfigOrDie()
	}

	var coreControlPlaneConfig *rest.Config
	if coreControlPlaneKubeconfig != "" {
		coreControlPlaneConfig, err = clientcmd.BuildConfigFromFlags("", coreControlPlaneKubeconfig)
		if err != nil {
			return fmt.Errorf("unable to load core control plane kubeconfig: %w", err)
		}
	} else {
		coreControlPlaneConfig = ctrl.GetConfigOrDie()
	}

	if openfgaAPIURL == "" {
		return fmt.Errorf("OpenFGA API URL must be provided via --openfga-api-url")
	}

	if openfgaStoreID == "" {
		return fmt.Errorf("OpenFGA Store ID must be provided via --openfga-store-id")
	}

	var creds credentials.TransportCredentials
	if strings.ToLower(openfgaScheme) == "https" {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(openfgaAPIURL,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                openfgaKeepaliveTime,
			Timeout:             openfgaKeepaliveTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithUnaryInterceptor(timeoutUnaryInterceptor(openfgaTimeout)),
	)
	if err != nil {
		return fmt.Errorf("unable to create gRPC connection to OpenFGA: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			ctrl.Log.Error(closeErr, "failed to close gRPC connection")
		}
	}()

	fgaClient := openfgav1.NewOpenFGAServiceClient(conn)

	deploymentClusterConfig := ctrl.GetConfigOrDie()

	deploymentCluster, err := cluster.New(deploymentClusterConfig, func(o *cluster.Options) {
		o.Scheme = scheme
	})
	if err != nil {
		return fmt.Errorf("failed to construct downstream cluster: %w", err)
	}

	runnables, provider, err := initializeClusterDiscovery(serverConfig, deploymentCluster, scheme)
	if err != nil {
		return fmt.Errorf("unable to initialize cluster discovery: %w", err)
	}

	coreControlPlaneCluster, err := cluster.New(coreControlPlaneConfig, func(o *cluster.Options) {
		o.Scheme = scheme
	})
	if err != nil {
		return fmt.Errorf("failed to construct core control plane cluster: %w", err)
	}
	runnables = append(runnables, coreControlPlaneCluster)

	// mcMgr is the primary manager. It owns leader election, metrics, and
	// health probes. All multicluster controllers (ServiceAccount) register here.
	mcMgr, err := mcmanager.New(upstreamClusterConfig, provider, ctrl.Options{
		Scheme:                     scheme,
		Metrics:                    metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:     probeAddr,
		LeaderElection:             enableLeaderElection,
		LeaderElectionID:           leaderElectionID,
		LeaderElectionNamespace:    leaderElectionNamespace,
		LeaderElectionResourceLock: leaderElectionResourceLock,
		LeaseDuration:              &leaseDuration,
		RenewDeadline:              &renewDeadline,
		RetryPeriod:                &retryPeriod,
	})
	if err != nil {
		return fmt.Errorf("unable to start multicluster manager: %w", err)
	}

	// localMgr is the secondary manager for local controllers (Role, PolicyBinding,
	// etc.). It delegates leader election to mcMgr and disables its own metrics
	// and health endpoints — the global metrics registry means all metrics are
	// available via mcMgr's endpoint.
	localMgr, err := ctrl.NewManager(coreControlPlaneConfig, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		HealthProbeBindAddress: "0",
		LeaderElection:         false,
	})
	if err != nil {
		return fmt.Errorf("unable to create local manager: %w", err)
	}

	if err = (&controller.RoleReconciler{
		Client:        localMgr.GetClient(),
		Scheme:        localMgr.GetScheme(),
		FgaClient:     fgaClient,
		StoreID:       openfgaStoreID,
		EventRecorder: localMgr.GetEventRecorderFor("role-controller"),
	}).SetupWithManager(localMgr); err != nil {
		return fmt.Errorf("unable to create controller Role: %w", err)
	}

	if err = (&controller.PolicyBindingReconciler{
		Client:                  localMgr.GetClient(),
		Scheme:                  localMgr.GetScheme(),
		FgaClient:               fgaClient,
		StoreID:                 openfgaStoreID,
		EventRecorder:           localMgr.GetEventRecorderFor("policybinding-controller"),
		MaxConcurrentReconciles: policyBindingMaxConcurrentReconciles,
	}).SetupWithManager(localMgr); err != nil {
		return fmt.Errorf("unable to create controller PolicyBinding: %w", err)
	}

	if err = (&controller.ResourceOwnerHierarchyReconciler{
		Client:        localMgr.GetClient(),
		Scheme:        localMgr.GetScheme(),
		FGAClient:     fgaClient,
		FGAStoreID:    openfgaStoreID,
		EventRecorder: localMgr.GetEventRecorderFor("resourceownerhierarchy-controller"),
	}).SetupWithManager(localMgr); err != nil {
		return fmt.Errorf("unable to create controller ResourceOwnerHierarchy: %w", err)
	}

	// Create an in-cluster client for ConfigMap operations. The manager's
	// primary client uses KUBECONFIG which may point to a remote control plane,
	// but the ConfigMap must be written to the local workload cluster where the
	// webhook pod watches it.
	var configMapClient client.Client
	if inClusterConfig, inClusterErr := rest.InClusterConfig(); inClusterErr == nil {
		configMapClient, err = client.New(inClusterConfig, client.Options{Scheme: scheme})
		if err != nil {
			return fmt.Errorf("unable to create in-cluster client for ConfigMap: %w", err)
		}
	} else {
		setupLog.Info("in-cluster config not available, falling back to manager client for ConfigMap operations")
	}

	if err = (&controller.AuthorizationModelReconciler{
		Client:             localMgr.GetClient(),
		Scheme:             localMgr.GetScheme(),
		FGAClient:          fgaClient,
		FGAStoreID:         openfgaStoreID,
		ConfigMapNamespace: configmapNamespace,
		ConfigMapName:      configmapName,
		ConfigMapClient:    configMapClient,
	}).SetupWithManager(localMgr); err != nil {
		return fmt.Errorf("unable to create controller AuthorizationModel: %w", err)
	}

	if err = (&controller.GroupMembershipReconciler{
		Client:        localMgr.GetClient(),
		Scheme:        localMgr.GetScheme(),
		FgaClient:     fgaClient,
		StoreID:       openfgaStoreID,
		EventRecorder: localMgr.GetEventRecorderFor("groupmembership-controller"),
	}).SetupWithManager(localMgr); err != nil {
		return fmt.Errorf("unable to create controller GroupMembership: %w", err)
	}

	// SystemGroupReconciler registers the User controller on localMgr and the
	// ServiceAccount controller on mcMgr.
	if err = (&controller.SystemGroupReconciler{
		Client:     localMgr.GetClient(),
		Scheme:     localMgr.GetScheme(),
		FGAClient:  fgaClient,
		FGAStoreID: openfgaStoreID,
	}).SetupWithManagerMultiCluster(localMgr, mcMgr); err != nil {
		return fmt.Errorf("unable to create controller SystemGroup: %w", err)
	}

	//+kubebuilder:scaffold:builder

	if err := mcMgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	if err := mcMgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}

	// localMgr starts only after mcMgr wins leader election.
	if err := mcMgr.Add(&localManagerRunnable{
		mcMgr:    mcMgr,
		localMgr: localMgr,
	}); err != nil {
		return fmt.Errorf("unable to add local manager runnable: %w", err)
	}

	ctx := ctrl.SetupSignalHandler()
	g, ctx := errgroup.WithContext(ctx)

	for _, runnable := range runnables {
		g.Go(func() error {
			return ignoreCanceled(runnable.Start(ctx))
		})
	}

	// Run the provider, which calls Engage to register the cluster with mcMgr.
	setupLog.Info("starting cluster provider")
	g.Go(func() error {
		return ignoreCanceled(provider.Run(ctx, mcMgr))
	})

	setupLog.Info("starting multicluster manager")
	g.Go(func() error {
		return ignoreCanceled(mcMgr.Start(ctx))
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("manager error: %w", err)
	}

	return nil
}

type runnableProvider interface {
	multicluster.Provider
	Run(context.Context, mcmanager.Manager) error
}

// localManagerRunnable starts the local manager only after the primary
// multicluster manager has won leader election.
type localManagerRunnable struct {
	mcMgr    mcmanager.Manager
	localMgr manager.Manager
}

func (r *localManagerRunnable) Start(ctx context.Context) error {
	<-r.mcMgr.Elected()
	setupLog.Info("multicluster manager elected leader, starting local manager")
	return r.localMgr.Start(ctx)
}

func (r *localManagerRunnable) Engage(_ context.Context, _ string, _ cluster.Cluster) error {
	// No-op: the local manager does not manage project clusters.
	return nil
}

// Needed until we contribute the patch in the following PR again (need to sign CLA):
//
//	See: https://github.com/kubernetes-sigs/multicluster-runtime/pull/18
type wrappedSingleClusterProvider struct {
	multicluster.Provider
	cluster cluster.Cluster
}

func (p *wrappedSingleClusterProvider) Run(ctx context.Context, mgr mcmanager.Manager) error {
	if err := mgr.Engage(ctx, "single", p.cluster); err != nil {
		return err
	}
	return p.Provider.(runnableProvider).Run(ctx, mgr)
}

func initializeClusterDiscovery(
	serverConfig config.AuthProviderOpenFGA,
	deploymentCluster cluster.Cluster,
	scheme *runtime.Scheme,
) (runnables []manager.Runnable, provider runnableProvider, err error) {
	runnables = append(runnables, deploymentCluster)
	switch serverConfig.Discovery.Mode {
	case milomulticluster.ProviderSingle:
		provider = &wrappedSingleClusterProvider{
			Provider: mcsingle.New("single", deploymentCluster),
			cluster:  deploymentCluster,
		}

	case milomulticluster.ProviderMilo:
		discoveryRestConfig, err := serverConfig.Discovery.DiscoveryRestConfig()
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get discovery rest config: %w", err)
		}

		projectRestConfig, err := serverConfig.Discovery.ProjectRestConfig()
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get project rest config: %w", err)
		}

		discoveryManager, err := manager.New(discoveryRestConfig, manager.Options{
			Client: client.Options{
				Cache: &client.CacheOptions{
					Unstructured: true,
				},
			},
			Metrics:                metricsserver.Options{BindAddress: "0"},
			HealthProbeBindAddress: "0",
		})
		if err != nil {
			return nil, nil, fmt.Errorf("unable to set up overall controller manager: %w", err)
		}

		provider, err = miloprovider.New(discoveryManager, miloprovider.Options{
			ClusterOptions: []cluster.Option{
				func(o *cluster.Options) {
					o.Scheme = scheme
				},
			},
			InternalServiceDiscovery: serverConfig.Discovery.InternalServiceDiscovery,
			ProjectRestConfig:        projectRestConfig,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("unable to create datum project provider: %w", err)
		}

		runnables = append(runnables, discoveryManager)

	default:
		return nil, nil, fmt.Errorf(
			"unsupported cluster discovery mode %s",
			serverConfig.Discovery.Mode,
		)
	}

	return runnables, provider, nil
}

func ignoreCanceled(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func timeoutUnaryInterceptor(timeout time.Duration) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

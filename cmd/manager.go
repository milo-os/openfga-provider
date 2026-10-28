package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/spf13/cobra"
	"go.miloapis.com/auth-provider-openfga/internal/controller"
	_ "go.miloapis.com/auth-provider-openfga/internal/features" // register feature gates
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/rest"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
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
) error {
	opts := zap.Options{
		Development: true,
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

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

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
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
		return fmt.Errorf("unable to start manager: %w", err)
	}

	if err = (&controller.RoleReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		FgaClient:     fgaClient,
		StoreID:       openfgaStoreID,
		EventRecorder: mgr.GetEventRecorderFor("role-controller"),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create controller Role: %w", err)
	}

	if err = (&controller.PolicyBindingReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		FgaClient:     fgaClient,
		StoreID:       openfgaStoreID,
		EventRecorder: mgr.GetEventRecorderFor("policybinding-controller"),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create controller PolicyBinding: %w", err)
	}

	if err = (&controller.ResourceOwnerHierarchyReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		FGAClient:     fgaClient,
		FGAStoreID:    openfgaStoreID,
		EventRecorder: mgr.GetEventRecorderFor("resourceownerhierarchy-controller"),
		// AuthzModelReconciler initialization removed as it's no longer a field here
	}).SetupWithManager(mgr); err != nil {
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

	// Add the new AuthorizationModelReconciler
	if err = (&controller.AuthorizationModelReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		FGAClient:          fgaClient,
		FGAStoreID:         openfgaStoreID,
		ConfigMapNamespace: configmapNamespace,
		ConfigMapName:      configmapName,
		ConfigMapClient:    configMapClient,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create controller AuthorizationModel: %w", err)
	}

	if err = (&controller.GroupMembershipReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		FgaClient:     fgaClient,
		StoreID:       openfgaStoreID,
		EventRecorder: mgr.GetEventRecorderFor("groupmembership-controller"),
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create controller GroupMembership: %w", err)
	}

	if err = (&controller.SystemGroupReconciler{
		Client:     mgr.GetClient(),
		Scheme:     mgr.GetScheme(),
		FGAClient:  fgaClient,
		FGAStoreID: openfgaStoreID,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to create controller SystemGroup: %w", err)
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}

	return nil
}

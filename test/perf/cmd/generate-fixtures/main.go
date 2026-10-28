// generate-fixtures is a standalone Go program that populates an OpenFGA store
// with scale-test fixtures. It supports two modes controlled by the PERF_MODE
// environment variable:
//
//   - PERF_MODE=direct (default) — writes OpenFGA tuples directly, bypassing
//     Kubernetes controller reconciliation. Fast but does not exercise the full
//     control plane.
//
//   - PERF_MODE=reconcile — creates actual Kubernetes CRDs (User, Role,
//     Organization, PolicyBinding) and waits for the controllers to reconcile
//     them into OpenFGA. Exercises the full control plane: CRD creation →
//     controller reconciliation → OpenFGA tuple writes → authorization checks.
//
// ProtectedResource CRDs are always created as actual Kubernetes objects because
// the webhook's ProtectedResourceCache validates permissions against them before
// building the OpenFGA check request.
//
// Usage:
//
//	OPENFGA_STORE_ID=<id> go run ./test/perf/cmd/generate-fixtures/
//	PERF_MODE=reconcile go run ./test/perf/cmd/generate-fixtures/
//
// All scale parameters are configured via environment variables. See the Config
// struct for the full list.
//
// Cleanup:
//
//	PERF_CLEANUP=true go run ./test/perf/cmd/generate-fixtures/
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	internalopenfga "go.miloapis.com/auth-provider-openfga/internal/openfga"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// OpenFGA hard limit on tuples per Write request.
const maxBatchSize = 100

// crdBatchSize is the number of Kubernetes resources to apply per kubectl call
// in reconcile mode.
const crdBatchSize = 50

// Config holds all scale parameters read from environment variables.
type Config struct {
	// Mode controls whether the generator writes tuples directly ("direct") or
	// creates Kubernetes CRDs and waits for controller reconciliation
	// ("reconcile").
	Mode string

	// Cleanup, when true, deletes all CRDs with the perf-test=scale label
	// instead of generating fixtures.
	Cleanup bool

	// OpenFGA connection (used in direct mode and Phase 2 model wait)
	OpenFGAAPIURL string
	StoreID       string

	// Scale parameters
	NumOrgs            int
	NumProjectsPerOrg  int
	NumUsers           int
	NumRoles           int
	PermissionsPerRole int
	MembershipsPerUser int
	NumPRTypes         int

	// Concurrency (direct mode only)
	Workers int

	// Tool paths
	Kubectl string

	// Output
	ManifestPath string
}

// ScaleManifest is written to ManifestPath after generation and read by the
// k6 scale test to select valid (user, org, project) targets.
type ScaleManifest struct {
	GeneratedAt string         `json:"generated_at"`
	Params      ManifestParams `json:"params"`
	// NumProjectsPerOrg is a top-level convenience field for k6 scripts that
	// access manifest.num_projects_per_org directly without going through params.
	NumProjectsPerOrg  int                 `json:"num_projects_per_org"`
	Users              []string            `json:"users"`
	Organizations      []string            `json:"organizations"`
	Projects           []string            `json:"projects"`
	Roles              []string            `json:"roles"`
	Permissions        []string            `json:"permissions"`
	UserOrgMemberships map[string][]string `json:"user_org_memberships"`
	DeniedUser         string              `json:"denied_user"`
	TupleCount         int64               `json:"tuple_count"`
}

// ManifestParams records the scale parameters used during generation so
// readers can validate tuple counts against the expected formula.
type ManifestParams struct {
	NumOrgs            int `json:"num_orgs"`
	NumProjectsPerOrg  int `json:"num_projects_per_org"`
	NumUsers           int `json:"num_users"`
	NumRoles           int `json:"num_roles"`
	PermissionsPerRole int `json:"permissions_per_role"`
	OrgsPerUser        int `json:"orgs_per_user"`
}

func main() {
	cfg := loadConfig()

	// Cleanup mode: delete all resources labelled perf-test=scale.
	if cfg.Cleanup {
		runCleanup(cfg)
		return
	}

	fmt.Fprintf(os.Stderr, "Scale parameters:\n")
	fmt.Fprintf(os.Stderr, "  Mode:               %s\n", cfg.Mode)
	fmt.Fprintf(os.Stderr, "  NumOrgs:            %d\n", cfg.NumOrgs)
	fmt.Fprintf(os.Stderr, "  NumProjectsPerOrg:  %d\n", cfg.NumProjectsPerOrg)
	fmt.Fprintf(os.Stderr, "  NumUsers:           %d\n", cfg.NumUsers)
	fmt.Fprintf(os.Stderr, "  NumRoles:           %d\n", cfg.NumRoles)
	fmt.Fprintf(os.Stderr, "  PermissionsPerRole: %d\n", cfg.PermissionsPerRole)
	fmt.Fprintf(os.Stderr, "  MembershipsPerUser: %d\n", cfg.MembershipsPerUser)
	fmt.Fprintf(os.Stderr, "  NumPRTypes:         %d\n", cfg.NumPRTypes)
	fmt.Fprintf(os.Stderr, "  Workers:            %d\n", cfg.Workers)
	fmt.Fprintf(os.Stderr, "  StoreID:            %s\n", cfg.StoreID)
	fmt.Fprintf(os.Stderr, "  ManifestPath:       %s\n", cfg.ManifestPath)

	ctx := context.Background()

	switch cfg.Mode {
	case "reconcile":
		runReconcileMode(ctx, cfg)
	default:
		runDirectMode(ctx, cfg)
	}
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

// loadConfig reads scale parameters from environment variables.
func loadConfig() Config {
	cfg := Config{
		Mode:               envOrDefault("PERF_MODE", "direct"),
		Cleanup:            os.Getenv("PERF_CLEANUP") == "true",
		OpenFGAAPIURL:      envOrDefault("OPENFGA_API_URL", "localhost:8081"),
		StoreID:            os.Getenv("OPENFGA_STORE_ID"),
		NumOrgs:            envIntOrDefault("PERF_NUM_ORGS", 100),
		NumProjectsPerOrg:  envIntOrDefault("PERF_NUM_PROJECTS_PER_ORG", 10),
		NumUsers:           envIntOrDefault("PERF_NUM_USERS", 500),
		NumRoles:           envIntOrDefault("PERF_NUM_ROLES", 5),
		PermissionsPerRole: envIntOrDefault("PERF_PERMISSIONS_PER_ROLE", 10),
		MembershipsPerUser: envIntOrDefault("PERF_MEMBERSHIPS_PER_USER", 2),
		NumPRTypes:         envIntOrDefault("PERF_NUM_PR_TYPES", 1),
		Workers:            envIntOrDefault("PERF_WORKERS", 20),
		Kubectl:            envOrDefault("KUBECTL", "kubectl"),
		ManifestPath:       envOrDefault("PERF_MANIFEST_PATH", "test/perf/fixtures/scale-manifest.json"),
	}

	// MembershipsPerUser cannot exceed NumOrgs.
	if cfg.MembershipsPerUser > cfg.NumOrgs {
		cfg.MembershipsPerUser = cfg.NumOrgs
	}

	return cfg
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
		fmt.Fprintf(os.Stderr, "WARNING: invalid value for %s=%q, using default %d\n", key, v, def)
	}
	return def
}

// ---------------------------------------------------------------------------
// Cleanup mode
// ---------------------------------------------------------------------------

// runCleanup deletes all Kubernetes resources created in reconcile mode. It
// selects resources by the perf-test=scale label applied during generation.
func runCleanup(cfg Config) {
	fmt.Fprintln(os.Stderr, "Cleanup mode: deleting all resources with label perf-test=scale")

	resources := []string{
		"policybinding.iam.miloapis.com",
		"project.resourcemanager.miloapis.com",
		"organization.resourcemanager.miloapis.com",
		"user.iam.miloapis.com",
		"role.iam.miloapis.com",
		"protectedresource.iam.miloapis.com",
	}

	ctx := context.Background()
	for _, resource := range resources {
		fmt.Fprintf(os.Stderr, "  Deleting %s resources...\n", resource)
		//nolint:gosec // cfg.Kubectl is a controlled value
		cmd := exec.CommandContext(ctx, cfg.Kubectl, "delete", resource,
			"--selector=perf-test=scale",
			"--ignore-not-found",
			"--wait=false",
		)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "  WARNING: failed to delete %s: %v\n", resource, err)
		}
	}

	fmt.Fprintln(os.Stderr, "Cleanup complete.")
}

// ---------------------------------------------------------------------------
// Direct mode (original behavior)
// ---------------------------------------------------------------------------

func runDirectMode(ctx context.Context, cfg Config) {
	if cfg.StoreID == "" {
		fmt.Fprintln(os.Stderr, "ERROR: OPENFGA_STORE_ID is required in direct mode")
		os.Exit(1)
	}

	// Estimate tuple count so the operator knows what to expect.
	bindingTuples := int64(cfg.NumUsers) * int64(cfg.MembershipsPerUser) * 3
	roleTuples := int64(cfg.NumRoles) * int64(cfg.PermissionsPerRole)
	orgRootBindings := int64(cfg.NumOrgs)
	projTuples := int64(cfg.NumOrgs) * int64(cfg.NumProjectsPerOrg) * 2
	estimate := bindingTuples + roleTuples + orgRootBindings + projTuples
	fmt.Fprintf(os.Stderr, "\nEstimated tuple count: %d\n\n", estimate)

	// Connect to OpenFGA via gRPC.
	conn, err := grpc.NewClient(cfg.OpenFGAAPIURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to connect to OpenFGA at %s: %v\n", cfg.OpenFGAAPIURL, err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	client := openfgav1.NewOpenFGAServiceClient(conn)

	// Phase 1: Generate ProtectedResource CRDs via kubectl.
	fmt.Fprintln(os.Stderr, "Phase 1: Generating ProtectedResource CRDs...")
	if err := generateProtectedResources(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 1 failed: %v\n", err)
		os.Exit(1)
	}

	// Phase 2: Wait for authorization model to include the new resource types.
	fmt.Fprintln(os.Stderr, "Phase 2: Waiting for authorization model to stabilize...")
	if err := waitForAuthorizationModel(ctx, client, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 2 failed: %v\n", err)
		os.Exit(1)
	}

	var totalWritten atomic.Int64

	// Phase 3: Write InternalRole permission tuples.
	fmt.Fprintln(os.Stderr, "Phase 3: Writing InternalRole permission tuples...")
	roleTupleSlice := buildInternalRoleTuples(cfg)
	if err := writeTuplesBatched(ctx, client, cfg.StoreID, roleTupleSlice, cfg.Workers, &totalWritten); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 3 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Wrote %d role permission tuples\n", len(roleTupleSlice))

	// Phase 4: Write organization binding tuples.
	fmt.Fprintln(os.Stderr, "Phase 4: Writing organization binding tuples...")
	membershipMap := buildMembershipMap(cfg)
	orgBindingTuples := buildOrgBindingTuples(cfg, membershipMap)
	if err := writeTuplesBatched(ctx, client, cfg.StoreID, orgBindingTuples, cfg.Workers, &totalWritten); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 4 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Wrote %d org binding tuples\n", len(orgBindingTuples))

	// Phase 5: Write RootBinding tuples for organizations.
	fmt.Fprintln(os.Stderr, "Phase 5: Writing RootBinding tuples for organizations...")
	orgRootTuples := buildOrgRootBindingTuples(cfg)
	if err := writeTuplesBatched(ctx, client, cfg.StoreID, orgRootTuples, cfg.Workers, &totalWritten); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 5 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Wrote %d org root binding tuples\n", len(orgRootTuples))

	// Phase 6: Write project parent and RootBinding tuples.
	fmt.Fprintln(os.Stderr, "Phase 6: Writing project parent and RootBinding tuples...")
	projectTuples := buildProjectTuples(cfg)
	if err := writeTuplesBatched(ctx, client, cfg.StoreID, projectTuples, cfg.Workers, &totalWritten); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 6 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Wrote %d project tuples\n", len(projectTuples))

	membershipMap = buildMembershipMap(cfg)

	// Phase 7: Write the fixture manifest.
	fmt.Fprintln(os.Stderr, "Phase 7: Writing scale manifest...")
	manifest := buildManifest(cfg, membershipMap, totalWritten.Load())
	if err := writeManifest(manifest, cfg.ManifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 7 failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\nDone. Total tuples written: %d\n", totalWritten.Load())
	fmt.Fprintf(os.Stderr, "Manifest written to: %s\n", cfg.ManifestPath)
}

// ---------------------------------------------------------------------------
// Reconcile mode
// ---------------------------------------------------------------------------

// runReconcileMode creates Kubernetes CRDs and waits for the controllers to
// reconcile them into OpenFGA. This exercises the full control plane.
func runReconcileMode(ctx context.Context, cfg Config) {
	// Phase 1: Generate ProtectedResource CRDs.
	fmt.Fprintln(os.Stderr, "Phase 1: Generating ProtectedResource CRDs...")
	if err := generateProtectedResources(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 1 failed: %v\n", err)
		os.Exit(1)
	}

	// Phase 2: Wait for the authorization model to stabilize. This confirms the
	// ProtectedResource controllers have run. We only need this when an OpenFGA
	// URL is configured; skip if the operator hasn't set one.
	if cfg.StoreID != "" {
		conn, err := grpc.NewClient(cfg.OpenFGAAPIURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: failed to connect to OpenFGA at %s: %v\n", cfg.OpenFGAAPIURL, err)
			os.Exit(1)
		}
		defer func() { _ = conn.Close() }()
		client := openfgav1.NewOpenFGAServiceClient(conn)

		fmt.Fprintln(os.Stderr, "Phase 2: Waiting for authorization model to stabilize...")
		if err := waitForAuthorizationModel(ctx, client, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Phase 2 failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Phase 2: Skipping authorization model wait (OPENFGA_STORE_ID not set)")
	}

	// Phase 3: Create User CRDs.
	fmt.Fprintf(os.Stderr, "Phase 3: Creating %d User CRDs...\n", cfg.NumUsers)
	if err := createUserCRDs(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 3 failed: %v\n", err)
		os.Exit(1)
	}

	// Phase 4: Create Role CRDs and wait for them to be Ready.
	fmt.Fprintf(os.Stderr, "Phase 4: Creating %d Role CRDs...\n", cfg.NumRoles)
	if err := createRoleCRDs(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 4 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "Phase 4: Waiting for Roles to reach Ready...")
	if err := waitForRolesReady(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 4 wait failed: %v\n", err)
		os.Exit(1)
	}

	// Phase 5: Create Organization CRDs.
	fmt.Fprintf(os.Stderr, "Phase 5: Creating %d Organization CRDs...\n", cfg.NumOrgs)
	if err := createOrganizationCRDs(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 5 failed: %v\n", err)
		os.Exit(1)
	}

	// Phase 5b: Create Project CRDs. Projects must exist so the
	// ProjectOrganizationCache can map each project to its parent org when
	// the authorization webhook fans out project-scoped checks.
	totalProjects := cfg.NumOrgs * cfg.NumProjectsPerOrg
	fmt.Fprintf(os.Stderr, "Phase 5b: Creating %d Project CRDs (%d orgs × %d projects/org)...\n",
		totalProjects, cfg.NumOrgs, cfg.NumProjectsPerOrg)
	if err := createProjectCRDs(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 5b failed: %v\n", err)
		os.Exit(1)
	}

	// Read UIDs for Users and Organizations — PolicyBinding requires them.
	fmt.Fprintln(os.Stderr, "Phase 5c: Reading User and Organization UIDs...")
	userUIDs, err := readResourceUIDs(ctx, cfg, "user.iam.miloapis.com", cfg.NumUsers, "scale-user-%d")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to read User UIDs: %v\n", err)
		os.Exit(1)
	}
	orgUIDs, err := readResourceUIDs(ctx, cfg, "organization.resourcemanager.miloapis.com", cfg.NumOrgs, "scale-org-%d")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to read Organization UIDs: %v\n", err)
		os.Exit(1)
	}

	// Phase 6: Create PolicyBinding CRDs and wait for reconciliation.
	membershipMap := buildMembershipMap(cfg)
	totalBindings := cfg.NumUsers * cfg.MembershipsPerUser
	fmt.Fprintf(os.Stderr, "Phase 6: Creating %d PolicyBinding CRDs...\n", totalBindings)
	if err := createPolicyBindingCRDs(ctx, cfg, membershipMap, userUIDs, orgUIDs); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 6 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "Phase 6: Waiting for PolicyBindings to reach Ready...")
	if err := waitForPolicyBindingsReady(ctx, cfg, totalBindings); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 6 wait failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Phase 6: %d/%d PolicyBindings Ready\n", totalBindings, totalBindings)

	// Phase 7: Write the fixture manifest.
	fmt.Fprintln(os.Stderr, "Phase 7: Writing scale manifest...")
	manifest := buildManifest(cfg, membershipMap, 0)
	if err := writeManifest(manifest, cfg.ManifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 7 failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "\nDone. All CRDs reconciled and manifest written.")
	fmt.Fprintf(os.Stderr, "Manifest written to: %s\n", cfg.ManifestPath)
}

// ---------------------------------------------------------------------------
// Phase 1: ProtectedResource CRD generation (shared by both modes)
// ---------------------------------------------------------------------------

// protectedResourceTemplate generates ProtectedResource YAML for a single
// perf service. Service names follow the pattern perf-N.miloapis.com with
// resource kinds Resource0 through ResourceM.
var protectedResourceTemplate = template.Must(template.New("pr").Parse(`---
apiVersion: iam.miloapis.com/v1alpha1
kind: ProtectedResource
metadata:
  name: perf-service-{{.ServiceIdx}}-resource-{{.ResourceIdx}}
  labels:
    perf-test: scale
spec:
  serviceRef:
    name: "perf-{{.ServiceIdx}}.miloapis.com"
  kind: Resource{{.ResourceIdx}}
  plural: resource{{.ResourceIdx}}s
  singular: resource{{.ResourceIdx}}
  permissions:
    - get
    - list
    - create
    - update
    - delete
    - watch
    - patch
    - use
`))

func generateProtectedResources(ctx context.Context, cfg Config) error {
	var buf bytes.Buffer

	for i := 0; i < cfg.NumPRTypes; i++ {
		data := struct {
			ServiceIdx  int
			ResourceIdx int
		}{
			ServiceIdx:  i,
			ResourceIdx: i,
		}
		if err := protectedResourceTemplate.Execute(&buf, data); err != nil {
			return fmt.Errorf("failed to render ProtectedResource template for index %d: %w", i, err)
		}
	}

	// Write to a temp file and apply it.
	tmp, err := os.CreateTemp("", "perf-protected-resources-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// kubectl apply --server-side is idempotent.
	//nolint:gosec // cfg.Kubectl and tmp.Name() are controlled values
	cmd := exec.CommandContext(ctx, cfg.Kubectl, "apply", "--server-side", "-f", tmp.Name())
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl apply failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  Applied %d ProtectedResource CRDs\n", cfg.NumPRTypes)
	return nil
}

// ---------------------------------------------------------------------------
// Phase 2: Wait for authorization model (shared by both modes when StoreID set)
// ---------------------------------------------------------------------------

func waitForAuthorizationModel(ctx context.Context, client openfgav1.OpenFGAServiceClient, cfg Config) error {
	// Wait up to 5 minutes for the controller to update the authorization model.
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		models, err := client.ReadAuthorizationModels(ctx, &openfgav1.ReadAuthorizationModelsRequest{
			StoreId: cfg.StoreID,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ReadAuthorizationModels error (will retry): %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(models.AuthorizationModels) == 0 {
			fmt.Fprintln(os.Stderr, "  No authorization models found yet, waiting...")
			time.Sleep(5 * time.Second)
			continue
		}

		// Count types in the most recent model that match the perf service prefix.
		latest := models.AuthorizationModels[0]
		perfTypeCount := 0
		for _, td := range latest.TypeDefinitions {
			if strings.HasPrefix(td.Type, "perf-") {
				perfTypeCount++
			}
		}

		if perfTypeCount >= cfg.NumPRTypes {
			fmt.Fprintf(os.Stderr, "  Authorization model contains %d perf resource types (need %d) — ready\n", perfTypeCount, cfg.NumPRTypes)
			return nil
		}

		fmt.Fprintf(os.Stderr, "  Authorization model has %d/%d perf resource types, waiting...\n", perfTypeCount, cfg.NumPRTypes)
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("authorization model did not stabilize within 5 minutes")
}

// ---------------------------------------------------------------------------
// Reconcile mode: Phase 3 — User CRDs
// ---------------------------------------------------------------------------

func createUserCRDs(ctx context.Context, cfg Config) error {
	numBatches := (cfg.NumUsers + crdBatchSize - 1) / crdBatchSize
	for b := 0; b < numBatches; b++ {
		start := b * crdBatchSize
		end := start + crdBatchSize
		if end > cfg.NumUsers {
			end = cfg.NumUsers
		}
		fmt.Fprintf(os.Stderr, "  Phase 3: Creating %d User CRDs... (batch %d/%d)\n", cfg.NumUsers, b+1, numBatches)

		var buf bytes.Buffer
		for i := start; i < end; i++ {
			fmt.Fprintf(&buf, `---
apiVersion: iam.miloapis.com/v1alpha1
kind: User
metadata:
  name: scale-user-%d
  labels:
    perf-test: scale
spec:
  email: scale-user-%d@datum.net
`, i, i)
		}

		if err := kubectlApplyBuf(ctx, cfg, buf.Bytes()); err != nil {
			return fmt.Errorf("batch %d: %w", b+1, err)
		}
	}
	fmt.Fprintf(os.Stderr, "  Applied %d User CRDs\n", cfg.NumUsers)
	return nil
}

// ---------------------------------------------------------------------------
// Reconcile mode: Phase 4 — Role CRDs
// ---------------------------------------------------------------------------

func createRoleCRDs(ctx context.Context, cfg Config) error {
	numBatches := (cfg.NumRoles + crdBatchSize - 1) / crdBatchSize
	for b := 0; b < numBatches; b++ {
		start := b * crdBatchSize
		end := start + crdBatchSize
		if end > cfg.NumRoles {
			end = cfg.NumRoles
		}
		fmt.Fprintf(os.Stderr, "  Phase 4: Creating %d Role CRDs... (batch %d/%d)\n", cfg.NumRoles, b+1, numBatches)

		var buf bytes.Buffer
		for r := start; r < end; r++ {
			fmt.Fprintf(&buf, "---\napiVersion: iam.miloapis.com/v1alpha1\nkind: Role\nmetadata:\n  name: scale-role-%d\n  labels:\n    perf-test: scale\nspec:\n  launchStage: Beta\n  includedPermissions:\n", r)
			for p := 0; p < cfg.PermissionsPerRole; p++ {
				fmt.Fprintf(&buf, "    - %s\n", buildPermissionString(r, p))
			}
		}

		if err := kubectlApplyBuf(ctx, cfg, buf.Bytes()); err != nil {
			return fmt.Errorf("batch %d: %w", b+1, err)
		}
	}
	fmt.Fprintf(os.Stderr, "  Applied %d Role CRDs\n", cfg.NumRoles)
	return nil
}

// waitForRolesReady waits until all scale Roles have reached the Ready condition.
func waitForRolesReady(ctx context.Context, cfg Config) error {
	//nolint:gosec // cfg.Kubectl is a controlled value
	cmd := exec.CommandContext(ctx, cfg.Kubectl, "wait",
		"--for=condition=Ready",
		"role.iam.miloapis.com",
		"--selector=perf-test=scale",
		"--timeout=5m",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl wait for Roles failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Reconcile mode: Phase 5 — Organization CRDs
// ---------------------------------------------------------------------------

func createOrganizationCRDs(ctx context.Context, cfg Config) error {
	numBatches := (cfg.NumOrgs + crdBatchSize - 1) / crdBatchSize
	for b := 0; b < numBatches; b++ {
		start := b * crdBatchSize
		end := start + crdBatchSize
		if end > cfg.NumOrgs {
			end = cfg.NumOrgs
		}
		fmt.Fprintf(os.Stderr, "  Phase 5: Creating %d Organization CRDs... (batch %d/%d)\n", cfg.NumOrgs, b+1, numBatches)

		var buf bytes.Buffer
		for o := start; o < end; o++ {
			fmt.Fprintf(&buf, `---
apiVersion: resourcemanager.miloapis.com/v1alpha1
kind: Organization
metadata:
  name: scale-org-%d
  labels:
    perf-test: scale
spec:
  type: Standard
`, o)
		}

		if err := kubectlApplyBuf(ctx, cfg, buf.Bytes()); err != nil {
			return fmt.Errorf("batch %d: %w", b+1, err)
		}
	}
	fmt.Fprintf(os.Stderr, "  Applied %d Organization CRDs\n", cfg.NumOrgs)
	return nil
}

// ---------------------------------------------------------------------------
// Reconcile mode: Phase 5b — Project CRDs
// ---------------------------------------------------------------------------

// createProjectCRDs creates Project CRDs for each (org, project) pair. The
// ownerRef.name field links each project to its parent organization so the
// ProjectOrganizationCache can build the project → org index that the webhook
// uses for parallel project/org authorization checks.
func createProjectCRDs(ctx context.Context, cfg Config) error {
	total := cfg.NumOrgs * cfg.NumProjectsPerOrg
	numBatches := (total + crdBatchSize - 1) / crdBatchSize

	// Flatten (orgIdx, projIdx) pairs into a slice so we can batch uniformly.
	type projectEntry struct {
		orgIdx  int
		projIdx int
	}
	entries := make([]projectEntry, 0, total)
	for o := 0; o < cfg.NumOrgs; o++ {
		for p := 0; p < cfg.NumProjectsPerOrg; p++ {
			entries = append(entries, projectEntry{orgIdx: o, projIdx: p})
		}
	}

	for b := 0; b < numBatches; b++ {
		start := b * crdBatchSize
		end := start + crdBatchSize
		if end > total {
			end = total
		}
		fmt.Fprintf(os.Stderr, "  Phase 5b: Creating %d Project CRDs... (batch %d/%d)\n", total, b+1, numBatches)

		var buf bytes.Buffer
		for _, e := range entries[start:end] {
			fmt.Fprintf(&buf, `---
apiVersion: resourcemanager.miloapis.com/v1alpha1
kind: Project
metadata:
  name: scale-proj-%d-%d
  labels:
    perf-test: scale
spec:
  ownerRef:
    kind: Organization
    name: scale-org-%d
`, e.orgIdx, e.projIdx, e.orgIdx)
		}

		if err := kubectlApplyBuf(ctx, cfg, buf.Bytes()); err != nil {
			return fmt.Errorf("batch %d: %w", b+1, err)
		}
	}
	fmt.Fprintf(os.Stderr, "  Applied %d Project CRDs\n", total)
	return nil
}

// ---------------------------------------------------------------------------
// Reconcile mode: UID reading
// ---------------------------------------------------------------------------

// readResourceUIDs reads the metadata.uid for each generated resource by
// executing a single kubectl get with jsonpath output. The namePattern is a
// fmt.Sprintf pattern accepting a single integer index, e.g. "scale-user-%d".
// It polls until all UIDs are non-empty, waiting up to 2 minutes.
func readResourceUIDs(ctx context.Context, cfg Config, resourceType string, count int, namePattern string) (map[int]string, error) {
	uids := make(map[int]string, count)
	deadline := time.Now().Add(2 * time.Minute)

	for time.Now().Before(deadline) {
		missing := 0
		// Read in batches to avoid an argument list that is too long.
		for b := 0; b < count; b += crdBatchSize {
			end := b + crdBatchSize
			if end > count {
				end = count
			}

			// Build the list of names for this batch.
			names := make([]string, 0, end-b)
			for i := b; i < end; i++ {
				if _, ok := uids[i]; !ok {
					names = append(names, fmt.Sprintf(namePattern, i))
				}
			}
			if len(names) == 0 {
				continue
			}

			// kubectl get <type> <name1> <name2> ... -o jsonpath
			args := []string{"get", resourceType}
			args = append(args, names...)
			args = append(args, "-o", `jsonpath={range .items[*]}{.metadata.name}={.metadata.uid}{"\n"}{end}`)

			//nolint:gosec // cfg.Kubectl is a controlled value
			cmd := exec.CommandContext(ctx, cfg.Kubectl, args...)
			out, err := cmd.Output()
			if err != nil {
				// Transient error — will retry on next iteration.
				break
			}

			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 || parts[1] == "" {
					missing++
					continue
				}
				// Reverse-map name to index.
				for i := b; i < end; i++ {
					if fmt.Sprintf(namePattern, i) == parts[0] {
						uids[i] = parts[1]
						break
					}
				}
			}
		}

		// Count how many are still missing.
		missing = 0
		for i := 0; i < count; i++ {
			if uids[i] == "" {
				missing++
			}
		}
		if missing == 0 {
			return uids, nil
		}

		fmt.Fprintf(os.Stderr, "  Waiting for %d/%d %s UIDs to be assigned...\n", count-missing, count, resourceType)
		time.Sleep(2 * time.Second)
	}

	// Count final missing.
	missing := 0
	for i := 0; i < count; i++ {
		if uids[i] == "" {
			missing++
		}
	}
	if missing > 0 {
		return nil, fmt.Errorf("%d out of %d %s resources did not receive UIDs within 2 minutes", missing, count, resourceType)
	}
	return uids, nil
}

// ---------------------------------------------------------------------------
// Reconcile mode: Phase 6 — PolicyBinding CRDs
// ---------------------------------------------------------------------------

func createPolicyBindingCRDs(
	ctx context.Context,
	cfg Config,
	membershipMap map[int][]int,
	userUIDs map[int]string,
	orgUIDs map[int]string,
) error {
	// Flatten memberships into an ordered slice so we can batch them.
	type binding struct {
		userIdx int
		orgIdx  int
	}
	var bindings []binding
	for u := 0; u < cfg.NumUsers; u++ {
		for _, o := range membershipMap[u] {
			bindings = append(bindings, binding{userIdx: u, orgIdx: o})
		}
	}

	total := len(bindings)
	numBatches := (total + crdBatchSize - 1) / crdBatchSize

	for b := 0; b < numBatches; b++ {
		start := b * crdBatchSize
		end := start + crdBatchSize
		if end > total {
			end = total
		}
		fmt.Fprintf(os.Stderr, "  Phase 6: Creating %d PolicyBindings... (batch %d/%d)\n", total, b+1, numBatches)

		var buf bytes.Buffer
		for _, bind := range bindings[start:end] {
			u := bind.userIdx
			o := bind.orgIdx
			roleIdx := u % cfg.NumRoles
			userUID := userUIDs[u]
			orgUID := orgUIDs[o]

			fmt.Fprintf(&buf, `---
apiVersion: iam.miloapis.com/v1alpha1
kind: PolicyBinding
metadata:
  name: scale-binding-%d-%d
  labels:
    perf-test: scale
spec:
  roleRef:
    name: scale-role-%d
    namespace: default
  subjects:
    - kind: User
      name: scale-user-%d
      uid: "%s"
  resourceSelector:
    resourceRef:
      apiGroup: resourcemanager.miloapis.com
      kind: Organization
      name: scale-org-%d
      uid: "%s"
`, u, o, roleIdx, u, userUID, o, orgUID)
		}

		if err := kubectlApplyBuf(ctx, cfg, buf.Bytes()); err != nil {
			return fmt.Errorf("batch %d: %w", b+1, err)
		}
	}
	fmt.Fprintf(os.Stderr, "  Applied %d PolicyBinding CRDs\n", total)
	return nil
}

// waitForPolicyBindingsReady polls kubectl wait until all policy bindings with
// the perf-test=scale label reach the Ready condition.
func waitForPolicyBindingsReady(ctx context.Context, cfg Config, totalBindings int) error {
	// kubectl wait reports progress implicitly; additionally poll the count so
	// we can emit progress messages to the operator.
	done := make(chan error, 1)
	go func() {
		//nolint:gosec // cfg.Kubectl is a controlled value
		cmd := exec.CommandContext(ctx, cfg.Kubectl, "wait",
			"--for=condition=Ready",
			"policybinding.iam.miloapis.com",
			"--selector=perf-test=scale",
			"--timeout=5m",
		)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		done <- cmd.Run()
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("kubectl wait for PolicyBindings failed: %w", err)
			}
			return nil
		case <-ticker.C:
			ready := countReadyPolicyBindings(ctx, cfg)
			fmt.Fprintf(os.Stderr, "Phase 6: %d/%d PolicyBindings Ready...\n", ready, totalBindings)
		}
	}
}

// countReadyPolicyBindings returns the number of PolicyBindings with
// perf-test=scale that currently have Ready=True.
func countReadyPolicyBindings(ctx context.Context, cfg Config) int {
	//nolint:gosec // cfg.Kubectl is a controlled value
	cmd := exec.CommandContext(ctx, cfg.Kubectl, "get",
		"policybinding.iam.miloapis.com",
		"--selector=perf-test=scale",
		"-o", `jsonpath={range .items[?(@.status.conditions[?(@.type=="Ready")].status=="True")]}{.metadata.name}{"\n"}{end}`,
	)
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	count := 0
	for _, l := range lines {
		if l != "" {
			count++
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Shared kubectl helper
// ---------------------------------------------------------------------------

// kubectlApplyBuf writes buf to a temporary file and applies it with
// kubectl apply --server-side. The temp file is removed after the call.
func kubectlApplyBuf(ctx context.Context, cfg Config, buf []byte) error {
	tmp, err := os.CreateTemp("", "perf-crd-batch-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(buf); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	//nolint:gosec // cfg.Kubectl and tmp.Name() are controlled values
	cmd := exec.CommandContext(ctx, cfg.Kubectl, "apply", "--server-side", "-f", tmp.Name())
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl apply failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Direct mode: Phase 3 — InternalRole permission tuples
// ---------------------------------------------------------------------------

// buildPermissionString returns the full permission string for a perf resource
// using the same format as getAllPermissions in authorization_model_reconciler.go:
// "<serviceAPIGroup>/<plural>.<verb>"
func buildPermissionString(_ int, permIdx int) string {
	// Use permissions from real ProtectedResources that exist in the authorization
	// model. These must match what the authorization model reconciler creates.
	permissions := []string{
		"resourcemanager.miloapis.com/organizations.get",
		"resourcemanager.miloapis.com/organizations.list",
		"resourcemanager.miloapis.com/organizations.create",
		"resourcemanager.miloapis.com/organizations.update",
		"resourcemanager.miloapis.com/organizations.delete",
		"resourcemanager.miloapis.com/projects.get",
		"resourcemanager.miloapis.com/projects.list",
		"resourcemanager.miloapis.com/projects.create",
		"resourcemanager.miloapis.com/projects.update",
		"resourcemanager.miloapis.com/projects.delete",
	}
	return permissions[permIdx%len(permissions)]
}

func buildInternalRoleTuples(cfg Config) []*openfgav1.TupleKey {
	tuples := make([]*openfgav1.TupleKey, 0, cfg.NumRoles*cfg.PermissionsPerRole)
	for r := 0; r < cfg.NumRoles; r++ {
		roleID := fmt.Sprintf("scale-role-%d", r)
		roleObject := internalopenfga.TypeInternalRole + ":" + roleID
		for p := 0; p < cfg.PermissionsPerRole; p++ {
			perm := buildPermissionString(r, p)
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     internalopenfga.TypeInternalUser + ":*",
				Relation: internalopenfga.HashPermission(perm),
				Object:   roleObject,
			})
		}
	}
	return tuples
}

// ---------------------------------------------------------------------------
// Direct mode: Phase 4 — Organization binding tuples
// ---------------------------------------------------------------------------

// buildMembershipMap returns a map of userIdx -> []orgIdx using a deterministic
// round-robin assignment. User i belongs to orgs starting at
// (i * MembershipsPerUser) mod NumOrgs, advancing by 1 each time.
func buildMembershipMap(cfg Config) map[int][]int {
	m := make(map[int][]int, cfg.NumUsers)
	for u := 0; u < cfg.NumUsers; u++ {
		orgs := make([]int, cfg.MembershipsPerUser)
		for j := 0; j < cfg.MembershipsPerUser; j++ {
			orgs[j] = (u*cfg.MembershipsPerUser + j) % cfg.NumOrgs
		}
		m[u] = orgs
	}
	return m
}

func buildOrgBindingTuples(cfg Config, membershipMap map[int][]int) []*openfgav1.TupleKey {
	// 3 tuples per (user, org) pair.
	tuples := make([]*openfgav1.TupleKey, 0, cfg.NumUsers*cfg.MembershipsPerUser*3)
	for u := 0; u < cfg.NumUsers; u++ {
		for _, o := range membershipMap[u] {
			bindingID := fmt.Sprintf("scale-binding-%d-%d", u, o)
			bindingObj := internalopenfga.TypeRoleBinding + ":" + bindingID
			orgObj := fmt.Sprintf("resourcemanager.miloapis.com/Organization:scale-org-%d", o)
			roleObj := internalopenfga.TypeInternalRole + fmt.Sprintf(":scale-role-%d", u%cfg.NumRoles)
			userObj := internalopenfga.TypeInternalUser + fmt.Sprintf(":scale-user-%d", u)

			// T1: binding → org
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     bindingObj,
				Relation: internalopenfga.RelationRoleBinding,
				Object:   orgObj,
			})
			// T2: internalRole → binding
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     roleObj,
				Relation: internalopenfga.RelationInternalRole,
				Object:   bindingObj,
			})
			// T3: internalUser → binding
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     userObj,
				Relation: internalopenfga.RelationInternalUser,
				Object:   bindingObj,
			})
		}
	}
	return tuples
}

// ---------------------------------------------------------------------------
// Direct mode: Phase 5 — Organization RootBinding tuples
// ---------------------------------------------------------------------------

func buildOrgRootBindingTuples(cfg Config) []*openfgav1.TupleKey {
	tuples := make([]*openfgav1.TupleKey, 0, cfg.NumOrgs)
	for o := 0; o < cfg.NumOrgs; o++ {
		tuples = append(tuples, &openfgav1.TupleKey{
			User:     internalopenfga.TypeRoot + ":resourcemanager.miloapis.com/Organization",
			Relation: internalopenfga.RelationRootBinding,
			Object:   fmt.Sprintf("resourcemanager.miloapis.com/Organization:scale-org-%d", o),
		})
	}
	return tuples
}

// ---------------------------------------------------------------------------
// Direct mode: Phase 6 — Project tuples
// ---------------------------------------------------------------------------

func buildProjectTuples(cfg Config) []*openfgav1.TupleKey {
	// 2 tuples per project: RootBinding + parent.
	tuples := make([]*openfgav1.TupleKey, 0, cfg.NumOrgs*cfg.NumProjectsPerOrg*2)
	for o := 0; o < cfg.NumOrgs; o++ {
		for p := 0; p < cfg.NumProjectsPerOrg; p++ {
			projectID := fmt.Sprintf("scale-proj-%d-%d", o, p)
			projectObj := "resourcemanager.miloapis.com/Project:" + projectID
			orgObj := fmt.Sprintf("resourcemanager.miloapis.com/Organization:scale-org-%d", o)

			// RootBinding for the project.
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     internalopenfga.TypeRoot + ":resourcemanager.miloapis.com/Project",
				Relation: internalopenfga.RelationRootBinding,
				Object:   projectObj,
			})
			// Parent relationship: project → org.
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     orgObj,
				Relation: internalopenfga.RelationParent,
				Object:   projectObj,
			})
		}
	}
	return tuples
}

// ---------------------------------------------------------------------------
// Direct mode: batched concurrent tuple writer
// ---------------------------------------------------------------------------

// writeTuplesBatched chunks tuples into batches of maxBatchSize and writes them
// concurrently using up to workers goroutines. "Already exists" errors are
// treated as success so the generator is idempotent on re-runs.
func writeTuplesBatched(
	ctx context.Context,
	client openfgav1.OpenFGAServiceClient,
	storeID string,
	tuples []*openfgav1.TupleKey,
	workers int,
	totalWritten *atomic.Int64,
) error {
	if len(tuples) == 0 {
		return nil
	}

	// Build batches.
	var batches [][]*openfgav1.TupleKey
	for i := 0; i < len(tuples); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(tuples) {
			end = len(tuples)
		}
		batches = append(batches, tuples[i:end])
	}

	batchCh := make(chan []*openfgav1.TupleKey, len(batches))
	for _, b := range batches {
		batchCh <- b
	}
	close(batchCh)

	errCh := make(chan error, workers)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range batchCh {
				if err := writeBatch(ctx, client, storeID, batch); err != nil {
					errCh <- err
					return
				}
				written := totalWritten.Add(int64(len(batch)))
				// Log progress every 10,000 tuples.
				prev := written - int64(len(batch))
				if prev/10000 < written/10000 {
					fmt.Fprintf(os.Stderr, "  Progress: %d tuples written\n", written)
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Return the first error, if any.
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// writeBatch writes a single batch of tuples to OpenFGA. Errors indicating
// that tuples already exist are silently ignored for idempotency.
func writeBatch(ctx context.Context, client openfgav1.OpenFGAServiceClient, storeID string, batch []*openfgav1.TupleKey) error {
	_, err := client.Write(ctx, &openfgav1.WriteRequest{
		StoreId: storeID,
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys: batch,
		},
	})
	if err != nil {
		// OpenFGA returns an error containing "already exists" when a tuple is
		// written a second time. Treat this as success for idempotency.
		if strings.Contains(err.Error(), "already exists") ||
			strings.Contains(err.Error(), "ErrInvalidWriteInput") {
			return nil
		}
		return fmt.Errorf("OpenFGA Write failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Manifest (shared by both modes)
// ---------------------------------------------------------------------------

func buildManifest(cfg Config, membershipMap map[int][]int, tupleCount int64) ScaleManifest {
	users := make([]string, cfg.NumUsers)
	for i := range users {
		users[i] = fmt.Sprintf("scale-user-%d", i)
	}

	orgs := make([]string, cfg.NumOrgs)
	for i := range orgs {
		orgs[i] = fmt.Sprintf("scale-org-%d", i)
	}

	projects := make([]string, 0, cfg.NumOrgs*cfg.NumProjectsPerOrg)
	for o := 0; o < cfg.NumOrgs; o++ {
		for p := 0; p < cfg.NumProjectsPerOrg; p++ {
			projects = append(projects, fmt.Sprintf("scale-proj-%d-%d", o, p))
		}
	}

	roles := make([]string, cfg.NumRoles)
	for i := range roles {
		roles[i] = fmt.Sprintf("scale-role-%d", i)
	}

	// Collect the set of permission strings used by the roles.
	permSet := make(map[string]struct{})
	for r := 0; r < cfg.NumRoles; r++ {
		for p := 0; p < cfg.PermissionsPerRole; p++ {
			permSet[buildPermissionString(r, p)] = struct{}{}
		}
	}
	permissions := make([]string, 0, len(permSet))
	for perm := range permSet {
		permissions = append(permissions, perm)
	}

	// Build the user → org membership map using names (not indices).
	userOrgMap := make(map[string][]string, cfg.NumUsers)
	for u, orgIdxs := range membershipMap {
		userName := fmt.Sprintf("scale-user-%d", u)
		orgNames := make([]string, len(orgIdxs))
		for i, o := range orgIdxs {
			orgNames[i] = fmt.Sprintf("scale-org-%d", o)
		}
		userOrgMap[userName] = orgNames
	}

	return ScaleManifest{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Params: ManifestParams{
			NumOrgs:            cfg.NumOrgs,
			NumProjectsPerOrg:  cfg.NumProjectsPerOrg,
			NumUsers:           cfg.NumUsers,
			NumRoles:           cfg.NumRoles,
			PermissionsPerRole: cfg.PermissionsPerRole,
			OrgsPerUser:        cfg.MembershipsPerUser,
		},
		NumProjectsPerOrg:  cfg.NumProjectsPerOrg,
		Users:              users,
		Organizations:      orgs,
		Projects:           projects,
		Roles:              roles,
		Permissions:        permissions,
		UserOrgMemberships: userOrgMap,
		// scale-denied-user has no tuples; it must not appear in the Users list
		// or UserOrgMemberships map. We record it here so k6 can use it.
		DeniedUser: "scale-denied-user",
		TupleCount: tupleCount,
	}
}

func writeManifest(manifest ScaleManifest, path string) error {
	// Ensure the directory exists.
	if idx := strings.LastIndex(path, "/"); idx > 0 {
		dir := path[:idx]
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create manifest directory %s: %w", dir, err)
		}
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	//nolint:gosec // manifest file does not contain secrets
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write manifest to %s: %w", path, err)
	}
	return nil
}

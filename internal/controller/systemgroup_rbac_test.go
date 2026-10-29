package controller

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	authorizationv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// generatedRoleGroup is the group the test binds the generated ClusterRole to.
const generatedRoleGroup = "openfga-provider:controller-manager"

// The controller manager reaches Milo with the ClusterRole its RBAC markers
// generate. The system group reconciler finalizes Milo ServiceAccounts, so that
// role must let it update them: without it the reconciler cannot add its
// finalizer, and a ServiceAccount that already carries the finalizer is never
// deleted.
var _ = Describe("The generated role, for the ServiceAccounts the system group reconciler finalizes", Ordered, func() {
	var (
		asManager  client.Client
		reconciler *SystemGroupReconciler
	)

	BeforeAll(func() {
		_, err := envtest.InstallCRDs(cfg, envtest.CRDInstallOptions{
			Paths: []string{miloCRD("iam", "iam.miloapis.com_serviceaccounts.yaml")},
		})
		Expect(err).NotTo(HaveOccurred())
		asManager = clientBoundToGeneratedRole()
		reconciler = &SystemGroupReconciler{FGAClient: &fgaTupleStore{}, FGAStoreID: testStoreID}
	})

	It("lets the reconciler add its finalizer to a new ServiceAccount", func() {
		sa := createServiceAccount("finalizer-added")

		_, err := reconciler.reconcileObject(ctx, sa, asManager)

		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sa), sa)).To(Succeed())
		Expect(sa.Finalizers).To(ContainElement(systemGroupFinalizerKey))
	})

	It("lets the reconciler remove its finalizer, so a deleted ServiceAccount goes", func() {
		sa := createServiceAccount("finalizer-removed")
		sa.Finalizers = []string{systemGroupFinalizerKey}
		Expect(k8sClient.Update(ctx, sa)).To(Succeed())
		Expect(reconciler.writeSystemGroupTuple(ctx, sa)).To(Succeed())
		Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sa), sa)).To(Succeed())

		_, err := reconciler.reconcileObject(ctx, sa, asManager)

		Expect(err).NotTo(HaveOccurred())
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKeyFromObject(sa), sa))).To(BeTrue())
	})
})

// miloCRD returns the path of one of Milo's CRDs in the module this repository
// builds against.
func miloCRD(parts ...string) string {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "go.miloapis.com/milo").Output()
	Expect(err).NotTo(HaveOccurred())
	return filepath.Join(append([]string{strings.TrimSpace(string(out)), "config", "crd", "bases"}, parts...)...)
}

// clientBoundToGeneratedRole applies config/base/rbac/role.yaml, binds it to a
// user of its own, and returns a client authenticated as that user once the
// binding is in force.
func clientBoundToGeneratedRole() client.Client {
	data, err := os.ReadFile(filepath.Join("..", "..", "config", "base", "rbac", "role.yaml"))
	Expect(err).NotTo(HaveOccurred())
	role := &rbacv1.ClusterRole{}
	Expect(utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), len(data)).Decode(role)).To(Succeed())
	Expect(k8sClient.Create(ctx, role)).To(Succeed())
	Expect(k8sClient.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: role.Name},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: generatedRoleGroup}},
	})).To(Succeed())

	user, err := testEnv.AddUser(envtest.User{Name: "openfga-provider-controller-manager", Groups: []string{generatedRoleGroup}}, nil)
	Expect(err).NotTo(HaveOccurred())
	cli, err := client.New(user.Config(), client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	// The role's wildcard read grants this as soon as the binding is in force.
	Eventually(func() bool {
		review := &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{Group: iamv1alpha1.SchemeGroupVersion.Group, Resource: "serviceaccounts", Verb: "get"},
		}}
		return cli.Create(ctx, review) == nil && review.Status.Allowed
	}).Should(BeTrue())
	return cli
}

// createServiceAccount creates a Milo ServiceAccount as the test's
// administrator and returns it.
func createServiceAccount(name string) *iamv1alpha1.ServiceAccount {
	sa := &iamv1alpha1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name}}
	Expect(k8sClient.Create(ctx, sa)).To(Succeed())
	return sa
}

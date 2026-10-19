package controller

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A binding adds our finalizer to its target only while the target is not
// being deleted. If the deletion starts between the read and the add, the API
// server refuses the add: apimachinery's ValidateObjectMetaAccessorUpdate
// forbids new finalizers once deletion has started, and apiserver's generic
// update runs it for every type, Milo's included. The live hold check after the
// add does not rest on this refusal alone.
var _ = Describe("Adding our finalizer to an object being deleted", func() {
	It("is refused by the API server", func() {
		obj := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "held-by-another", Namespace: "default", Finalizers: []string{"example.com/another"}}}
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		Expect(k8sClient.Delete(ctx, obj)).To(Succeed())
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		Expect(obj.DeletionTimestamp).NotTo(BeNil())

		err := holdWithFinalizer(ctx, k8sClient, obj)

		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "the add was not refused as invalid: %v", err)
		Expect(err.Error()).To(ContainSubstring("no new finalizers can be added if the object is being deleted"))
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
		Expect(obj.Finalizers).To(Equal([]string{"example.com/another"}))

		obj.Finalizers = nil
		Expect(k8sClient.Update(ctx, obj)).To(Succeed())
	})
})

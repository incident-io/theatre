package integration

import (
	"context"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Manager cache", func() {
	var namespaceName string

	BeforeEach(func() {
		namespaceName = uuid.New().String()
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
		Expect(mgr.GetClient().Create(context.TODO(), ns)).To(Succeed())
	})

	podSpec := corev1.PodSpec{
		RestartPolicy: corev1.RestartPolicyNever,
		Containers:    []corev1.Container{{Name: "sleep", Image: "alpine:latest"}},
	}

	// The cached client and the API reader are the same server, so an object
	// the reader can see but the cache cannot was filtered out by the cache.
	expectCached := func(obj client.Object, cached bool) {
		key := client.ObjectKeyFromObject(obj)
		fresh := obj.DeepCopyObject().(client.Object)
		Expect(mgr.GetAPIReader().Get(context.TODO(), key, fresh)).To(Succeed())

		get := func() error {
			return mgr.GetClient().Get(context.TODO(), key, obj.DeepCopyObject().(client.Object))
		}
		if cached {
			Eventually(get, 5*time.Second, 100*time.Millisecond).Should(Succeed())
			return
		}
		Consistently(func() bool {
			return apierrors.IsNotFound(get())
		}, 2*time.Second, 200*time.Millisecond).Should(BeTrue())
	}

	It("caches only the jobs that belong to a console", func() {
		console := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name: "console-job", Namespace: namespaceName,
				Labels: map[string]string{"console-name": "some-console"},
			},
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec}},
		}
		other := &batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name: "burst-capacity-abcde", Namespace: namespaceName,
				Labels: map[string]string{"app.kubernetes.io/component": "burst-capacity"},
			},
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec}},
		}
		Expect(mgr.GetClient().Create(context.TODO(), console)).To(Succeed())
		Expect(mgr.GetClient().Create(context.TODO(), other)).To(Succeed())

		expectCached(console, true)
		expectCached(other, false)
	})

	It("caches only the pods that belong to a console", func() {
		console := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "console-pod", Namespace: namespaceName,
				Labels: map[string]string{"console-name": "some-console", "job-name": "some-console-console"},
			},
			Spec: podSpec,
		}
		other := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "burst-capacity-abcde-xyz12", Namespace: namespaceName,
				Labels: map[string]string{"job-name": "burst-capacity-abcde"},
			},
			Spec: podSpec,
		}
		Expect(mgr.GetClient().Create(context.TODO(), console)).To(Succeed())
		Expect(mgr.GetClient().Create(context.TODO(), other)).To(Succeed())

		expectCached(console, true)
		expectCached(other, false)
	})
})

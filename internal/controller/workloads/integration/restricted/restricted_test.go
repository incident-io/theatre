package restricted

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
)

var _ = Describe("Console RBAC with approvers-without-exec and subjects-without-access", func() {
	const (
		consoleName = "console-0"
		approver    = "approver@example.com"
	)

	var (
		namespaceName string
		podName       string
		csl           *workloadsv1alpha1.Console
	)

	clientFor := func(username string) client.Client {
		user, err := testEnv.AddUser(
			envtest.User{Name: username, Groups: []string{"system:masters"}},
			&rest.Config{},
		)
		Expect(err).NotTo(HaveOccurred())

		c, err := client.New(user.Config(), client.Options{Scheme: mgr.GetScheme()})
		Expect(err).NotTo(HaveOccurred())

		return c
	}

	approve := func(username string) {
		c := clientFor(username)
		Eventually(func() error {
			auth := &workloadsv1alpha1.ConsoleAuthorisation{}
			if err := c.Get(context.TODO(), client.ObjectKeyFromObject(csl), auth); err != nil {
				return err
			}
			auth.Spec.Authorisations = append(auth.Spec.Authorisations,
				rbacv1.Subject{Kind: rbacv1.UserKind, Name: username},
			)
			return c.Update(context.TODO(), auth)
		}).Should(Succeed())
	}

	// can asks the API server's RBAC authoriser, so it reflects the Roles and
	// RoleBindings the controller created rather than their spec.
	can := func(username, verb, subresource string) bool {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: username,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   namespaceName,
					Verb:        verb,
					Resource:    "pods",
					Subresource: subresource,
					Name:        podName,
				},
			},
		}
		Expect(mgr.GetClient().Create(context.TODO(), sar)).To(Succeed())

		return sar.Status.Allowed
	}

	BeforeEach(func() {
		namespaceName = uuid.New().String()
		podName = fmt.Sprintf("%s-console-abcde", consoleName)

		Expect(mgr.GetClient().Create(context.TODO(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
		})).To(Succeed())

		ttl := int32(60)
		Expect(mgr.GetClient().Create(context.TODO(), &workloadsv1alpha1.ConsoleTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "console-template-0", Namespace: namespaceName},
			Spec: workloadsv1alpha1.ConsoleTemplateSpec{
				DefaultTTLSecondsBeforeRunning: &ttl,
				DefaultTimeoutSeconds:          600,
				MaxTimeoutSeconds:              7200,
				DefaultAuthorisationRule: &workloadsv1alpha1.ConsoleAuthorisers{
					AuthorisationsRequired: 1,
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.UserKind, Name: approver},
						{Kind: rbacv1.UserKind, Name: authoriserUsername},
					},
				},
				Template: workloadsv1alpha1.PodTemplatePreserveMetadataSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Image: "alpine:latest", Name: "console-container-0", Command: []string{"sleep", "100"}},
						},
						RestartPolicy: "OnFailure",
					},
				},
			},
		})).To(Succeed())

		csl = &workloadsv1alpha1.Console{
			ObjectMeta: metav1.ObjectMeta{Name: consoleName, Namespace: namespaceName},
			Spec: workloadsv1alpha1.ConsoleSpec{
				ConsoleTemplateRef: corev1.LocalObjectReference{Name: "console-template-0"},
				TimeoutSeconds:     3600,
			},
		}
		Expect(mgr.GetClient().Create(context.TODO(), csl)).To(Succeed())

		By("Approving as a human and as the authoriser")
		approve(approver)
		approve(authoriserUsername)

		By("Creating a running pod for the console's job")
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: namespaceName,
				Labels:    labels.Set{"job-name": fmt.Sprintf("%s-console", consoleName)},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Image: "alpine:latest", Name: "console-container-0"}},
			},
		}
		Expect(mgr.GetClient().Create(context.TODO(), pod)).To(Succeed())
		pod.Status.Phase = corev1.PodRunning
		Expect(mgr.GetClient().Status().Update(context.TODO(), pod)).To(Succeed())

		By("Waiting for the approvers' role binding")
		Eventually(func() error {
			return mgr.GetClient().Get(context.TODO(), client.ObjectKey{
				Namespace: namespaceName, Name: fmt.Sprintf("%s-approvers", consoleName),
			}, &rbacv1.RoleBinding{})
		}).Should(Succeed())
	})

	It("lets an approver attach and read logs, but not exec or delete", func() {
		Eventually(func() bool { return can(approver, "create", "attach") }).Should(BeTrue())
		Expect(can(approver, "get", "log")).To(BeTrue())
		Expect(can(approver, "create", "exec")).To(BeFalse())
		Expect(can(approver, "delete", "")).To(BeFalse())
	})

	It("keeps exec for the creator only", func() {
		// envtest's client authenticates as "admin", which becomes the creator.
		Eventually(func() bool { return can("admin", "create", "exec") }).Should(BeTrue())
		Expect(can("admin", "create", "attach")).To(BeTrue())

		rb := &rbacv1.RoleBinding{}
		Expect(mgr.GetClient().Get(context.TODO(), client.ObjectKeyFromObject(csl), rb)).To(Succeed())
		Expect(rb.RoleRef.Name).To(Equal(consoleName))
		Expect(rb.Subjects).To(ConsistOf(HaveField("Name", "admin")))
	})

	It("gives the authoriser no role binding and no access", func() {
		Eventually(func() bool { return can(approver, "create", "attach") }).Should(BeTrue())

		bindings := &rbacv1.RoleBindingList{}
		Expect(mgr.GetClient().List(context.TODO(), bindings, client.InNamespace(namespaceName))).To(Succeed())

		for _, rb := range bindings.Items {
			// The authorisation binding lets rule subjects approve the console,
			// which is how the authoriser works, and grants nothing on the pod.
			if rb.Name == fmt.Sprintf("%s-authorisation", consoleName) {
				continue
			}
			Expect(rb.Subjects).NotTo(ContainElement(HaveField("Name", authoriserUsername)),
				"role binding %s should not include the authoriser", rb.Name)
		}

		Expect(can(authoriserUsername, "create", "attach")).To(BeFalse())
		Expect(can(authoriserUsername, "create", "exec")).To(BeFalse())
		Expect(can(authoriserUsername, "get", "log")).To(BeFalse())
	})
})

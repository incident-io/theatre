package pendingcapacity

import (
	"context"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
	consolecontroller "github.com/gocardless/theatre/v5/internal/controller/workloads"
)

const approverName = "approver@example.com"

var _ = Describe("Pending capacity pod", func() {
	var (
		namespaceName string
		consoleName   string
		csl           *workloadsv1alpha1.Console
		template      *workloadsv1alpha1.ConsoleTemplate
	)

	podKey := func() client.ObjectKey {
		return client.ObjectKey{Namespace: namespaceName, Name: consoleName + "-capacity"}
	}

	capacityPod := func() *corev1.Pod {
		pod := &corev1.Pod{}
		Eventually(func() error {
			return mgr.GetClient().Get(context.TODO(), podKey(), pod)
		}).Should(Succeed())
		return pod
	}

	consolePhase := func() workloadsv1alpha1.ConsolePhase {
		updated := &workloadsv1alpha1.Console{}
		Expect(mgr.GetClient().Get(context.TODO(), client.ObjectKeyFromObject(csl), updated)).To(Succeed())
		return updated.Status.Phase
	}

	approve := func() {
		user, err := testEnv.AddUser(
			envtest.User{Name: approverName, Groups: []string{"system:masters"}},
			&rest.Config{},
		)
		Expect(err).NotTo(HaveOccurred())
		approver, err := client.New(user.Config(), client.Options{Scheme: mgr.GetScheme()})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() error {
			auth := &workloadsv1alpha1.ConsoleAuthorisation{}
			if err := approver.Get(context.TODO(), client.ObjectKeyFromObject(csl), auth); err != nil {
				return err
			}
			auth.Spec.Authorisations = append(auth.Spec.Authorisations,
				rbacv1.Subject{Kind: rbacv1.UserKind, Name: approverName},
			)
			return approver.Update(context.TODO(), auth)
		}).Should(Succeed())
	}

	BeforeEach(func() {
		namespaceName = uuid.New().String()
		consoleName = "console-0"
		ttl := int32(3600)

		Expect(mgr.GetClient().Create(context.TODO(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
		})).To(Succeed())

		// The apiserver rejects a pod whose priority class does not exist.
		preempt := corev1.PreemptNever
		class := &schedulingv1.PriorityClass{
			ObjectMeta:       metav1.ObjectMeta{Name: consolecontroller.DefaultPendingCapacityPriorityClass},
			Value:            -9,
			PreemptionPolicy: &preempt,
			GlobalDefault:    false,
		}
		err := mgr.GetClient().Create(context.TODO(), class)
		Expect(err == nil || apierrors.IsAlreadyExists(err)).To(BeTrue())

		template = &workloadsv1alpha1.ConsoleTemplate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "console-template-0",
				Namespace: namespaceName,
			},
			Spec: workloadsv1alpha1.ConsoleTemplateSpec{
				DefaultTTLSecondsBeforeRunning: &ttl,
				DefaultTimeoutSeconds:          600,
				MaxTimeoutSeconds:              7200,
				DefaultAuthorisationRule: &workloadsv1alpha1.ConsoleAuthorisers{
					AuthorisationsRequired: 1,
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.UserKind, Name: approverName},
					},
				},
				Template: workloadsv1alpha1.PodTemplatePreserveMetadataSpec{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: map[string]string{
							"cluster-autoscaler.kubernetes.io/safe-to-evict": "false",
						},
					},
					Spec: corev1.PodSpec{
						NodeSelector: map[string]string{
							"cloud.google.com/compute-class": "Balanced",
						},
						Tolerations: []corev1.Toleration{{
							Key:      "dedicated",
							Operator: corev1.TolerationOpEqual,
							Value:    "console",
							Effect:   corev1.TaintEffectNoSchedule,
						}},
						Affinity: &corev1.Affinity{
							NodeAffinity: &corev1.NodeAffinity{
								RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
									NodeSelectorTerms: []corev1.NodeSelectorTerm{{
										MatchExpressions: []corev1.NodeSelectorRequirement{{
											Key:      "topology.kubernetes.io/zone",
											Operator: corev1.NodeSelectorOpIn,
											Values:   []string{"europe-west1-b"},
										}},
									}},
								},
							},
						},
						InitContainers: []corev1.Container{{
							Name:  "migrate",
							Image: "alpine:latest",
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("2"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("2"),
									corev1.ResourceMemory: resource.MustParse("512Mi"),
								},
							},
						}},
						Containers: []corev1.Container{
							{
								Name:    "app",
								Image:   "alpine:latest",
								Command: []string{"sleep", "666"},
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceCPU:              resource.MustParse("1"),
										corev1.ResourceMemory:           resource.MustParse("2Gi"),
										corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceCPU:              resource.MustParse("1"),
										corev1.ResourceMemory:           resource.MustParse("2Gi"),
										corev1.ResourceEphemeralStorage: resource.MustParse("1Gi"),
									},
								},
							},
							{
								Name:  "sidecar",
								Image: "alpine:latest",
								Resources: corev1.ResourceRequirements{
									Requests: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("500m"),
										corev1.ResourceMemory: resource.MustParse("1Gi"),
									},
									Limits: corev1.ResourceList{
										corev1.ResourceCPU:    resource.MustParse("500m"),
										corev1.ResourceMemory: resource.MustParse("1Gi"),
									},
								},
							},
						},
					},
				},
			},
		}

		csl = &workloadsv1alpha1.Console{
			ObjectMeta: metav1.ObjectMeta{
				Name:      consoleName,
				Namespace: namespaceName,
			},
			Spec: workloadsv1alpha1.ConsoleSpec{
				Command:            []string{"sleep", "666"},
				ConsoleTemplateRef: corev1.LocalObjectReference{Name: template.Name},
				TimeoutSeconds:     600,
			},
		}
	})

	create := func() {
		Expect(mgr.GetClient().Create(context.TODO(), template)).To(Succeed())
		Expect(mgr.GetClient().Create(context.TODO(), csl)).To(Succeed())
	}

	It("creates a pause pod from the template while authorisation is pending", func() {
		create()

		pod := capacityPod()
		Expect(consolePhase()).To(Equal(workloadsv1alpha1.ConsolePendingAuthorisation))

		By("Expect the pod to be owned by the console, so deleting the console collects it")
		Expect(pod.OwnerReferences).To(HaveLen(1))
		Expect(pod.OwnerReferences[0].Kind).To(Equal("Console"))
		Expect(pod.OwnerReferences[0].Name).To(Equal(consoleName))
		Expect(pod.OwnerReferences[0].Controller).NotTo(BeNil())
		Expect(*pod.OwnerReferences[0].Controller).To(BeTrue())

		By("Expect a pause container at the console pod's effective size")
		Expect(pod.Spec.Containers).To(HaveLen(1))
		Expect(pod.Spec.Containers[0].Name).To(Equal("pause"))
		Expect(pod.Spec.Containers[0].Image).To(Equal(consolecontroller.DefaultPendingCapacityImage))
		// Init asks for 2 CPU, the two app containers ask for 1.5 between them.
		Expect(pod.Spec.Containers[0].Resources.Requests.Cpu().MilliValue()).To(Equal(int64(2000)))
		// App containers ask for 3Gi, the init container for 512Mi.
		Expect(pod.Spec.Containers[0].Resources.Requests.Memory().Value()).To(Equal(int64(3 * 1024 * 1024 * 1024)))
		Expect(pod.Spec.Containers[0].Resources.Requests.StorageEphemeral().Value()).To(Equal(int64(1024 * 1024 * 1024)))
		Expect(pod.Spec.Containers[0].Resources.Limits.Cpu().MilliValue()).To(Equal(int64(2000)))
		Expect(pod.Spec.Containers[0].Resources.Limits.Memory().Value()).To(Equal(int64(3 * 1024 * 1024 * 1024)))

		Expect(pod.Spec.NodeSelector).To(Equal(map[string]string{
			"cloud.google.com/compute-class": "Balanced",
		}))
		Expect(pod.Spec.Tolerations).To(ContainElement(template.Spec.Template.Spec.Tolerations[0]))
		Expect(pod.Spec.Affinity).To(Equal(template.Spec.Template.Spec.Affinity))
		Expect(pod.Spec.PriorityClassName).To(Equal(consolecontroller.DefaultPendingCapacityPriorityClass))
		Expect(pod.Annotations).To(HaveKeyWithValue("cluster-autoscaler.kubernetes.io/safe-to-evict", "false"))
		Expect(pod.Labels).To(HaveKeyWithValue("app.kubernetes.io/component", "console-pending-capacity"))
		Expect(pod.Labels).NotTo(HaveKey("job-name"))
		Expect(pod.Spec.RestartPolicy).To(Equal(corev1.RestartPolicyAlways))
		Expect(pod.Spec.TerminationGracePeriodSeconds).NotTo(BeNil())
		Expect(*pod.Spec.TerminationGracePeriodSeconds).To(Equal(int64(0)))
		Expect(pod.Spec.ServiceAccountName).To(BeEmpty())
		Expect(pod.Spec.AutomountServiceAccountToken).NotTo(BeNil())
		Expect(*pod.Spec.AutomountServiceAccountToken).To(BeFalse())

		By("Expect no job yet")
		err := mgr.GetClient().Get(context.TODO(), client.ObjectKey{
			Namespace: namespaceName, Name: consoleName + "-console",
		}, &batchv1.Job{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})

	It("deletes the pause pod once the console is authorised and again leaves it gone when the job stops", func() {
		create()
		Expect(capacityPod()).NotTo(BeNil())

		approve()

		By("Expect the job to exist and the pause pod to be gone")
		Eventually(func() error {
			return mgr.GetClient().Get(context.TODO(), client.ObjectKey{
				Namespace: namespaceName, Name: consoleName + "-console",
			}, &batchv1.Job{})
		}).Should(Succeed())
		Eventually(func() bool {
			err := mgr.GetClient().Get(context.TODO(), podKey(), &corev1.Pod{})
			return apierrors.IsNotFound(err)
		}).Should(BeTrue())

		By("Mark the job failed so the console stops")
		job := &batchv1.Job{}
		Expect(mgr.GetClient().Get(context.TODO(), client.ObjectKey{
			Namespace: namespaceName, Name: consoleName + "-console",
		}, job)).To(Succeed())
		now := metav1.Now()
		job.Status = batchv1.JobStatus{
			StartTime:      &now,
			CompletionTime: &now,
			Conditions: []batchv1.JobCondition{
				{Type: batchv1.JobSuccessCriteriaMet, Status: corev1.ConditionTrue},
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
			},
		}
		Expect(mgr.GetClient().Status().Update(context.TODO(), job)).To(Succeed())

		Eventually(consolePhase).Should(Equal(workloadsv1alpha1.ConsoleStopped))
		err := mgr.GetClient().Get(context.TODO(), podKey(), &corev1.Pod{})
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})

	It("deletes the pause pod when the console expires before it is authorised", func() {
		ttl := int32(8)
		template.Spec.DefaultTTLSecondsBeforeRunning = &ttl
		create()
		Expect(capacityPod()).NotTo(BeNil())

		Eventually(func() bool {
			err := mgr.GetClient().Get(context.TODO(), client.ObjectKeyFromObject(csl), &workloadsv1alpha1.Console{})
			return apierrors.IsNotFound(err)
		}).Should(BeTrue())
		Eventually(func() bool {
			err := mgr.GetClient().Get(context.TODO(), podKey(), &corev1.Pod{})
			return apierrors.IsNotFound(err)
		}).Should(BeTrue())
	})

	It("deletes the pause pod when its own TTL elapses and leaves the console waiting", func() {
		reconciler.PendingCapacityTTL = 3 * time.Second
		DeferCleanup(func() { reconciler.PendingCapacityTTL = 0 })

		create()
		pod := capacityPod()
		Expect(pod.CreationTimestamp.IsZero()).To(BeFalse())

		By("Expect the pause pod to be removed from its creation time, not the console TTL")
		Eventually(func() bool {
			err := mgr.GetClient().Get(context.TODO(), podKey(), &corev1.Pod{})
			return apierrors.IsNotFound(err)
		}).Should(BeTrue())

		updated := &workloadsv1alpha1.Console{}
		Expect(mgr.GetClient().Get(context.TODO(), client.ObjectKeyFromObject(csl), updated)).To(Succeed())
		Expect(updated.Status.Phase).To(Equal(workloadsv1alpha1.ConsolePendingAuthorisation))
		Expect(updated.Annotations).To(HaveKeyWithValue(consolecontroller.PendingCapacityExpiredAnnotation, "true"))
		Expect(updated.Spec.TTLSecondsBeforeRunning).NotTo(BeNil())
		Expect(*updated.Spec.TTLSecondsBeforeRunning).To(Equal(int32(3600)))
	})

	It("does not recreate the pause pod after that TTL while the console stays pending", func() {
		reconciler.PendingCapacityTTL = 3 * time.Second
		DeferCleanup(func() { reconciler.PendingCapacityTTL = 0 })

		create()
		Expect(capacityPod()).NotTo(BeNil())

		Eventually(func() bool {
			err := mgr.GetClient().Get(context.TODO(), podKey(), &corev1.Pod{})
			if !apierrors.IsNotFound(err) {
				return false
			}
			updated := &workloadsv1alpha1.Console{}
			if err := mgr.GetClient().Get(context.TODO(), client.ObjectKeyFromObject(csl), updated); err != nil {
				return false
			}
			return updated.Annotations[consolecontroller.PendingCapacityExpiredAnnotation] == "true"
		}).Should(BeTrue())

		By("Ask the controller to reconcile again, the way any console update would")
		Eventually(func() error {
			fresh := &workloadsv1alpha1.Console{}
			if err := mgr.GetClient().Get(context.TODO(), client.ObjectKeyFromObject(csl), fresh); err != nil {
				return err
			}
			base := fresh.DeepCopy()
			if fresh.Labels == nil {
				fresh.Labels = map[string]string{}
			}
			fresh.Labels["capacity-recheck"] = "again"
			return mgr.GetClient().Patch(context.TODO(), fresh, client.MergeFrom(base))
		}).Should(Succeed())

		Consistently(func() bool {
			err := mgr.GetClient().Get(context.TODO(), podKey(), &corev1.Pod{})
			return apierrors.IsNotFound(err)
		}, 3*time.Second, 200*time.Millisecond).Should(BeTrue())

		updated := &workloadsv1alpha1.Console{}
		Expect(mgr.GetClient().Get(context.TODO(), client.ObjectKeyFromObject(csl), updated)).To(Succeed())
		Expect(updated.Status.Phase).To(Equal(workloadsv1alpha1.ConsolePendingAuthorisation))
		Expect(*updated.Spec.TTLSecondsBeforeRunning).To(Equal(int32(3600)))
	})

	It("does not create a pause pod when the console does not need authorisation", func() {
		template.Spec.DefaultAuthorisationRule = nil
		create()

		Eventually(func() error {
			return mgr.GetClient().Get(context.TODO(), client.ObjectKey{
				Namespace: namespaceName, Name: consoleName + "-console",
			}, &batchv1.Job{})
		}).Should(Succeed())
		Consistently(func() bool {
			err := mgr.GetClient().Get(context.TODO(), podKey(), &corev1.Pod{})
			return apierrors.IsNotFound(err)
		}, 2*time.Second, 200*time.Millisecond).Should(BeTrue())
	})
})

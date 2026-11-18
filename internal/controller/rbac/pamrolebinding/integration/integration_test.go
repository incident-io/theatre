package integration

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	rbacv1alpha1 "github.com/gocardless/theatre/v5/api/rbac/v1alpha1"
	"github.com/gocardless/theatre/v5/internal/controller/rbac/pamrolebinding"
)

var _ = Describe("PAMRoleBinding", func() {
	var (
		namespace   string
		entitlement string
		prb         *rbacv1alpha1.PAMRoleBinding
	)

	roleBindings := func() []rbacv1.RoleBinding {
		list := &rbacv1.RoleBindingList{}
		Expect(k8sClient.List(ctx, list, client.InNamespace(namespace))).To(Succeed())
		return list.Items
	}

	syncedCondition := func() *metav1.Condition {
		got := &rbacv1alpha1.PAMRoleBinding{}
		Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(prb), got)).To(Succeed())
		return meta.FindStatusCondition(got.Status.Conditions, rbacv1alpha1.PAMRoleBindingConditionSynced)
	}

	syncedReason := func() string {
		if c := syncedCondition(); c != nil {
			return c.Reason
		}
		return ""
	}

	grant := func(user, approver string, endsIn time.Duration) pamrolebinding.Grant {
		return pamrolebinding.Grant{
			Name:      fmt.Sprintf("%s/grants/%s", entitlement, uuid.NewString()),
			Requester: user,
			Approvers: approvers(approver),
			EndsAt:    clock.Now().Add(endsIn).Truncate(time.Second),
		}
	}

	BeforeEach(func() {
		namespace = "pam-" + uuid.NewString()[:8]
		entitlement = "projects/test/locations/global/entitlements/" + namespace
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})).To(Succeed())

		prb = &rbacv1alpha1.PAMRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "operator", Namespace: namespace},
			Spec: rbacv1alpha1.PAMRoleBindingSpec{
				Entitlement: entitlement,
				RoleRef:     rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "edit"},
			},
		}
	})

	Context("with an active grant", func() {
		var alice pamrolebinding.Grant

		BeforeEach(func() {
			alice = grant("alice.smith@example.com", "bob@example.com", time.Hour)
			grants.SetGrants(entitlement, alice)
			Expect(k8sClient.Create(ctx, prb)).To(Succeed())
		})

		It("binds the user, owned by the PAMRoleBinding and traceable to the grant", func() {
			Eventually(roleBindings).Should(HaveLen(1))
			rb := roleBindings()[0]

			Expect(rb.Name).To(MatchRegexp(`^pam-operator-alice-smith-[0-9a-f]{8}$`))
			Expect(rb.RoleRef).To(Equal(prb.Spec.RoleRef))
			Expect(rb.Subjects).To(Equal([]rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "User", Name: "alice.smith@example.com"}}))
			Expect(rb.Annotations).To(HaveKeyWithValue(pamrolebinding.AnnotationGrant, alice.Name))
			Expect(rb.Annotations).To(HaveKeyWithValue(pamrolebinding.AnnotationGrantID, alice.ID()))
			Expect(rb.Annotations).To(HaveKeyWithValue(pamrolebinding.AnnotationApprovers, "bob@example.com"))
			Expect(rb.Labels).To(HaveKeyWithValue(pamrolebinding.LabelPAMRoleBinding, "operator"))
			Expect(rb.Annotations).To(HaveKeyWithValue(pamrolebinding.AnnotationRequester, "alice.smith@example.com"))
			Expect(rb.Annotations).To(HaveKeyWithValue(pamrolebinding.AnnotationEndsAt, alice.EndsAt.UTC().Format(time.RFC3339)))
			Expect(rb.OwnerReferences).To(HaveLen(1))
			Expect(rb.OwnerReferences[0].Kind).To(Equal("PAMRoleBinding"))
			Expect(*rb.OwnerReferences[0].Controller).To(BeTrue())
		})

		It("reports the grant in its status", func() {
			Eventually(func() []rbacv1alpha1.PAMGrant {
				got := &rbacv1alpha1.PAMRoleBinding{}
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(prb), got)).To(Succeed())
				return got.Status.ActiveGrants
			}).Should(ConsistOf(And(
				HaveField("User", "alice.smith@example.com"),
				HaveField("Approvers", []string{"bob@example.com"}),
				HaveField("RoleBinding", HavePrefix("pam-operator-alice-smith-")),
			)))
			Eventually(syncedCondition).Should(HaveField("Status", metav1.ConditionTrue))
		})

		It("unbinds the user when the grant is withdrawn", func() {
			Eventually(roleBindings).Should(HaveLen(1))
			grants.SetGrants(entitlement)
			Eventually(roleBindings).Should(BeEmpty())
		})

		It("recreates a binding someone deletes while the grant is active", func() {
			Eventually(roleBindings).Should(HaveLen(1))
			rb := roleBindings()[0]
			Expect(k8sClient.Delete(ctx, &rb)).To(Succeed())
			Eventually(func() []string {
				return uids(roleBindings())
			}).Should(And(HaveLen(1), Not(ContainElement(string(rb.UID)))))
		})

		It("deletes its bindings when it's deleted, even orphaning its dependents", func() {
			Eventually(roleBindings).Should(HaveLen(1))
			Expect(k8sClient.Delete(ctx, prb, client.PropagationPolicy(metav1.DeletePropagationOrphan))).To(Succeed())
			Eventually(roleBindings).Should(BeEmpty())
		})

		It("adds a finalizer", func() {
			Eventually(func() []string {
				got := &rbacv1alpha1.PAMRoleBinding{}
				Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(prb), got)).To(Succeed())
				return got.Finalizers
			}).Should(ContainElement(pamrolebinding.Finalizer))
		})

		It("keeps the binding if PAM can't be reached, until the grant ends", func() {
			Eventually(roleBindings).Should(HaveLen(1))
			grants.SetError(entitlement, errors.New("connection refused"))

			Eventually(syncedReason).
				Should(Equal(rbacv1alpha1.PAMRoleBindingReasonPAMUnreachable))
			Consistently(roleBindings, time.Second).Should(HaveLen(1))

			clock.Advance(2 * time.Hour)
			Eventually(roleBindings).Should(BeEmpty())
		})

		It("replaces a binding whose label has been removed", func() {
			Eventually(roleBindings).Should(HaveLen(1))
			rb := roleBindings()[0]
			delete(rb.Labels, pamrolebinding.LabelPAMRoleBinding)
			Expect(k8sClient.Update(ctx, &rb)).To(Succeed())

			Eventually(func() []rbacv1.RoleBinding {
				rbs := roleBindings()
				if len(rbs) == 1 && rbs[0].UID != rb.UID {
					return rbs
				}
				return nil
			}).Should(ConsistOf(HaveField("Labels", HaveKeyWithValue(pamrolebinding.LabelPAMRoleBinding, "operator"))))
		})

		It("still removes a binding whose label has been removed, when its grant is withdrawn", func() {
			Eventually(roleBindings).Should(HaveLen(1))
			rb := roleBindings()[0]
			delete(rb.Labels, pamrolebinding.LabelPAMRoleBinding)
			grants.SetGrants(entitlement)
			Expect(k8sClient.Update(ctx, &rb)).To(Succeed())
			Eventually(roleBindings).Should(BeEmpty())
		})

		It("moves a user to their newer grant", func() {
			Eventually(roleBindings).Should(HaveLen(1))
			newer := grant("alice.smith@example.com", "", 3*time.Hour)
			grants.SetGrants(entitlement, alice, newer)

			Eventually(func() map[string]string {
				rbs := roleBindings()
				if len(rbs) != 1 {
					return nil
				}
				return rbs[0].Annotations
			}).Should(And(
				HaveKeyWithValue(pamrolebinding.AnnotationGrant, newer.Name),
				Not(HaveKey(pamrolebinding.AnnotationApprovers)),
			))
		})
	})

	It("removes the binding when the grant expires, even if PAM still lists it", func() {
		grants.SetGrants(entitlement, grant("carol@example.com", "", 30*time.Minute))
		Expect(k8sClient.Create(ctx, prb)).To(Succeed())
		Eventually(roleBindings).Should(HaveLen(1))

		clock.Advance(31 * time.Minute)
		Eventually(roleBindings).Should(BeEmpty())
	})

	It("doesn't bind a grant that ends while PAM is answering", func() {
		grants.SetGrants(entitlement, grant("frank@example.com", "", 25*time.Second))
		grants.SetDuringList(func() { clock.Advance(28 * time.Second) })
		DeferCleanup(func() { grants.SetDuringList(nil) })
		Expect(k8sClient.Create(ctx, prb)).To(Succeed())

		Eventually(syncedReason).Should(Equal(rbacv1alpha1.PAMRoleBindingReasonSynced))
		Consistently(roleBindings, time.Second).Should(BeEmpty())
	})

	It("doesn't bind requesters that aren't people", func() {
		grants.SetGrants(entitlement,
			grant("bot@my-project.iam.gserviceaccount.com", "", time.Hour),
			grant("group:team@example.com", "", time.Hour),
			grant("grace@example.com", "", time.Hour),
		)
		Expect(k8sClient.Create(ctx, prb)).To(Succeed())

		Eventually(roleBindings).Should(ConsistOf(HaveField("Subjects", ConsistOf(HaveField("Name", "grace@example.com")))))
		Eventually(func() []string {
			events := &corev1.EventList{}
			Expect(k8sClient.List(ctx, events, client.InNamespace(namespace))).To(Succeed())
			reasons := []string{}
			for _, e := range events.Items {
				reasons = append(reasons, e.Reason)
			}
			return reasons
		}).Should(ContainElement(pamrolebinding.EventGrantSkipped))
	})

	It("binds users for a PAMRoleBinding whose name is too long for a label", func() {
		prb.Name = strings.Repeat("a", 70)
		grants.SetGrants(entitlement, grant("heidi@example.com", "", time.Hour))
		Expect(k8sClient.Create(ctx, prb)).To(Succeed())

		Eventually(roleBindings).Should(ConsistOf(HaveField("Labels", HaveKeyWithValue(pamrolebinding.LabelPAMRoleBinding, strings.Repeat("a", 63)))))
		Eventually(syncedReason).Should(Equal(rbacv1alpha1.PAMRoleBindingReasonSynced))
	})

	It("reports an entitlement that doesn't exist", func() {
		// The fake reports any entitlement it has no grants for as not found.
		Expect(k8sClient.Create(ctx, prb)).To(Succeed())
		Eventually(func() *metav1.Condition { return syncedCondition() }).Should(And(
			Not(BeNil()),
			HaveField("Status", metav1.ConditionFalse),
			HaveField("Reason", rbacv1alpha1.PAMRoleBindingReasonEntitlementNotFound),
		))
		Expect(roleBindings()).To(BeEmpty())
	})

	It("binds grants on an entitlement named by project number", func() {
		prb.Spec.Entitlement = "projects/123456789/locations/global/entitlements/" + namespace
		grants.SetGrants(prb.Spec.Entitlement, grant("ivan@example.com", "", time.Hour))
		Expect(k8sClient.Create(ctx, prb)).To(Succeed())
		Eventually(roleBindings).Should(HaveLen(1))
	})

	It("refuses entitlements in other projects, even ones whose ID starts with ours", func() {
		prb.Spec.Entitlement = "projects/test-evil/locations/global/entitlements/" + namespace
		grants.SetGrants(prb.Spec.Entitlement, grant("erin@example.com", "", time.Hour))
		Expect(k8sClient.Create(ctx, prb)).To(Succeed())

		Eventually(syncedReason).Should(Equal(rbacv1alpha1.PAMRoleBindingReasonEntitlementNotAllowed))
		Consistently(roleBindings, time.Second).Should(BeEmpty())
		Expect(grants.Calls(prb.Spec.Entitlement)).To(BeZero())
	})

	It("refuses to take over a RoleBinding it doesn't own", func() {
		name := pamrolebinding.RoleBindingName("operator", "dave@example.com")
		Expect(k8sClient.Create(ctx, &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
			Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "User", Name: "someone@example.com"}},
		})).To(Succeed())

		grants.SetGrants(entitlement, grant("dave@example.com", "", time.Hour))
		Expect(k8sClient.Create(ctx, prb)).To(Succeed())

		Eventually(syncedReason).Should(Equal(rbacv1alpha1.PAMRoleBindingReasonRoleBindingFailed))

		rb := &rbacv1.RoleBinding{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, rb)).To(Succeed())
		Expect(rb.RoleRef.Name).To(Equal("view"))
	})

	It("rejects changes to roleRef", func() {
		grants.SetGrants(entitlement)
		Expect(k8sClient.Create(ctx, prb)).To(Succeed())
		// Re-read each time: the controller writes status, which bumps resourceVersion.
		Eventually(func() error {
			got := &rbacv1alpha1.PAMRoleBinding{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(prb), got)).To(Succeed())
			got.Spec.RoleRef.Name = "admin"
			return k8sClient.Update(ctx, got)
		}).Should(MatchError(ContainSubstring("RoleRef is immutable")))
	})
})

func uids(rbs []rbacv1.RoleBinding) []string {
	out := []string{}
	for _, rb := range rbs {
		out = append(out, string(rb.UID))
	}
	return out
}

func approvers(approver string) []string {
	if approver == "" {
		return nil
	}
	return []string{approver}
}

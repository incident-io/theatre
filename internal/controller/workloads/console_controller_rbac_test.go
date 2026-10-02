package controllers

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"

	workloadsv1alpha1 "github.com/gocardless/theatre/v5/api/workloads/v1alpha1"
)

var _ = Describe("ConsoleReconciler.userRbacSubjects", func() {
	var (
		reconciler    *ConsoleReconciler
		tpl           *workloadsv1alpha1.ConsoleTemplate
		csl           *workloadsv1alpha1.Console
		authorisation *workloadsv1alpha1.ConsoleAuthorisation

		userSubjects, approverSubjects []rbacv1.Subject
	)

	authoriserUsername := "system:serviceaccount:theatre-system:console-authoriser"

	BeforeEach(func() {
		reconciler = &ConsoleReconciler{}
		tpl = &workloadsv1alpha1.ConsoleTemplate{
			Spec: workloadsv1alpha1.ConsoleTemplateSpec{
				AdditionalAttachSubjects: []rbacv1.Subject{
					{Kind: "GoogleGroup", Name: "group@example.com"},
				},
			},
		}
		csl = &workloadsv1alpha1.Console{
			Spec: workloadsv1alpha1.ConsoleSpec{User: "creator@example.com"},
		}
		authorisation = &workloadsv1alpha1.ConsoleAuthorisation{
			Spec: workloadsv1alpha1.ConsoleAuthorisationSpec{
				Authorisations: []rbacv1.Subject{
					{Kind: "User", Name: "approver@example.com"},
					{Kind: "User", Name: authoriserUsername},
				},
			},
		}
	})

	JustBeforeEach(func() {
		userSubjects, approverSubjects = reconciler.userRbacSubjects(tpl, csl, authorisation)
	})

	Context("with both flags off", func() {
		It("binds approvers alongside the creator, as before", func() {
			Expect(userSubjects).To(ConsistOf(
				rbacv1.Subject{Kind: "GoogleGroup", Name: "group@example.com"},
				rbacv1.Subject{Kind: "User", Name: "creator@example.com"},
				rbacv1.Subject{Kind: "User", Name: "approver@example.com"},
				rbacv1.Subject{Kind: "User", Name: authoriserUsername},
			))
			Expect(approverSubjects).To(BeEmpty())
		})
	})

	Context("with ApproversWithoutExec", func() {
		BeforeEach(func() {
			reconciler.ApproversWithoutExec = true
		})

		It("binds approvers separately from the creator", func() {
			Expect(userSubjects).To(ConsistOf(
				rbacv1.Subject{Kind: "GoogleGroup", Name: "group@example.com"},
				rbacv1.Subject{Kind: "User", Name: "creator@example.com"},
			))
			Expect(approverSubjects).To(ConsistOf(
				rbacv1.Subject{Kind: "User", Name: "approver@example.com"},
				rbacv1.Subject{Kind: "User", Name: authoriserUsername},
			))
		})

		Context("before anyone has approved", func() {
			BeforeEach(func() {
				authorisation = nil
			})

			It("has no approver subjects", func() {
				Expect(approverSubjects).To(BeEmpty())
			})
		})

		Context("and SubjectsWithoutAccess", func() {
			BeforeEach(func() {
				reconciler.SubjectsWithoutAccess = []string{authoriserUsername}
			})

			It("leaves the listed approver out", func() {
				Expect(approverSubjects).To(ConsistOf(
					rbacv1.Subject{Kind: "User", Name: "approver@example.com"},
				))
			})
		})
	})

	Context("with SubjectsWithoutAccess", func() {
		BeforeEach(func() {
			reconciler.SubjectsWithoutAccess = []string{authoriserUsername}
		})

		It("leaves the listed user out of the creator's binding", func() {
			Expect(userSubjects).To(ConsistOf(
				rbacv1.Subject{Kind: "GoogleGroup", Name: "group@example.com"},
				rbacv1.Subject{Kind: "User", Name: "creator@example.com"},
				rbacv1.Subject{Kind: "User", Name: "approver@example.com"},
			))
		})

		Context("when the listed user created the console", func() {
			BeforeEach(func() {
				csl.Spec.User = authoriserUsername
			})

			It("leaves them out too", func() {
				Expect(userSubjects).NotTo(ContainElement(
					rbacv1.Subject{Kind: "User", Name: authoriserUsername},
				))
			})
		})

		Context("when the listed username appears as a ServiceAccount subject", func() {
			BeforeEach(func() {
				tpl.Spec.AdditionalAttachSubjects = append(tpl.Spec.AdditionalAttachSubjects,
					rbacv1.Subject{Kind: "ServiceAccount", Namespace: "theatre-system", Name: "console-authoriser"},
				)
			})

			It("leaves it out", func() {
				Expect(userSubjects).NotTo(ContainElement(
					rbacv1.Subject{Kind: "ServiceAccount", Namespace: "theatre-system", Name: "console-authoriser"},
				))
			})
		})

		Context("when a Group has the listed name", func() {
			BeforeEach(func() {
				tpl.Spec.AdditionalAttachSubjects = []rbacv1.Subject{
					{Kind: "Group", Name: authoriserUsername},
				}
			})

			It("keeps the group, as group names aren't usernames", func() {
				Expect(userSubjects).To(ContainElement(
					rbacv1.Subject{Kind: "Group", Name: authoriserUsername},
				))
			})
		})
	})
})

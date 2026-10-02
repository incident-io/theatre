package v1alpha1

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
)

var _ = Describe("Helpers", func() {

	Describe("ConsoleTemplate GetAuthorisationRuleForCommand", func() {
		var (
			// Inputs
			command  []string
			template ConsoleTemplate

			// Outputs
			err    error
			result ConsoleAuthorisationRule
		)

		defaultRuleAuths := 3

		BeforeEach(func() {
			// Reset to empty defaults each time, to avoid pollution between specs
			template = ConsoleTemplate{}
			command = []string{}

			// Always set a default authorisation rule, because we require one if any
			// rules are set.
			template.Spec.DefaultAuthorisationRule = &ConsoleAuthorisers{
				AuthorisationsRequired: defaultRuleAuths,
			}
		})

		JustBeforeEach(func() {
			result, err = template.GetAuthorisationRuleForCommand(command)
		})

		Context("with a default rule only", func() {
			It("returns the default rule", func() {
				Expect(result.AuthorisationsRequired).To(Equal(defaultRuleAuths))
			})
		})

		// Generally we'll never reach this case in real usage, as we should only
		// be calling GetAuthorisationRuleForCommand if HasAuthorisationRules
		// returns true.
		Context("with no rules defined", func() {
			BeforeEach(func() {
				template.Spec.DefaultAuthorisationRule = nil
				command = []string{"bash"}
			})

			It("returns an error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(BeEquivalentTo("no rules matched the command")))
			})
		})

		Context("with a basic match pattern", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						Name:                 "non-matching",
						MatchCommandElements: []string{"irb"},
					},
					{
						Name:                 "matching",
						MatchCommandElements: []string{"bash"},
					},
				}
				command = []string{"bash"}
			})

			It("matches successfully", func() {
				Expect(err).NotTo(HaveOccurred())
			})
			It("returns the name of the matching rule", func() {
				Expect(result.Name).To(Equal("matching"))
			})
		})

		Context("with a basic match pattern that is longer than the command", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						MatchCommandElements: []string{"echo", "hello"},
					},
				}
				command = []string{"echo"}
			})

			It("returns the default rule", func() {
				Expect(result.AuthorisationsRequired).To(Equal(defaultRuleAuths))
			})
		})

		Context("with a basic match pattern that is shorter than the command", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						MatchCommandElements: []string{"echo"},
					},
				}
				command = []string{"echo", "hello"}
			})

			It("returns the default rule", func() {
				Expect(result.AuthorisationsRequired).To(Equal(defaultRuleAuths))
			})
		})

		Context("with a match pattern that contains single wildcards", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						MatchCommandElements: []string{"rake", "*", "*"},
					},
				}
				command = []string{"rake", "task:do_thing", "some-args"}
			})

			It("matches successfully", func() {
				Expect(err).NotTo(HaveOccurred())
			})
			It("does not return the default rule", func() {
				Expect(result.AuthorisationsRequired).NotTo(Equal(defaultRuleAuths))
			})
		})

		Context("with a single wildcard match pattern that is longer than the command", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						MatchCommandElements: []string{"echo", "*"},
					},
				}
				command = []string{"echo"}
			})

			It("returns the default rule", func() {
				Expect(result.AuthorisationsRequired).To(Equal(defaultRuleAuths))
			})
		})

		Context("with a match pattern that contains double wildcards", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						MatchCommandElements: []string{"rails", "runner", "**"},
					},
				}
				command = []string{"rails", "runner", "thing"}
			})

			It("matches successfully", func() {
				Expect(err).NotTo(HaveOccurred())
			})
			It("does not return the default rule", func() {
				Expect(result.AuthorisationsRequired).NotTo(Equal(defaultRuleAuths))
			})

			Context("with a command that has no additional arguments", func() {
				BeforeEach(func() {
					command = []string{"rails", "runner"}
				})

				It("matches successfully", func() {
					Expect(err).NotTo(HaveOccurred())
				})
				It("does not return the default rule", func() {
					Expect(result.AuthorisationsRequired).NotTo(Equal(defaultRuleAuths))
				})
			})

			Context("with a command that is shorter than the the pre-** matchers", func() {
				BeforeEach(func() {
					command = []string{"rails"}
				})

				It("returns the default rule", func() {
					Expect(result.AuthorisationsRequired).To(Equal(defaultRuleAuths))
				})
			})
		})

		Context("with no matching rules", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						MatchCommandElements: []string{"ruby"},
					},
				}
				command = []string{"python"}
			})

			It("matches successfully", func() {
				Expect(err).NotTo(HaveOccurred())
			})
			It("returns the default rule", func() {
				Expect(result.AuthorisationsRequired).To(Equal(defaultRuleAuths))
			})
		})

		Context("with rules of multiple match command element lengths", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						Name:                 "python",
						MatchCommandElements: []string{"python"},
					},
					{
						Name:                 "perl",
						MatchCommandElements: []string{"perl", "*"},
						ConsoleAuthorisers: ConsoleAuthorisers{
							AuthorisationsRequired: 7,
						},
					},
					{
						Name:                 "php",
						MatchCommandElements: []string{"php"},
					},
				}
				command = []string{"perl", "test"}
			})

			It("matches successfully", func() {
				Expect(err).NotTo(HaveOccurred())
			})
			It("returns the name of the matching rule", func() {
				Expect(result.Name).To(Equal("perl"))
			})
			It("has the correct authorisations required", func() {
				Expect(result.AuthorisationsRequired).To(Equal(7))
			})
		})

		Context("with multiple rules containing **", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						Name:                 "python",
						MatchCommandElements: []string{"python", "**"},
					},
					{
						Name:                 "bash",
						MatchCommandElements: []string{"bash", "test", "**"},
					},
					{
						Name:                 "perl",
						MatchCommandElements: []string{"perl", "**"},
						ConsoleAuthorisers: ConsoleAuthorisers{
							AuthorisationsRequired: 7,
						},
					},
					{
						Name:                 "php",
						MatchCommandElements: []string{"php"},
					},
				}
				command = []string{"perl", "test", "case"}
			})

			It("matches successfully", func() {
				Expect(err).NotTo(HaveOccurred())
			})
			It("returns the name of the matching rule", func() {
				Expect(result.Name).To(Equal("perl"))
			})
			It("has the correct authorisations required", func() {
				Expect(result.AuthorisationsRequired).To(Equal(7))
			})
		})

		Context("with a matching rule that isn't the first or last match", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						Name:                 "python",
						MatchCommandElements: []string{"python"},
					},
					{
						Name:                 "perl",
						MatchCommandElements: []string{"perl"},
						ConsoleAuthorisers: ConsoleAuthorisers{
							AuthorisationsRequired: 7,
						},
					},
					{
						Name:                 "php",
						MatchCommandElements: []string{"php"},
					},
				}
				command = []string{"perl"}
			})

			It("matches successfully", func() {
				Expect(err).NotTo(HaveOccurred())
			})
			It("returns the name of the matching rule", func() {
				Expect(result.Name).To(Equal("perl"))
			})
			It("has the correct authorisations required", func() {
				Expect(result.AuthorisationsRequired).To(Equal(7))
			})
		})
	})

	Describe("ConsoleTemplate Validate", func() {
		var (
			template ConsoleTemplate
			err      error
		)

		BeforeEach(func() {
			// Reset to empty defaults each time, to avoid pollution between specs
			template = ConsoleTemplate{}
		})

		JustBeforeEach(func() {
			err = template.Validate()
		})

		Context("with an invalid rule", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						MatchCommandElements: []string{""},
					},
				}
			})

			It("returns an error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(ContainSubstring(".spec.authorisationRules[0].matchCommandElements[0]: an empty matcher is invalid")))
			})
		})

		Context("with a rule that contains double wildcards in the middle of a pattern", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						MatchCommandElements: []string{"bash"},
					},
					{
						MatchCommandElements: []string{"rails", "**", "other-stuff"},
					},
				}
			})

			It("returns an error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(ContainSubstring(".spec.authorisationRules[1].matchCommandElements[1]: a double wildcard is only valid at the end of the pattern")))
			})
		})

		Context("with authorisation rules but no default rule", func() {
			BeforeEach(func() {
				template.Spec.AuthorisationRules = []ConsoleAuthorisationRule{
					{
						MatchCommandElements: []string{"bash"},
					},
				}
			})

			It("returns an error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(ContainSubstring(".spec.defaultAuthorisationRule must be set if authorisation rules are defined")))
			})
		})

		Context("with valid creator rules", func() {
			BeforeEach(func() {
				template.Spec.CreatorRules = []rbacv1.Subject{
					{Kind: rbacv1.UserKind, Name: "buildkite@example.com"},
					{Kind: rbacv1.GroupKind, Name: "deployers@example.com"},
					{Kind: rbacv1.ServiceAccountKind, Namespace: "ci", Name: "deployer"},
				}
			})

			It("returns no error", func() {
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("with a creator rule of an unsupported kind", func() {
			BeforeEach(func() {
				template.Spec.CreatorRules = []rbacv1.Subject{
					{Kind: "GoogleGroup", Name: "deployers@example.com"},
				}
			})

			It("returns an error", func() {
				Expect(err).To(MatchError(ContainSubstring(`.spec.creatorRules[0]: kind must be one of User, Group or ServiceAccount, got "GoogleGroup"`)))
			})
		})

		Context("with a ServiceAccount creator rule without a namespace", func() {
			BeforeEach(func() {
				template.Spec.CreatorRules = []rbacv1.Subject{
					{Kind: rbacv1.ServiceAccountKind, Name: "deployer"},
				}
			})

			It("returns an error", func() {
				Expect(err).To(MatchError(ContainSubstring(".spec.creatorRules[0]: a ServiceAccount subject must set its namespace")))
			})
		})
	})

	Describe("ConsoleTemplate AllowsCreator", func() {
		var (
			template ConsoleTemplate
			username string
			groups   []string
		)

		BeforeEach(func() {
			template = ConsoleTemplate{}
			username = "someone@example.com"
			groups = []string{"system:authenticated", "engineers@example.com"}
		})

		allows := func() bool {
			return template.AllowsCreator(username, groups)
		}

		Context("with no creator rules", func() {
			It("allows anyone", func() {
				Expect(allows()).To(BeTrue())
			})
		})

		Context("with creator rules", func() {
			BeforeEach(func() {
				template.Spec.CreatorRules = []rbacv1.Subject{
					{Kind: rbacv1.UserKind, Name: "buildkite@example.com"},
					{Kind: rbacv1.GroupKind, Name: "deployers@example.com"},
					{Kind: rbacv1.ServiceAccountKind, Namespace: "ci", Name: "deployer"},
				}
			})

			It("rejects a caller who isn't listed", func() {
				Expect(allows()).To(BeFalse())
			})

			It("rejects a system:masters caller who isn't listed", func() {
				groups = append(groups, "system:masters")
				Expect(allows()).To(BeFalse())
			})

			It("allows a listed user", func() {
				username = "buildkite@example.com"
				Expect(allows()).To(BeTrue())
			})

			It("allows a member of a listed group", func() {
				groups = append(groups, "deployers@example.com")
				Expect(allows()).To(BeTrue())
			})

			It("allows a listed service account", func() {
				username = "system:serviceaccount:ci:deployer"
				Expect(allows()).To(BeTrue())
			})

			It("doesn't match a user whose name is a listed group", func() {
				username = "deployers@example.com"
				Expect(allows()).To(BeFalse())
			})

			It("doesn't match a group whose name is a listed user", func() {
				groups = append(groups, "buildkite@example.com")
				Expect(allows()).To(BeFalse())
			})
		})
	})
})

package pamrolebinding

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RoleBindingName", func() {
	const grant = "projects/p/locations/global/entitlements/e/grants/g1"

	It("names bindings after the binding and the local part of the user's email", func() {
		Expect(RoleBindingName("operator", "jane.doe@example.com", grant)).To(MatchRegexp(`^pam-operator-jane-doe-[0-9a-f]{8}$`))
		Expect(RoleBindingName("operator", "x_y+z@example.com", grant)).To(MatchRegexp(`^pam-operator-x-y-z-[0-9a-f]{8}$`))
	})

	It("is stable for a given binding and grant", func() {
		Expect(RoleBindingName("operator", "jane@example.com", grant)).To(Equal(RoleBindingName("operator", "jane@example.com", grant)))
	})

	It("gives each grant its own name", func() {
		Expect(RoleBindingName("operator", "jane@example.com", grant)).NotTo(Equal(RoleBindingName("operator", "jane@example.com", grant+"x")))
	})

	It("tells apart bindings whose names run together", func() {
		Expect(RoleBindingName("op", "x-jane@example.com", grant)).NotTo(Equal(RoleBindingName("op-x", "jane@example.com", grant)))
	})

	It("keeps names within the Kubernetes limit, and distinct when truncated", func() {
		long := strings.Repeat("a", 245)
		first, second := RoleBindingName(long, "alice@example.com", grant), RoleBindingName(long, "alice@example.com", grant+"x")
		Expect(len(first)).To(BeNumerically("<=", 253))
		Expect(first).NotTo(Equal(second))
	})
})

package pamrolebinding

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("roleBindingName", func() {
	It("names bindings after the binding and the local part of the user's email", func() {
		Expect(RoleBindingName("operator", "jane.doe@example.com")).To(MatchRegexp(`^pam-operator-jane-doe-[0-9a-f]{8}$`))
		Expect(RoleBindingName("operator", "x_y+z@example.com")).To(MatchRegexp(`^pam-operator-x-y-z-[0-9a-f]{8}$`))
	})

	It("is stable for a given binding and user", func() {
		Expect(RoleBindingName("operator", "jane@example.com")).To(Equal(RoleBindingName("operator", "jane@example.com")))
	})

	It("tells apart users whose local parts are the same", func() {
		Expect(RoleBindingName("operator", "jane@example.com")).NotTo(Equal(RoleBindingName("operator", "jane@example.org")))
	})

	It("tells apart bindings and users whose names run together", func() {
		Expect(RoleBindingName("op", "x-jane@example.com")).NotTo(Equal(RoleBindingName("op-x", "jane@example.com")))
	})

	It("keeps names within the Kubernetes limit, and distinct when truncated", func() {
		long := strings.Repeat("a", 245)
		alice, alfred := RoleBindingName(long, "alice@example.com"), RoleBindingName(long, "alfred@example.com")
		Expect(len(alice)).To(BeNumerically("<=", 253))
		Expect(alice).NotTo(Equal(alfred))
	})
})

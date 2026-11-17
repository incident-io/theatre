package pamrolebinding

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("roleBindingNames", func() {
	It("names bindings after the local part of the user's email", func() {
		names := roleBindingNames("operator", []string{"jane.doe@example.com", "x_y+z@example.com"})
		Expect(names).To(Equal(map[string]string{
			"jane.doe@example.com": "pam-operator-jane-doe",
			"x_y+z@example.com":    "pam-operator-x-y-z",
		}))
	})

	It("disambiguates users whose local parts clash", func() {
		names := roleBindingNames("operator", []string{"jane@example.com", "jane@example.org"})
		Expect(names["jane@example.com"]).To(HavePrefix("pam-operator-jane-"))
		Expect(names["jane@example.org"]).To(HavePrefix("pam-operator-jane-"))
		Expect(names["jane@example.com"]).NotTo(Equal(names["jane@example.org"]))
	})

	It("keeps names within the Kubernetes limit", func() {
		long := strings.Repeat("a", 300) + "@example.com"
		Expect(len(roleBindingNames("operator", []string{long})[long])).To(BeNumerically("<=", 253))
	})
})

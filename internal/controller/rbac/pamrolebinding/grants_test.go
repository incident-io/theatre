package pamrolebinding

import (
	"time"

	pampb "cloud.google.com/go/privilegedaccessmanager/apiv1/privilegedaccessmanagerpb"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ = Describe("FromProto", func() {
	created := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	activated := created.Add(5 * time.Minute)

	grant := func(state pampb.Grant_State, events ...*pampb.Grant_Timeline_Event) *pampb.Grant {
		return &pampb.Grant{
			Name:              "projects/p/locations/global/entitlements/e/grants/abc-123",
			Requester:         "Alice@Example.com",
			State:             state,
			CreateTime:        timestamppb.New(created),
			RequestedDuration: durationpb.New(time.Hour),
			Timeline:          &pampb.Grant_Timeline{Events: events},
		}
	}
	approvedEvent := &pampb.Grant_Timeline_Event{
		EventTime: timestamppb.New(created.Add(time.Minute)),
		Event: &pampb.Grant_Timeline_Event_Approved_{
			Approved: &pampb.Grant_Timeline_Event_Approved{Actor: "bob@example.com"},
		},
	}
	activatedEvent := &pampb.Grant_Timeline_Event{
		EventTime: timestamppb.New(activated),
		Event:     &pampb.Grant_Timeline_Event_Activated_{Activated: &pampb.Grant_Timeline_Event_Activated{}},
	}

	It("ends the requested duration after activation, and records the approver", func() {
		g, ok := FromProto(grant(pampb.Grant_ACTIVE, approvedEvent, activatedEvent))
		Expect(ok).To(BeTrue())
		Expect(g.Requester).To(Equal("alice@example.com"))
		Expect(g.Approver).To(Equal("bob@example.com"))
		Expect(g.EndsAt).To(Equal(activated.Add(time.Hour)))
		Expect(g.ID()).To(Equal("abc-123"))
	})

	It("leaves the approver empty when no approval was needed", func() {
		g, ok := FromProto(grant(pampb.Grant_ACTIVE, activatedEvent))
		Expect(ok).To(BeTrue())
		Expect(g.Approver).To(BeEmpty())
	})

	It("falls back to the creation time, ending early rather than late", func() {
		g, ok := FromProto(grant(pampb.Grant_ACTIVE))
		Expect(ok).To(BeTrue())
		Expect(g.EndsAt).To(Equal(created.Add(time.Hour)))
	})

	DescribeTable("ignores grants that aren't active",
		func(state pampb.Grant_State) {
			_, ok := FromProto(grant(state, activatedEvent))
			Expect(ok).To(BeFalse())
		},
		Entry("awaiting approval", pampb.Grant_APPROVAL_AWAITED),
		Entry("activating", pampb.Grant_ACTIVATING),
		Entry("ended", pampb.Grant_ENDED),
		Entry("expired", pampb.Grant_EXPIRED),
		Entry("revoked", pampb.Grant_REVOKED),
		Entry("withdrawn", pampb.Grant_WITHDRAWN),
	)
})

package pamrolebinding

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	pam "cloud.google.com/go/privilegedaccessmanager/apiv1"
	pampb "cloud.google.com/go/privilegedaccessmanager/apiv1/privilegedaccessmanagerpb"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrEntitlementNotFound is returned when PAM says the entitlement doesn't exist, which
// usually means a typo in the PAMRoleBinding's spec.
var ErrEntitlementNotFound = errors.New("entitlement not found")

type Grant struct {
	Name string
	// Requester is unvalidated: check it with BindableUser before binding it.
	Requester string
	// Approvers are in the order they approved.
	Approvers []string
	EndsAt    time.Time
}

// ID is the last segment of the grant's name. Audit logs name its project inconsistently
// (ID or number), so the ID is what to search them by.
func (g Grant) ID() string {
	return path.Base(g.Name)
}

type GrantLister interface {
	// ListActiveGrants returns ErrEntitlementNotFound if the entitlement doesn't exist. Any
	// other error means the list is unknown, and must never be treated as "no grants".
	ListActiveGrants(ctx context.Context, entitlement string) ([]Grant, error)
}

// activeFilter asks PAM for active grants only, so we don't page through an entitlement's
// whole history every few seconds. Grants are checked for ACTIVE again client-side.
const activeFilter = "state = ACTIVE"

type PAMGrantLister struct {
	client *pam.Client
}

// NewPAMGrantLister creates a GrantLister using Application Default Credentials.
func NewPAMGrantLister(ctx context.Context) (*PAMGrantLister, error) {
	client, err := pam.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating PAM client: %w", err)
	}

	return &PAMGrantLister{client: client}, nil
}

func (l *PAMGrantLister) Close() error {
	return l.client.Close()
}

func (l *PAMGrantLister) ListActiveGrants(ctx context.Context, entitlement string) ([]Grant, error) {
	grants, err := l.list(ctx, entitlement, activeFilter)
	if err != nil && status.Code(err) == codes.InvalidArgument {
		// Filter client-side rather than never seeing a grant. Only for this call: an
		// InvalidArgument can also mean a malformed entitlement.
		grants, err = l.list(ctx, entitlement, "")
	}

	return grants, err
}

func (l *PAMGrantLister) list(ctx context.Context, entitlement, filter string) ([]Grant, error) {
	grants := []Grant{}
	it := l.client.ListGrants(ctx, &pampb.ListGrantsRequest{Parent: entitlement, Filter: filter, PageSize: 100})
	for {
		pb, err := it.Next()
		if err == iterator.Done {
			return grants, nil
		}
		if err != nil {
			if status.Code(err) == codes.NotFound {
				return nil, fmt.Errorf("%w: %s", ErrEntitlementNotFound, entitlement)
			}
			return nil, fmt.Errorf("listing grants on %s: %w", entitlement, err)
		}

		if grant, ok := FromProto(pb); ok {
			grants = append(grants, grant)
		}
	}
}

// FromProto returns false if the grant isn't active or we can't tell when it ends.
func FromProto(pb *pampb.Grant) (Grant, bool) {
	if pb.GetState() != pampb.Grant_ACTIVE || pb.GetRequestedDuration() == nil {
		return Grant{}, false
	}

	var activatedAt time.Time
	var approvers []string
	for _, event := range pb.GetTimeline().GetEvents() {
		switch {
		case event.GetActivated() != nil:
			activatedAt = event.GetEventTime().AsTime()
		case event.GetApproved() != nil:
			approvers = append(approvers, normaliseEmail(event.GetApproved().GetActor()))
		}
	}

	// An active grant should always have been activated. If it somehow hasn't, assume it
	// started when it was created, which can only end the binding early, never late.
	if activatedAt.IsZero() {
		if pb.GetCreateTime() == nil {
			return Grant{}, false
		}
		activatedAt = pb.GetCreateTime().AsTime()
	}

	return Grant{
		Name:      pb.GetName(),
		Requester: pb.GetRequester(),
		Approvers: approvers,
		EndsAt:    activatedAt.Add(pb.GetRequestedDuration().AsDuration()),
	}, true
}

// normaliseEmail lowercases, because Kubernetes compares usernames case-sensitively and
// Google authenticates users by their lowercased email.
func normaliseEmail(principal string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(principal), "user:"))
}

// BindableUser returns the Kubernetes username for a grant's requester. GKE authenticates
// Google accounts by email, so only a bare email or "user:" principal can be bound; other
// principal types wouldn't match any Kubernetes user. Service accounts are refused even as
// bare emails, though GKE would accept them: just-in-time access is for people.
func BindableUser(requester string) (string, error) {
	raw := strings.TrimSpace(requester)
	if prefix, _, ok := strings.Cut(raw, ":"); ok && prefix != "user" {
		return "", fmt.Errorf("requester %q isn't a user", requester)
	}

	email := normaliseEmail(raw)
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || strings.ContainsAny(email, " /:") {
		return "", fmt.Errorf("requester %q isn't an email address", requester)
	}
	if strings.HasSuffix(domain, "gserviceaccount.com") {
		return "", fmt.Errorf("requester %q is a service account", requester)
	}

	return email, nil
}

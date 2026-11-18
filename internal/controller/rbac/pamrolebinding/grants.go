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

// Grant is an active PAM grant.
type Grant struct {
	// Name is the full resource name of the grant.
	Name string
	// Requester is the principal who requested the grant, as PAM reports it. Check it with
	// BindableUser before binding it.
	Requester string
	// Approvers are the email addresses of everyone who approved the grant, in the order
	// they approved. PAM supports several approval levels, each needing one or more
	// approvals. Empty if the grant needed no approval.
	Approvers []string
	// EndsAt is when the grant ends.
	EndsAt time.Time
}

// ID is the grant's ID, the last segment of its name. Audit logs name the grant's project
// inconsistently (ID or number), so the ID is the reliable thing to search them by.
func (g Grant) ID() string {
	return path.Base(g.Name)
}

// GrantLister lists the active grants on a PAM entitlement.
type GrantLister interface {
	// ListActiveGrants returns every grant on the entitlement that is currently active.
	// It returns ErrEntitlementNotFound if the entitlement doesn't exist. Any other error
	// means the list is unknown, and must never be treated as "no grants".
	ListActiveGrants(ctx context.Context, entitlement string) ([]Grant, error)
}

// activeFilter asks PAM for active grants only, so we don't page through an entitlement's
// whole history every few seconds. Grants are checked for ACTIVE again client-side.
const activeFilter = "state = ACTIVE"

// PAMGrantLister lists grants from the Google Cloud Privileged Access Manager API.
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
		// If PAM rejects the filter, filter client-side rather than never seeing a grant.
		// Only for this call: an InvalidArgument can also mean a malformed entitlement, which
		// shouldn't turn filtering off for every other PAMRoleBinding.
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

// FromProto converts an API grant, returning false if it isn't active or we can't tell
// when it ends.
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

// normaliseEmail strips a "user:" prefix, should PAM ever include one, and lowercases the
// address, since Kubernetes compares usernames case-sensitively and Google returns them
// lowercased.
func normaliseEmail(principal string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(principal), "user:"))
}

// BindableUser returns the Kubernetes username to bind for a grant's requester, or an
// error if it isn't a principal we can or should bind.
//
// GKE authenticates Google accounts by their email, so only a bare email or a "user:"
// principal is bound. Groups can't request grants (the requester is always the person
// who asked), and anything else, such as a workforce-federated "principal://..." or a
// "serviceAccount:" principal, wouldn't match a Kubernetes user.
//
// Service accounts are refused too, even as bare emails, though GKE would accept them:
// just-in-time access is for people, and automation should have standing access that's
// reviewed in code rather than self-approved grants.
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

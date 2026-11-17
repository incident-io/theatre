package pamrolebinding

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	rbacv1alpha1 "github.com/gocardless/theatre/v5/api/rbac/v1alpha1"
)

const (
	// LabelPAMRoleBinding names the PAMRoleBinding that owns a RoleBinding, so the
	// controller can find its own bindings with a label selector.
	LabelPAMRoleBinding = "rbac.crd.gocardless.com/pam-role-binding"

	// Finalizer makes sure a PAMRoleBinding's RoleBindings are deleted with it, even if it's
	// deleted with --cascade=orphan, which would otherwise leave them in place for good.
	Finalizer = "rbac.crd.gocardless.com/pam-role-binding"

	annotationPrefix = "pam.rbac.crd.gocardless.com/"
	// AnnotationGrant is the grant's full resource name, for `gcloud pam grants describe`.
	AnnotationGrant = annotationPrefix + "grant"
	// AnnotationGrantID is the grant's ID, for searching audit logs.
	AnnotationGrantID = annotationPrefix + "grant-id"
	// AnnotationApprover is the approver's email, absent if no approval was needed.
	AnnotationApprover = annotationPrefix + "approver"
	// AnnotationRequester is the user's email. Labels can't hold an '@'.
	AnnotationRequester = annotationPrefix + "requester"
	// AnnotationEndsAt is when the grant ends, in RFC 3339. The controller deletes the
	// RoleBinding at this time even if PAM can't be reached.
	AnnotationEndsAt = annotationPrefix + "ends-at"

	EventGrantBound     = "GrantBound"
	EventGrantExpired   = "GrantExpired"
	EventGrantWithdrawn = "GrantWithdrawn"
	EventSyncFailed     = "SyncFailed"

	// maxBackoff caps how long we wait between attempts while PAM is failing. Expiry is
	// scheduled separately, so this only delays new grants and early withdrawals.
	maxBackoff = time.Minute

	// pamTimeout bounds each call to PAM, so a hung request can't hold up expiry.
	pamTimeout = 30 * time.Second

	// expiryMargin removes bindings this long before their grant ends, to allow for skew
	// between Google's clock, which sets the end time, and ours.
	expiryMargin = 10 * time.Second
)

// Reconciler keeps one RoleBinding per user with an active grant on a PAMRoleBinding's
// entitlement.
//
// It needs create, delete, get, list and watch on RoleBindings, and bind on the roles it
// hands out. It never updates a RoleBinding: one that's wrong is deleted and recreated.
type Reconciler struct {
	client.Client
	// APIReader reads straight from the API server, bypassing the cache, to check whether a
	// RoleBinding that already exists is ours.
	APIReader client.Reader
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Grants    GrantLister
	// RefreshInterval is how often each PAMRoleBinding is synced with PAM.
	RefreshInterval time.Duration
	// EntitlementPrefixes, if set, limits which entitlements a PAMRoleBinding may name, e.g.
	// to projects you control. Anyone who can create a PAMRoleBinding could otherwise point
	// it at an entitlement in a project of their own.
	EntitlementPrefixes []string
	// Now is overridable for tests.
	Now func() time.Time

	mu       sync.Mutex
	failures map[types.NamespacedName]int
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	r.failures = map[types.NamespacedName]int{}

	return ctrl.NewControllerManagedBy(mgr).
		// Syncs are driven by RequeueAfter. Only spec, deletion and finalizer changes should
		// trigger one early, not our own status writes.
		For(&rbacv1alpha1.PAMRoleBinding{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.AnnotationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		))).
		// Recreate a binding promptly if someone deletes it while its grant is active.
		Owns(&rbacv1.RoleBinding{}).
		// Several workers, so one slow call to PAM can't hold up other bindings' expiry.
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues("pamrolebinding", req.NamespacedName)

	prb := &rbacv1alpha1.PAMRoleBinding{}
	if err := r.Get(ctx, req.NamespacedName, prb); err != nil {
		if apierrors.IsNotFound(err) {
			forgetMetrics(req.Namespace, req.Name)
			r.resetFailures(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !prb.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, prb)
	}

	if !controllerutil.ContainsFinalizer(prb, Finalizer) {
		controllerutil.AddFinalizer(prb, Finalizer)
		if err := r.Update(ctx, prb); err != nil {
			return ctrl.Result{}, err
		}
	}

	now := r.Now()

	owned, err := r.ownedRoleBindings(ctx, prb)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Remove bindings whose grant has ended before asking PAM anything, so expiry never
	// depends on PAM answering.
	var errs []error
	for name, rb := range owned {
		if expired(rb, now) {
			if err := r.deleteRoleBinding(ctx, prb, rb, EventGrantExpired); err != nil {
				errs = append(errs, err)
				continue
			}
			delete(owned, name)
		}
	}

	if !r.entitlementAllowed(prb.Spec.Entitlement) {
		err := fmt.Errorf("entitlement %s isn't under any of rbac-manager's allowed prefixes (%s)",
			prb.Spec.Entitlement, strings.Join(r.EntitlementPrefixes, ", "))
		for name, rb := range owned {
			if delErr := r.deleteRoleBinding(ctx, prb, rb, EventGrantWithdrawn); delErr != nil {
				errs = append(errs, delErr)
				continue
			}
			delete(owned, name)
		}
		return r.syncFailed(ctx, logger, prb, owned, now, rbacv1alpha1.PAMRoleBindingReasonEntitlementNotAllowed, errors.Join(append([]error{err}, errs...)...))
	}

	listCtx, cancel := context.WithTimeout(ctx, pamTimeout)
	grants, listErr := r.Grants.ListActiveGrants(listCtx, prb.Spec.Entitlement)
	cancel()
	if listErr != nil {
		reason := rbacv1alpha1.PAMRoleBindingReasonPAMUnreachable
		if errors.Is(listErr, ErrEntitlementNotFound) {
			reason = rbacv1alpha1.PAMRoleBindingReasonEntitlementNotFound
		}
		return r.syncFailed(ctx, logger, prb, owned, now, reason, errors.Join(append([]error{listErr}, errs...)...))
	}

	desired := desiredBindings(prb, grants, now)

	for name, rb := range owned {
		want, ok := desired[name]
		if ok && matches(rb, want) {
			continue
		}
		reason := EventGrantWithdrawn
		if ok {
			reason = "" // replaced by a newer grant, recreated below
		}
		if err := r.deleteRoleBinding(ctx, prb, rb, reason); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(owned, name)
	}

	for name, want := range desired {
		if _, ok := owned[name]; ok {
			continue
		}
		if err := r.createRoleBinding(ctx, prb, want); err != nil {
			errs = append(errs, err)
			continue
		}
		owned[name] = want
	}

	prb.Status.LastSyncTime = &metav1.Time{Time: now}
	prb.Status.ActiveGrants = activeGrantStatus(owned)
	lastSyncTimestamp.WithLabelValues(prb.Namespace, prb.Name).Set(float64(now.Unix()))
	entitlementNotFound.WithLabelValues(prb.Namespace, prb.Name).Set(0)
	activeGrants.WithLabelValues(prb.Namespace, prb.Name).Set(float64(len(owned)))

	if len(errs) > 0 {
		err := errors.Join(errs...)
		logger.Error(err, "failed to reconcile RoleBindings")
		r.setCondition(prb, metav1.ConditionFalse, rbacv1alpha1.PAMRoleBindingReasonRoleBindingFailed, err.Error())
		r.Recorder.Event(prb, corev1.EventTypeWarning, EventSyncFailed, err.Error())
		r.updateStatus(ctx, logger, prb)
		return ctrl.Result{RequeueAfter: r.backoff(req.NamespacedName, owned, now)}, nil
	}

	r.resetFailures(req.NamespacedName)
	r.setCondition(prb, metav1.ConditionTrue, rbacv1alpha1.PAMRoleBindingReasonSynced,
		fmt.Sprintf("%d active grant(s) bound", len(owned)))
	r.updateStatus(ctx, logger, prb)

	return ctrl.Result{RequeueAfter: r.nextSync(owned, now, r.RefreshInterval)}, nil
}

// syncFailed handles a sync we couldn't finish. A failed list from PAM says nothing about
// which grants are active, so it never removes access early: expired bindings have
// already been removed by the time we get here.
func (r *Reconciler) syncFailed(ctx context.Context, logger logr.Logger, prb *rbacv1alpha1.PAMRoleBinding, remaining map[string]*rbacv1.RoleBinding, now time.Time, reason string, err error) (ctrl.Result, error) {
	logger.Error(err, "failed to sync with PAM", "reason", reason)

	notFound := 0.0
	if reason == rbacv1alpha1.PAMRoleBindingReasonEntitlementNotFound {
		notFound = 1
	}
	entitlementNotFound.WithLabelValues(prb.Namespace, prb.Name).Set(notFound)
	activeGrants.WithLabelValues(prb.Namespace, prb.Name).Set(float64(len(remaining)))

	prb.Status.ActiveGrants = activeGrantStatus(remaining)
	r.setCondition(prb, metav1.ConditionFalse, reason, err.Error())
	r.Recorder.Event(prb, corev1.EventTypeWarning, EventSyncFailed, err.Error())
	r.updateStatus(ctx, logger, prb)

	return ctrl.Result{RequeueAfter: r.backoff(types.NamespacedName{Namespace: prb.Namespace, Name: prb.Name}, remaining, now)}, nil
}

// updateStatus writes status, logging rather than returning a failure: returning an error
// would swap our expiry-aware RequeueAfter for the rate limiter's backoff, which can run to
// many minutes.
func (r *Reconciler) updateStatus(ctx context.Context, logger logr.Logger, prb *rbacv1alpha1.PAMRoleBinding) {
	if err := r.Status().Update(ctx, prb); err != nil && !apierrors.IsConflict(err) {
		logger.Error(err, "failed to update status")
	}
}

// finalize deletes every RoleBinding this PAMRoleBinding made, then lets it go. Bindings
// are found by label rather than owner, since `--cascade=orphan` strips the owner
// references before we get here.
func (r *Reconciler) finalize(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding) error {
	if !controllerutil.ContainsFinalizer(prb, Finalizer) {
		return nil
	}

	list := &rbacv1.RoleBindingList{}
	if err := r.APIReader.List(ctx, list, client.InNamespace(prb.Namespace), client.MatchingLabels{LabelPAMRoleBinding: prb.Name}); err != nil {
		return fmt.Errorf("listing RoleBindings: %w", err)
	}
	for i := range list.Items {
		rb := &list.Items[i]
		// Leave alone anything owned by something else that happens to carry the label.
		if owner := metav1.GetControllerOf(rb); owner != nil && owner.UID != prb.UID {
			continue
		}
		if err := r.deleteRoleBinding(ctx, prb, rb, EventGrantWithdrawn); err != nil {
			return err
		}
	}

	controllerutil.RemoveFinalizer(prb, Finalizer)
	return r.Update(ctx, prb)
}

func (r *Reconciler) entitlementAllowed(entitlement string) bool {
	if len(r.EntitlementPrefixes) == 0 {
		return true
	}
	for _, prefix := range r.EntitlementPrefixes {
		if strings.HasPrefix(entitlement, prefix) {
			return true
		}
	}
	return false
}

// backoff doubles the wait after each consecutive failure, up to maxBackoff, but always
// wakes up in time to remove the next binding that expires.
func (r *Reconciler) backoff(key types.NamespacedName, bindings map[string]*rbacv1.RoleBinding, now time.Time) time.Duration {
	r.mu.Lock()
	r.failures[key]++
	n := r.failures[key]
	r.mu.Unlock()

	wait := r.RefreshInterval
	for i := 1; i < n && wait < maxBackoff; i++ {
		wait *= 2
	}
	if wait > maxBackoff {
		wait = maxBackoff
	}

	return r.nextSync(bindings, now, wait)
}

func (r *Reconciler) resetFailures(key types.NamespacedName) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failures, key)
}

// nextSync returns the sooner of wait and the moment the next binding expires.
func (r *Reconciler) nextSync(bindings map[string]*rbacv1.RoleBinding, now time.Time, wait time.Duration) time.Duration {
	for _, rb := range bindings {
		if endsAt, ok := endsAt(rb); ok {
			if until := endsAt.Add(-expiryMargin).Sub(now) + time.Second; until < wait {
				wait = until
			}
		}
	}
	if wait < time.Second {
		wait = time.Second
	}
	return wait
}

func (r *Reconciler) ownedRoleBindings(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding) (map[string]*rbacv1.RoleBinding, error) {
	list := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, list, client.InNamespace(prb.Namespace), client.MatchingLabels{LabelPAMRoleBinding: prb.Name}); err != nil {
		return nil, fmt.Errorf("listing RoleBindings: %w", err)
	}

	owned := map[string]*rbacv1.RoleBinding{}
	for i := range list.Items {
		rb := &list.Items[i]
		if metav1.IsControlledBy(rb, prb) {
			owned[rb.Name] = rb
		}
	}
	return owned, nil
}

func (r *Reconciler) createRoleBinding(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding, rb *rbacv1.RoleBinding) error {
	if err := controllerutil.SetControllerReference(prb, rb, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, rb); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Our cache may not have caught up with a binding we've just created.
			existing := &rbacv1.RoleBinding{}
			if getErr := r.APIReader.Get(ctx, client.ObjectKeyFromObject(rb), existing); getErr == nil && metav1.IsControlledBy(existing, prb) {
				return nil
			}
			return fmt.Errorf("RoleBinding %s already exists and isn't owned by this PAMRoleBinding", rb.Name)
		}
		return fmt.Errorf("creating RoleBinding %s: %w", rb.Name, err)
	}

	r.Recorder.Eventf(prb, corev1.EventTypeNormal, EventGrantBound,
		"Bound %s to %s %s until %s (grant %s)", rb.Annotations[AnnotationRequester],
		rb.RoleRef.Kind, rb.RoleRef.Name, rb.Annotations[AnnotationEndsAt], rb.Annotations[AnnotationGrantID])
	return nil
}

func (r *Reconciler) deleteRoleBinding(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding, rb *rbacv1.RoleBinding, reason string) error {
	err := r.Delete(ctx, rb, client.Preconditions{UID: &rb.UID})
	// A UID precondition conflict means this binding is already gone, replaced by another
	// of the same name.
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return fmt.Errorf("deleting RoleBinding %s: %w", rb.Name, err)
	}

	if reason != "" {
		r.Recorder.Eventf(prb, corev1.EventTypeNormal, reason,
			"Unbound %s (grant %s)", rb.Annotations[AnnotationRequester], rb.Annotations[AnnotationGrantID])
	}
	return nil
}

func (r *Reconciler) setCondition(prb *rbacv1alpha1.PAMRoleBinding, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&prb.Status.Conditions, metav1.Condition{
		Type:               rbacv1alpha1.PAMRoleBindingConditionSynced,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: prb.Generation,
	})
}

// desiredBindings works out one RoleBinding per user with an active grant. A user with
// several grants gets one binding, for the grant that ends last.
func desiredBindings(prb *rbacv1alpha1.PAMRoleBinding, grants []Grant, now time.Time) map[string]*rbacv1.RoleBinding {
	latest := map[string]Grant{}
	for _, grant := range grants {
		if grant.Requester == "" || !grant.EndsAt.Add(-expiryMargin).After(now) {
			continue
		}
		if current, ok := latest[grant.Requester]; !ok || grant.EndsAt.After(current.EndsAt) {
			latest[grant.Requester] = grant
		}
	}

	desired := map[string]*rbacv1.RoleBinding{}
	for user, grant := range latest {
		annotations := map[string]string{
			AnnotationGrant:     grant.Name,
			AnnotationGrantID:   grant.ID(),
			AnnotationRequester: user,
			AnnotationEndsAt:    grant.EndsAt.UTC().Format(time.RFC3339),
		}
		if grant.Approver != "" {
			annotations[AnnotationApprover] = grant.Approver
		}

		name := RoleBindingName(prb.Name, user)
		desired[name] = &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Namespace:   prb.Namespace,
				Labels:      map[string]string{LabelPAMRoleBinding: prb.Name},
				Annotations: annotations,
			},
			RoleRef: prb.Spec.RoleRef,
			Subjects: []rbacv1.Subject{{
				APIGroup: rbacv1.GroupName,
				Kind:     rbacv1.UserKind,
				Name:     user,
			}},
		}
	}
	return desired
}

// matches reports whether an existing binding already reflects the desired grant.
func matches(existing, desired *rbacv1.RoleBinding) bool {
	if existing.RoleRef != desired.RoleRef || len(existing.Subjects) != 1 || existing.Subjects[0] != desired.Subjects[0] {
		return false
	}
	for _, key := range []string{AnnotationGrant, AnnotationApprover, AnnotationRequester, AnnotationEndsAt} {
		if existing.Annotations[key] != desired.Annotations[key] {
			return false
		}
	}
	return true
}

func endsAt(rb *rbacv1.RoleBinding) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339, rb.Annotations[AnnotationEndsAt])
	return t, err == nil
}

// expired reports whether a binding's grant has ended, or is within expiryMargin of
// ending. A binding we can't read an end time from is treated as expired, so it can never
// outstay its grant.
func expired(rb *rbacv1.RoleBinding, now time.Time) bool {
	t, ok := endsAt(rb)
	return !ok || !t.Add(-expiryMargin).After(now)
}

func activeGrantStatus(bindings map[string]*rbacv1.RoleBinding) []rbacv1alpha1.PAMGrant {
	out := make([]rbacv1alpha1.PAMGrant, 0, len(bindings))
	for name, rb := range bindings {
		t, _ := endsAt(rb)
		out = append(out, rbacv1alpha1.PAMGrant{
			User:        rb.Annotations[AnnotationRequester],
			Grant:       rb.Annotations[AnnotationGrant],
			Approver:    rb.Annotations[AnnotationApprover],
			EndsAt:      metav1.Time{Time: t},
			RoleBinding: name,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

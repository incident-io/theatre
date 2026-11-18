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
	// LabelPAMRoleBinding names the PAMRoleBinding that made a RoleBinding, cut to 63
	// characters. Never use it to decide ownership: anyone who can edit a RoleBinding can
	// change it. The owner reference decides.
	LabelPAMRoleBinding = "rbac.crd.gocardless.com/pam-role-binding"

	// Finalizer deletes a PAMRoleBinding's RoleBindings with it, including after
	// `--cascade=orphan`, which would otherwise leave them in place for good.
	Finalizer = "rbac.crd.gocardless.com/pam-role-binding"

	annotationPrefix  = "pam.rbac.crd.gocardless.com/"
	AnnotationGrant   = annotationPrefix + "grant"
	AnnotationGrantID = annotationPrefix + "grant-id"
	// AnnotationApprovers is comma-separated, in the order they approved.
	AnnotationApprovers = annotationPrefix + "approvers"
	// AnnotationRequester holds the user's email, which a label can't (no '@').
	AnnotationRequester = annotationPrefix + "requester"
	// AnnotationEndsAt is RFC 3339. Expiry is enforced from this, not from PAM, so it works
	// while PAM is unreachable.
	AnnotationEndsAt = annotationPrefix + "ends-at"

	EventGrantBound     = "GrantBound"
	EventGrantExpired   = "GrantExpired"
	EventGrantWithdrawn = "GrantWithdrawn"
	EventSyncFailed     = "SyncFailed"
	EventGrantSkipped   = "GrantSkipped"
	// EventNamespaceRemoved is for bindings removed from a namespace that's left
	// spec.namespaces while the grant is still active elsewhere.
	EventNamespaceRemoved = "NamespaceRemoved"

	// maxBackoff caps how long we wait between attempts while PAM is failing. Expiry is
	// scheduled separately, so this only delays new grants and early withdrawals.
	maxBackoff = time.Minute

	// pamTimeout bounds each call to PAM. During a PAM outage every PAMRoleBinding waits
	// this long, so with N of them an expiry can wait about ceil(N/workers) * pamTimeout.
	pamTimeout = 10 * time.Second

	// expiryMargin removes bindings this long before their grant ends, to allow for skew
	// between Google's clock, which sets the end time, and ours.
	expiryMargin = 10 * time.Second
)

// Reconciler never updates a RoleBinding: one that's wrong is deleted and recreated. So it
// needs only create, delete, get, list and watch on RoleBindings, plus bind on the roles
// it hands out.
type Reconciler struct {
	client.Client
	// APIReader bypasses the cache, to tell a binding we've only just created from one that
	// isn't ours.
	APIReader       client.Reader
	Log             logr.Logger
	Scheme          *runtime.Scheme
	Recorder        record.EventRecorder
	Grants          GrantLister
	RefreshInterval time.Duration
	// Projects are the IDs and numbers of the only projects whose entitlements are
	// honoured. Otherwise anyone who can create a PAMRoleBinding could point it at an
	// entitlement in a project they control. Empty allows none.
	Projects []string
	Now      func() time.Time

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
		// So a binding deleted while its grant is active is recreated straight away.
		Owns(&rbacv1.RoleBinding{}).
		// Several workers, so one slow call to PAM can't hold up other bindings' expiry.
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues("pamrolebinding", req.Name)

	prb := &rbacv1alpha1.PAMRoleBinding{}
	if err := r.Get(ctx, req.NamespacedName, prb); err != nil {
		if apierrors.IsNotFound(err) {
			forgetMetrics(req.Name)
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
	for key, rb := range owned {
		if expired(rb, now) {
			if err := r.deleteRoleBinding(ctx, prb, rb, EventGrantExpired); err != nil {
				errs = append(errs, err)
				continue
			}
			delete(owned, key)
		}
	}

	if !r.entitlementAllowed(prb.Spec.Entitlement) {
		err := fmt.Errorf("entitlement %s isn't in rbac-manager's own project (%s)",
			prb.Spec.Entitlement, strings.Join(r.Projects, " / "))
		for key, rb := range owned {
			if delErr := r.deleteRoleBinding(ctx, prb, rb, EventGrantWithdrawn); delErr != nil {
				errs = append(errs, delErr)
				continue
			}
			delete(owned, key)
		}
		return r.syncFailed(ctx, logger, prb, owned, now, rbacv1alpha1.PAMRoleBindingReasonEntitlementNotAllowed, errors.Join(append([]error{err}, errs...)...))
	}

	listCtx, cancel := context.WithTimeout(ctx, pamTimeout)
	grants, listErr := r.Grants.ListActiveGrants(listCtx, prb.Spec.Entitlement)
	cancel()
	// The call to PAM can take up to pamTimeout, so work out what has ended, and when to
	// next wake up, from the time it returned.
	now = r.Now()
	if listErr != nil {
		reason := rbacv1alpha1.PAMRoleBindingReasonPAMUnreachable
		if errors.Is(listErr, ErrEntitlementNotFound) {
			reason = rbacv1alpha1.PAMRoleBindingReasonEntitlementNotFound
		}
		return r.syncFailed(ctx, logger, prb, owned, now, reason, errors.Join(append([]error{listErr}, errs...)...))
	}

	desired, skipped := desiredBindings(prb, grants, now)
	for _, err := range skipped {
		logger.Info("skipping grant", "error", err.Error())
		r.Recorder.Event(prb, corev1.EventTypeWarning, EventGrantSkipped, err.Error())
	}

	stillGranted := map[string]bool{}
	for key := range desired {
		stillGranted[key.Name] = true
	}

	for key, rb := range owned {
		want, ok := desired[key]
		if ok && matches(rb, want) {
			continue
		}
		reason := EventGrantWithdrawn
		switch {
		case ok:
			reason = "" // replaced by a newer grant, recreated below
		case stillGranted[key.Name]:
			reason = EventNamespaceRemoved
		}
		if err := r.deleteRoleBinding(ctx, prb, rb, reason); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(owned, key)
	}

	for key, want := range desired {
		if _, ok := owned[key]; ok {
			continue
		}
		if err := r.createRoleBinding(ctx, prb, want); err != nil {
			errs = append(errs, err)
			continue
		}
		owned[key] = want
	}

	prb.Status.LastSyncTime = &metav1.Time{Time: now}
	prb.Status.ActiveGrants = activeGrantStatus(owned)
	lastSyncTimestamp.WithLabelValues(prb.Name).Set(float64(now.Unix()))
	entitlementNotFound.WithLabelValues(prb.Name).Set(0)
	activeGrants.WithLabelValues(prb.Name).Set(float64(len(prb.Status.ActiveGrants)))

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
		fmt.Sprintf("%d active grant(s) bound in %d namespace(s)", len(prb.Status.ActiveGrants), len(prb.Spec.Namespaces)))
	r.updateStatus(ctx, logger, prb)

	return ctrl.Result{RequeueAfter: r.nextSync(owned, now, r.RefreshInterval)}, nil
}

// syncFailed never removes access: a failed list from PAM says nothing about which grants
// are active. Expired bindings have already been removed before PAM was called.
func (r *Reconciler) syncFailed(ctx context.Context, logger logr.Logger, prb *rbacv1alpha1.PAMRoleBinding, remaining map[types.NamespacedName]*rbacv1.RoleBinding, now time.Time, reason string, err error) (ctrl.Result, error) {
	logger.Error(err, "failed to sync with PAM", "reason", reason)

	notFound := 0.0
	if reason == rbacv1alpha1.PAMRoleBindingReasonEntitlementNotFound {
		notFound = 1
	}
	entitlementNotFound.WithLabelValues(prb.Name).Set(notFound)

	prb.Status.ActiveGrants = activeGrantStatus(remaining)
	activeGrants.WithLabelValues(prb.Name).Set(float64(len(prb.Status.ActiveGrants)))
	r.setCondition(prb, metav1.ConditionFalse, reason, err.Error())
	r.Recorder.Event(prb, corev1.EventTypeWarning, EventSyncFailed, err.Error())
	r.updateStatus(ctx, logger, prb)

	return ctrl.Result{RequeueAfter: r.backoff(types.NamespacedName{Namespace: prb.Namespace, Name: prb.Name}, remaining, now)}, nil
}

// updateStatus logs failures rather than returning them: an error would replace the
// expiry-aware RequeueAfter with the rate limiter's backoff, which can run to many minutes.
func (r *Reconciler) updateStatus(ctx context.Context, logger logr.Logger, prb *rbacv1alpha1.PAMRoleBinding) {
	prb.Status.ObservedGeneration = prb.Generation
	if err := r.Status().Update(ctx, prb); err != nil && !apierrors.IsConflict(err) {
		logger.Error(err, "failed to update status")
	}
}

func (r *Reconciler) finalize(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding) error {
	if !controllerutil.ContainsFinalizer(prb, Finalizer) {
		return nil
	}

	// Every namespace, not just spec.namespaces: a namespace may have been removed from the
	// list while its bindings failed to delete.
	list := &rbacv1.RoleBindingList{}
	if err := r.APIReader.List(ctx, list); err != nil {
		return fmt.Errorf("listing RoleBindings: %w", err)
	}
	for i := range list.Items {
		rb := &list.Items[i]
		// Ownerless bindings carrying our label are ours too: `--cascade=orphan` strips the
		// owner references before the finalizer runs.
		owner := metav1.GetControllerOf(rb)
		ours := owner != nil && owner.UID == prb.UID
		orphaned := owner == nil && rb.Labels[LabelPAMRoleBinding] == labelValue(prb.Name)
		if !ours && !orphaned {
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
	for _, project := range r.Projects {
		if project != "" && strings.HasPrefix(entitlement, "projects/"+project+"/") {
			return true
		}
	}
	return false
}

// backoff never waits past the next binding's expiry.
func (r *Reconciler) backoff(key types.NamespacedName, bindings map[types.NamespacedName]*rbacv1.RoleBinding, now time.Time) time.Duration {
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

func (r *Reconciler) nextSync(bindings map[types.NamespacedName]*rbacv1.RoleBinding, now time.Time, wait time.Duration) time.Duration {
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

func (r *Reconciler) ownedRoleBindings(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding) (map[types.NamespacedName]*rbacv1.RoleBinding, error) {
	// Every namespace, not just spec.namespaces, to catch bindings in namespaces that have
	// since been removed from it.
	list := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, list); err != nil {
		return nil, fmt.Errorf("listing RoleBindings: %w", err)
	}

	owned := map[types.NamespacedName]*rbacv1.RoleBinding{}
	for i := range list.Items {
		rb := &list.Items[i]
		if metav1.IsControlledBy(rb, prb) {
			owned[client.ObjectKeyFromObject(rb)] = rb
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
				if matches(existing, rb) {
					return nil
				}
				// Ours, but edited since: replace it.
				if err := r.deleteRoleBinding(ctx, prb, existing, ""); err != nil {
					return err
				}
				return fmt.Errorf("RoleBinding %s/%s didn't match its grant, so it was deleted to be recreated", rb.Namespace, rb.Name)
			}
			return fmt.Errorf("RoleBinding %s/%s already exists and isn't owned by this PAMRoleBinding", rb.Namespace, rb.Name)
		}
		return fmt.Errorf("creating RoleBinding %s/%s: %w", rb.Namespace, rb.Name, err)
	}

	r.Recorder.Eventf(prb, corev1.EventTypeNormal, EventGrantBound,
		"Bound %s to %s %s in %s until %s (grant %s)", rb.Annotations[AnnotationRequester],
		rb.RoleRef.Kind, rb.RoleRef.Name, rb.Namespace, rb.Annotations[AnnotationEndsAt], rb.Annotations[AnnotationGrantID])
	return nil
}

func (r *Reconciler) deleteRoleBinding(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding, rb *rbacv1.RoleBinding, reason string) error {
	err := r.Delete(ctx, rb, client.Preconditions{UID: &rb.UID})
	// A UID precondition conflict means this binding is already gone, replaced by another
	// of the same name.
	if err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
		return fmt.Errorf("deleting RoleBinding %s/%s: %w", rb.Namespace, rb.Name, err)
	}

	if reason != "" {
		r.Recorder.Eventf(prb, corev1.EventTypeNormal, reason,
			"Unbound %s in %s (grant %s)", rb.Annotations[AnnotationRequester], rb.Namespace, rb.Annotations[AnnotationGrantID])
	}
	return nil
}

func (r *Reconciler) setCondition(prb *rbacv1alpha1.PAMRoleBinding, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&prb.Status.Conditions, metav1.Condition{
		Type:               rbacv1alpha1.PAMRoleBindingConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: prb.Generation,
	})
}

// desiredBindings gives a user with several grants one binding, for the grant that ends
// last. Grants whose requester can't be bound are returned as errors.
func desiredBindings(prb *rbacv1alpha1.PAMRoleBinding, grants []Grant, now time.Time) (map[types.NamespacedName]*rbacv1.RoleBinding, []error) {
	var skipped []error
	latest := map[string]Grant{}
	for _, grant := range grants {
		if !grant.EndsAt.Add(-expiryMargin).After(now) {
			continue
		}
		user, err := BindableUser(grant.Requester)
		if err != nil {
			skipped = append(skipped, fmt.Errorf("grant %s: %w", grant.ID(), err))
			continue
		}
		if current, ok := latest[user]; !ok || grant.EndsAt.After(current.EndsAt) {
			latest[user] = grant
		}
	}

	desired := map[types.NamespacedName]*rbacv1.RoleBinding{}
	for user, grant := range latest {
		annotations := map[string]string{
			AnnotationGrant:     grant.Name,
			AnnotationGrantID:   grant.ID(),
			AnnotationRequester: user,
			AnnotationEndsAt:    grant.EndsAt.UTC().Format(time.RFC3339),
		}
		if len(grant.Approvers) > 0 {
			annotations[AnnotationApprovers] = strings.Join(grant.Approvers, ",")
		}

		name := RoleBindingName(prb.Name, user)
		for _, namespace := range prb.Spec.Namespaces {
			desired[types.NamespacedName{Namespace: namespace, Name: name}] = &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:        name,
					Namespace:   namespace,
					Labels:      map[string]string{LabelPAMRoleBinding: labelValue(prb.Name)},
					Annotations: copyMap(annotations),
				},
				RoleRef: prb.Spec.RoleRef,
				Subjects: []rbacv1.Subject{{
					APIGroup: rbacv1.GroupName,
					Kind:     rbacv1.UserKind,
					Name:     user,
				}},
			}
		}
	}
	return desired, skipped
}

// labelValue fits a name into a label value: at most 63 characters, ending in a letter or
// digit. Names sharing their first 63 characters get the same label, which is safe only
// because ownership is decided by owner reference.
func labelValue(name string) string {
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.TrimRight(name, "-.")
}

func matches(existing, desired *rbacv1.RoleBinding) bool {
	if existing.RoleRef != desired.RoleRef || len(existing.Subjects) != 1 || existing.Subjects[0] != desired.Subjects[0] {
		return false
	}
	if existing.Labels[LabelPAMRoleBinding] != desired.Labels[LabelPAMRoleBinding] {
		return false
	}
	for _, key := range []string{AnnotationGrant, AnnotationApprovers, AnnotationRequester, AnnotationEndsAt} {
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

// expired treats a binding without a readable end time as expired, so it can't outstay
// its grant.
func expired(rb *rbacv1.RoleBinding, now time.Time) bool {
	t, ok := endsAt(rb)
	return !ok || !t.Add(-expiryMargin).After(now)
}

func activeGrantStatus(bindings map[types.NamespacedName]*rbacv1.RoleBinding) []rbacv1alpha1.PAMGrant {
	byGrant := map[string]*rbacv1alpha1.PAMGrant{}
	for key, rb := range bindings {
		grant := rb.Annotations[AnnotationGrant]
		entry, ok := byGrant[grant]
		if !ok {
			t, _ := endsAt(rb)
			subject := rbacv1.Subject{}
			if len(rb.Subjects) == 1 {
				subject = rb.Subjects[0]
			}
			entry = &rbacv1alpha1.PAMGrant{
				Subject:     subject,
				Grant:       grant,
				Approvers:   splitApprovers(rb.Annotations[AnnotationApprovers]),
				EndsAt:      metav1.Time{Time: t},
				RoleBinding: key.Name,
			}
			byGrant[grant] = entry
		}
		entry.Namespaces = append(entry.Namespaces, key.Namespace)
	}

	out := make([]rbacv1alpha1.PAMGrant, 0, len(byGrant))
	for _, entry := range byGrant {
		sort.Strings(entry.Namespaces)
		out = append(out, *entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject.Name < out[j].Subject.Name })
	return out
}

func copyMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func splitApprovers(annotation string) []string {
	if annotation == "" {
		return nil
	}
	return strings.Split(annotation, ",")
}

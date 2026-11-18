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
	// AnnotationEndsAt is RFC 3339. While PAM answers, an ended grant is no longer listed
	// as active, so its binding is withdrawn anyway; this lets bindings still expire while
	// PAM can't be reached. Editing it gains nothing: the binding no longer matches its
	// grant, so it's recreated from PAM, and anyone who can edit a RoleBinding could
	// create one instead.
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

	// ownerIndex indexes cached RoleBindings by the UID of the PAMRoleBinding controlling
	// them. The API server can't filter by owner reference.
	ownerIndex = "pamRoleBindingOwnerUID"
)

type roleBindings map[types.NamespacedName]*rbacv1.RoleBinding

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
	// EntitlementProjects are the IDs and numbers of the projects whose entitlements are
	// honoured. Empty allows none.
	EntitlementProjects []string
	Now                 func() time.Time

	mu       sync.Mutex
	failures map[string]int
}

func (r *Reconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.APIReader == nil {
		r.APIReader = mgr.GetAPIReader()
	}
	r.failures = map[string]int{}

	if err := mgr.GetFieldIndexer().IndexField(ctx, &rbacv1.RoleBinding{}, ownerIndex, controllerUID); err != nil {
		return fmt.Errorf("indexing RoleBindings by owner: %w", err)
	}

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

func controllerUID(obj client.Object) []string {
	owner := metav1.GetControllerOf(obj)
	if owner == nil || owner.Kind != "PAMRoleBinding" || !strings.HasPrefix(owner.APIVersion, rbacv1alpha1.GroupVersion.Group+"/") {
		return nil
	}
	return []string{string(owner.UID)}
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues("pamrolebinding", req.Name)

	prb := &rbacv1alpha1.PAMRoleBinding{}
	if err := r.Get(ctx, req.NamespacedName, prb); err != nil {
		if apierrors.IsNotFound(err) {
			forgetMetrics(req.Name)
			r.resetFailures(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	if !prb.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, prb)
	}
	if err := r.ensureFinalizer(ctx, prb); err != nil {
		return ctrl.Result{}, err
	}

	owned, err := r.ownedRoleBindings(ctx, prb)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Before asking PAM anything, so expiry never depends on PAM answering.
	errs := r.removeExpired(ctx, prb, owned, r.Now())

	if !r.entitlementAllowed(prb.Spec.Entitlement) {
		errs = append(errs, r.removeAll(ctx, prb, owned)...)
		err := fmt.Errorf("entitlement %s isn't in rbac-manager's own project (%s)",
			prb.Spec.Entitlement, strings.Join(r.EntitlementProjects, " / "))
		return r.syncFailed(ctx, logger, prb, owned, r.Now(), rbacv1alpha1.PAMRoleBindingReasonEntitlementNotAllowed, errors.Join(append([]error{err}, errs...)...))
	}

	grants, err := r.listGrants(ctx, prb)
	// The call to PAM can take up to pamTimeout, so work out what has ended, and when to
	// next wake up, from the time it returned.
	now := r.Now()
	if err != nil {
		reason := rbacv1alpha1.PAMRoleBindingReasonPAMUnreachable
		if errors.Is(err, ErrEntitlementNotFound) {
			reason = rbacv1alpha1.PAMRoleBindingReasonEntitlementNotFound
		}
		return r.syncFailed(ctx, logger, prb, owned, now, reason, errors.Join(append([]error{err}, errs...)...))
	}

	desired := r.desiredBindings(logger, prb, grants, now)
	errs = append(errs, r.applyBindings(ctx, prb, owned, desired)...)

	return r.synced(ctx, logger, prb, owned, now, errs), nil
}

func (r *Reconciler) ensureFinalizer(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding) error {
	if controllerutil.ContainsFinalizer(prb, Finalizer) {
		return nil
	}
	controllerutil.AddFinalizer(prb, Finalizer)
	return r.Update(ctx, prb)
}

func (r *Reconciler) listGrants(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding) ([]Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, pamTimeout)
	defer cancel()
	return r.Grants.ListActiveGrants(ctx, prb.Spec.Entitlement)
}

// removeExpired deletes bindings whose grant has ended, removing them from owned.
func (r *Reconciler) removeExpired(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding, owned roleBindings, now time.Time) []error {
	var errs []error
	for key, rb := range owned {
		if !expired(rb, now) {
			continue
		}
		if err := r.deleteRoleBinding(ctx, prb, rb, EventGrantExpired); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(owned, key)
	}
	return errs
}

func (r *Reconciler) removeAll(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding, owned roleBindings) []error {
	var errs []error
	for key, rb := range owned {
		if err := r.deleteRoleBinding(ctx, prb, rb, EventGrantWithdrawn); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(owned, key)
	}
	return errs
}

// applyBindings makes owned match desired, updating owned as it goes.
func (r *Reconciler) applyBindings(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding, owned, desired roleBindings) []error {
	stillGranted := map[string]bool{}
	for key := range desired {
		stillGranted[key.Name] = true
	}

	var errs []error
	for key, rb := range owned {
		want, ok := desired[key]
		if ok && matches(rb, want) {
			continue
		}
		reason := EventGrantWithdrawn
		switch {
		case ok:
			reason = "" // edited since it was made, recreated below
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
	return errs
}

// synced records a sync in which PAM answered. Any errs are from creating or deleting
// RoleBindings.
func (r *Reconciler) synced(ctx context.Context, logger logr.Logger, prb *rbacv1alpha1.PAMRoleBinding, owned roleBindings, now time.Time, errs []error) ctrl.Result {
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
		return ctrl.Result{RequeueAfter: r.backoff(prb.Name, owned, now)}
	}

	r.resetFailures(prb.Name)
	r.setCondition(prb, metav1.ConditionTrue, rbacv1alpha1.PAMRoleBindingReasonSynced,
		fmt.Sprintf("%d active grant(s) bound in %d namespace(s)", len(prb.Status.ActiveGrants), len(prb.Spec.Namespaces)))
	r.updateStatus(ctx, logger, prb)
	return ctrl.Result{RequeueAfter: nextSync(owned, now, r.RefreshInterval)}
}

// syncFailed never removes access: a failed list from PAM says nothing about which grants
// are active. Expired bindings have already been removed before PAM was called.
func (r *Reconciler) syncFailed(ctx context.Context, logger logr.Logger, prb *rbacv1alpha1.PAMRoleBinding, owned roleBindings, now time.Time, reason string, err error) (ctrl.Result, error) {
	logger.Error(err, "failed to sync with PAM", "reason", reason)

	notFound := 0.0
	if reason == rbacv1alpha1.PAMRoleBindingReasonEntitlementNotFound {
		notFound = 1
	}
	entitlementNotFound.WithLabelValues(prb.Name).Set(notFound)

	prb.Status.ActiveGrants = activeGrantStatus(owned)
	activeGrants.WithLabelValues(prb.Name).Set(float64(len(prb.Status.ActiveGrants)))
	r.setCondition(prb, metav1.ConditionFalse, reason, err.Error())
	r.Recorder.Event(prb, corev1.EventTypeWarning, EventSyncFailed, err.Error())
	r.updateStatus(ctx, logger, prb)

	return ctrl.Result{RequeueAfter: r.backoff(prb.Name, owned, now)}, nil
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

	owned, err := r.ownedRoleBindings(ctx, prb)
	if err != nil {
		return err
	}

	// `--cascade=orphan` strips the owner references before the finalizer runs, leaving
	// only the label. Read it fresh: the cache may still show them as owned.
	labelled := &rbacv1.RoleBindingList{}
	if err := r.APIReader.List(ctx, labelled, client.MatchingLabels{LabelPAMRoleBinding: labelValue(prb.Name)}); err != nil {
		return fmt.Errorf("listing RoleBindings: %w", err)
	}
	for i := range labelled.Items {
		if rb := &labelled.Items[i]; metav1.GetControllerOf(rb) == nil {
			owned[client.ObjectKeyFromObject(rb)] = rb
		}
	}

	for _, rb := range owned {
		if err := r.deleteRoleBinding(ctx, prb, rb, EventGrantWithdrawn); err != nil {
			return err
		}
	}

	controllerutil.RemoveFinalizer(prb, Finalizer)
	return r.Update(ctx, prb)
}

func (r *Reconciler) entitlementAllowed(entitlement string) bool {
	for _, project := range r.EntitlementProjects {
		if project != "" && strings.HasPrefix(entitlement, "projects/"+project+"/") {
			return true
		}
	}
	return false
}

// backoff never waits past the next binding's expiry.
func (r *Reconciler) backoff(name string, owned roleBindings, now time.Time) time.Duration {
	r.mu.Lock()
	r.failures[name]++
	n := r.failures[name]
	r.mu.Unlock()

	wait := r.RefreshInterval
	for i := 1; i < n && wait < maxBackoff; i++ {
		wait *= 2
	}
	if wait > maxBackoff {
		wait = maxBackoff
	}

	return nextSync(owned, now, wait)
}

func (r *Reconciler) resetFailures(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.failures, name)
}

func nextSync(owned roleBindings, now time.Time, wait time.Duration) time.Duration {
	for _, rb := range owned {
		if endsAt, ok := endsAt(rb); ok {
			if until := endsAt.Sub(now) + time.Second; until < wait {
				wait = until
			}
		}
	}
	if wait < time.Second {
		wait = time.Second
	}
	return wait
}

// ownedRoleBindings looks in every namespace, not just spec.namespaces, to catch bindings
// in namespaces that have since been removed from it.
func (r *Reconciler) ownedRoleBindings(ctx context.Context, prb *rbacv1alpha1.PAMRoleBinding) (roleBindings, error) {
	list := &rbacv1.RoleBindingList{}
	if err := r.List(ctx, list, client.MatchingFields{ownerIndex: string(prb.UID)}); err != nil {
		return nil, fmt.Errorf("listing RoleBindings: %w", err)
	}

	owned := roleBindings{}
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

// desiredBindings records a warning event for each grant whose requester can't be bound.
func (r *Reconciler) desiredBindings(logger logr.Logger, prb *rbacv1alpha1.PAMRoleBinding, grants []Grant, now time.Time) roleBindings {
	desired := roleBindings{}
	for _, grant := range grants {
		if !grant.EndsAt.After(now) {
			continue
		}
		user, err := BindableUser(grant.Requester)
		if err != nil {
			err = fmt.Errorf("grant %s: %w", grant.ID(), err)
			logger.Info("skipping grant", "error", err.Error())
			r.Recorder.Event(prb, corev1.EventTypeWarning, EventGrantSkipped, err.Error())
			continue
		}

		annotations := map[string]string{
			AnnotationGrant:     grant.Name,
			AnnotationGrantID:   grant.ID(),
			AnnotationRequester: user,
			AnnotationEndsAt:    grant.EndsAt.UTC().Format(time.RFC3339),
		}
		if len(grant.Approvers) > 0 {
			annotations[AnnotationApprovers] = strings.Join(grant.Approvers, ",")
		}

		name := RoleBindingName(prb.Name, user, grant.Name)
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
	return desired
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
	return !ok || !t.After(now)
}

func activeGrantStatus(owned roleBindings) []rbacv1alpha1.PAMGrant {
	byGrant := map[string]*rbacv1alpha1.PAMGrant{}
	for key, rb := range owned {
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subject.Name != out[j].Subject.Name {
			return out[i].Subject.Name < out[j].Subject.Name
		}
		return out[i].Grant < out[j].Grant
	})
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
